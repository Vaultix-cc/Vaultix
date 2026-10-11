"""
Vaultix SDK - Python client library for the Vaultix API (https://vaultix.cc).

Sign in with a license key or an account, download files and folders, read
product variables, status and news. Apps with end-to-end encryption need the
app's content key (``set_content_key("vxk_...")``): every download then uses a
new one-time X25519 key, and content is returned only after the uploader's
signature, the size and the SHA-256 check out. Every API response is checked
against Vaultix's Ed25519 response signature (on by default).

``VaultixClient`` has an async API (``await client.download_file(...)``);
``SyncVaultixClient`` offers the same calls without ``await``.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import hmac
import http.client
import json
import os
import platform
import secrets
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import response_signing
from . import zk1
from ._transport import RawResponse, UrllibTransport

__version__ = "2.0.0"

__all__ = [
    "VaultixClient", "SyncVaultixClient", "FileInfo", "FolderInfo", "AppUser", "SubscriptionInfo",
    "Session", "ProductStatusInfo", "ProductNewsInfo", "AccountInfo", "NEED_CONTENT_KEY", "zk1",
    "response_signing", "__version__",
]

NEED_CONTENT_KEY = zk1.NEED_CONTENT_KEY

_SAFETY_UNSUPPORTED = ("This app requires approved-build checks (Safety), which only the C++ SDK supports")
_LEGACY_SALT = b"vaultix_salt_2024"
_LEGACY_ITERATIONS = 100000
_STREAM_CHUNK = 4096
_READ_CHUNK = 64 * 1024
_DEBUG_VISIBLE_HEADERS = frozenset((
    "content-type", "x-product-id", "x-vaultix-nonce", "x-vaultix-eph", "x-request-timestamp",
    "content-length", "content-disposition", "x-vaultix-key-id", "x-vaultix-signed-at",
))


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class FileInfo:
    """Represents a file stored in the Vaultix system"""
    id: str = ""
    name: str = ""
    app_id: str = ""
    size: int = 0
    encrypted: bool = False
    encryption_key: Optional[str] = None
    encryption_iv: Optional[str] = None
    downloads: int = 0
    uploaded_at: str = ""
    product_id: str = ""
    enc: Optional[str] = None            # "zk1": end-to-end encrypted
    sha256_hash: Optional[str] = None


@dataclass
class FolderInfo:
    """Represents a folder stored in the Vaultix system"""
    id: str = ""
    name: str = ""
    app_id: str = ""
    total_size: int = 0
    file_count: int = 0
    downloads: int = 0
    uploaded_at: str = ""
    product_id: str = ""
    enc: Optional[str] = None            # "zk1": end-to-end encrypted


@dataclass
class AppUser:
    """Represents an authenticated user within an application"""
    id: str = ""
    app_id: str = ""
    username: Optional[str] = None
    key: Optional[str] = None
    subscriptions: List[str] = field(default_factory=list)


@dataclass
class SubscriptionInfo:
    """Represents a user's subscription to a product"""
    subscription_id: str = ""
    app_user_id: str = ""
    product_id: str = ""
    status: str = ""
    expires_at: Optional[str] = None
    is_paused: bool = False
    paused_at: Optional[str] = None
    paused_until: Optional[str] = None
    downloads: int = 0
    created_at: str = ""
    updated_at: str = ""

    @property
    def is_active(self) -> bool:
        """Check if the subscription is active (not paused, not expired)"""
        return not self.is_paused and (self.expires_at is None or self.status == "active")

    @property
    def is_lifetime(self) -> bool:
        """Check if the subscription is lifetime (no expiration)"""
        return self.expires_at is None


@dataclass
class Session:
    """Represents an active session with the Vaultix API"""
    hwid: str = ""
    session_token: str = ""
    session_id: str = ""
    is_valid: bool = False
    app_id: str = ""
    app_user: AppUser = field(default_factory=AppUser)
    token_expiry: Optional[str] = None
    app_api_key: str = ""


@dataclass
class ProductStatusInfo:
    """Product status information"""
    has_status: bool = False
    name: str = ""
    color: str = ""
    action: str = ""


@dataclass
class ProductNewsInfo:
    """Product news/announcement information"""
    has_news: bool = False
    headline: str = ""
    content: str = ""
    updated_at: str = ""


@dataclass
class AccountInfo:
    """Cosmetic profile of the signed-in user (display strings only)"""
    username: str = ""
    note: str = ""


# =============================================================================
# Helpers
# =============================================================================

def _url_encode(text: str) -> str:
    """Percent-encode everything except A-Z a-z 0-9 - _ . ~ (as the C++ SDK)."""
    return quote(text or "", safe="")


def _legacy_decrypt(encrypted: bytes, key: bytes) -> bytes:
    """Downloads of apps without end-to-end encryption: SALT(16) || IV(12) ||
    TAG(16) || CIPHERTEXT (or the older IV(12) || TAG(16) || CIPHERTEXT with a
    fixed salt), AES-256-GCM under PBKDF2-HMAC-SHA256(key, salt, 100000)."""
    if len(encrypted) >= 44:
        salt, iv, tag, ciphertext = encrypted[:16], encrypted[16:28], encrypted[28:44], encrypted[44:]
    elif len(encrypted) >= 28:
        salt, iv, tag, ciphertext = _LEGACY_SALT, encrypted[:12], encrypted[12:28], encrypted[28:]
    else:
        raise ValueError("Invalid encrypted data size for AES-GCM")
    derived = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=_LEGACY_ITERATIONS).derive(key)
    try:
        return AESGCM(derived).decrypt(iv, bytes(ciphertext) + bytes(tag), None)
    except InvalidTag as exc:
        raise ValueError("Failed to finalize decryption (authentication failed)") from exc


def _scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _parse_size(value: Any) -> int:
    """A size as an int, or from the server's "25.5 MB" form."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        parts = value.split()
        units = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
        try:
            if len(parts) == 2 and parts[1].upper() in units:
                return int(float(parts[0]) * units[parts[1].upper()])
            return int(float(value))
        except ValueError:
            return 0
    return 0


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _opt_str(value: Any) -> Optional[str]:
    return None if value is None else str(value)


def _file_info(data: Dict[str, Any]) -> FileInfo:
    return FileInfo(
        id=str(data.get("id") or ""), name=str(data.get("name") or ""), app_id=str(data.get("appId") or ""),
        size=_parse_size(data.get("size")), encrypted=bool(data.get("encrypted", False)),
        encryption_key=_opt_str(data.get("encryptionKey", data.get("key"))),
        encryption_iv=_opt_str(data.get("encryptionIV", data.get("iv"))),
        downloads=_as_int(data.get("downloads")), uploaded_at=str(data.get("uploadedAt") or ""),
        product_id=str(data.get("productId") or ""), enc=_opt_str(data.get("enc")),
        sha256_hash=_opt_str(data.get("sha256Hash")))


def _folder_info(data: Dict[str, Any]) -> FolderInfo:
    return FolderInfo(
        id=str(data.get("id") or ""), name=str(data.get("name") or ""), app_id=str(data.get("appId") or ""),
        total_size=_parse_size(data.get("totalSize")), file_count=_as_int(data.get("fileCount")),
        downloads=_as_int(data.get("downloads")), uploaded_at=str(data.get("uploadedAt") or ""),
        product_id=str(data.get("productId") or ""), enc=_opt_str(data.get("enc")))


class _Zk1Download:
    """One download that may come back as a zk1 delivery. _perform_request()
    decides when the headers arrive: X-Encryption-Key "zk1d." -> check the
    response signature (always, also with set_require_signed_responses(False)),
    then decrypt while the body streams; anything else stays on the legacy path."""

    MEMORY, FILE, VARIABLES = "memory", "file", "variables"
    IDLE, ACTIVE, DONE, FAILED = "idle", "active", "done", "failed"

    def __init__(self, client: "VaultixClient", target: str, kind: str, name: str, product_id: str,
                 output_path: str = ""):
        self.client = client
        self.target = target
        self.kind = kind                  # "file", "folder" or "vars"
        self.name = name                  # the name that was asked for (seal context)
        self.product_id = product_id      # the product asked for: seal scope; vars: the delivery's object id
        self.output_path = output_path
        self.part_path = ""               # "<output_path>.vxpart" while the file is unverified
        self.part = None
        self.memory = bytearray()
        self.variables: List[Tuple[str, str]] = []
        self.opener: Optional[zk1.DeliveryOpener] = None
        self.client_secret: Optional[bytes] = None
        self.state = self.IDLE
        self.error = ""
        self.store_error = ""
        self.rejected = False             # the response signature check failed

    @staticmethod
    def failure(detail: str) -> str:
        return "End-to-end encrypted download failed: " + detail

    @property
    def is_delivery(self) -> bool:
        return self.state in (self.ACTIVE, self.DONE, self.FAILED)

    @property
    def succeeded(self) -> bool:
        return self.state == self.DONE

    def discard(self) -> None:
        """Drop every result and the partial file."""
        self.opener = None
        if self.memory:
            self.memory[:] = bytes(len(self.memory))
        self.memory = bytearray()
        self.variables = []
        if self.part is not None:
            try:
                self.part.close()
            except OSError:
                pass
            self.part = None
        if self.part_path:
            try:
                os.remove(self.part_path)
            except OSError:
                pass
            self.part_path = ""

    def reset(self) -> None:
        self.discard()
        self.state = self.IDLE
        self.error = ""
        self.store_error = ""
        self.rejected = False
        self.client_secret = None

    def fail(self, message: str) -> bool:
        if self.state != self.FAILED and not self.error:
            self.error = message
        self.state = self.FAILED
        self.discard()
        return False

    def prepare_request(self) -> str:
        """A fresh X25519 key for this request; the value of X-Vaultix-Eph."""
        secret, public = zk1.x25519_generate()
        self.client_secret = secret
        return zk1.b64u_encode(public)

    def engage(self, status: int, headers: Dict[str, bytes], method: str, path_and_query: str, nonce: str,
               redirects: int) -> bool:
        self.state = self.ACTIVE
        client = self.client
        verified, reason = False, ""
        if redirects > 0:
            reason = "the request was redirected"
        elif not nonce:
            reason = "the request had no nonce"
        else:
            verified, reason = client._verify_response(method, path_and_query, status,
                                                       response_signing.STREAM_BODY_MARKER, headers, nonce)
        if not verified:
            self.rejected = True
            return self.fail(f"Server response could not be verified (HTTP {status}): {reason}")
        if status != 200:
            return self.fail(self.failure(f"unexpected HTTP status {status}"))
        if self.kind != "vars" and client._content_key is None:
            return self.fail(NEED_CONTENT_KEY)
        app_id = client._current_session.app_id
        if not app_id:  # part of every signed message (from the signed login response)
            return self.fail(self.failure("no app id in the session"))
        if self.client_secret is None:
            return self.fail(self.failure("no request key"))
        self.opener = zk1.DeliveryOpener(self.client_secret, self.kind)
        self.client_secret = None
        if self.kind != "vars":
            self.opener.set_file_context(client._content_key, app_id, self.name, self.product_id, self.store)
        if not self.opener.begin(headers.get("x-encryption-key", b"").decode("latin-1")):
            return self.fail(self.failure(self.opener.error))
        if self.kind == "vars" and self.opener.object_id != self.product_id:
            return self.fail(self.failure("the variables delivery is for another product"))
        if self.target == self.FILE:
            self.part_path = self.output_path + ".vxpart"
            try:
                parent = os.path.dirname(os.path.abspath(self.output_path))
                os.makedirs(parent, exist_ok=True)
                self.part = open(self.part_path, "wb")
            except OSError:
                return self.fail("Failed to open output file: " + self.part_path)
        return True

    def store(self, data: bytes) -> bool:
        """Decrypted content (authenticated chunk by chunk, not yet as a whole)."""
        if self.target == self.MEMORY:
            self.memory += data
            return True
        if self.target == self.FILE and self.part is not None:
            try:
                self.part.write(data)
                return True
            except OSError:
                self.store_error = "Failed to write output file: " + self.part_path
        return False

    def feed(self, data: bytes) -> bool:
        if self.state != self.ACTIVE:
            return False
        if data and not self.opener.update(data):
            return self.fail(self.store_error or self.failure(self.opener.error))
        return True

    def finish(self) -> bool:
        """End of the body: the whole delivery must authenticate."""
        if self.state != self.ACTIVE:
            return self.state == self.DONE
        client = self.client
        if not self.opener.finish():
            return self.fail(self.store_error or self.failure(self.opener.error))
        if self.target == self.FILE:
            try:
                self.part.flush()
                os.fsync(self.part.fileno())
                self.part.close()
            except OSError:
                return self.fail("Failed to write output file: " + self.part_path)
            self.part = None
            try:
                os.replace(self.part_path, self.output_path)
            except OSError:
                return self.fail("Failed to save the file to " + self.output_path)
            self.part_path = ""
        elif self.target == self.VARIABLES:
            try:
                self.variables = zk1.open_variables(self.opener.vars_payload, client._content_key,
                                                    client._current_session.app_id, self.product_id)
            except zk1.Zk1Error as exc:
                reason = str(exc)
                return self.fail(reason if reason == NEED_CONTENT_KEY else self.failure(reason))
        if self.kind != "vars":
            client._last_signed_at = self.opener.signed_at
        if self.kind == "file":
            # verified and fully decrypted: is_valid_file_hash never sends its plain hash
            client._verified_zk1_files.add((self.product_id, self.name))
        self.opener = None
        self.state = self.DONE
        return True

    def take_memory(self) -> bytes:
        data = bytes(self.memory)
        self.memory[:] = bytes(len(self.memory))
        self.memory = bytearray()
        return data


# =============================================================================
# Client
# =============================================================================

class VaultixClient:
    """
    Main client class for interacting with the Vaultix API.

    Example:
        >>> client = VaultixClient("https://vaultix.cc/api")
        >>> client.set_api_key("ap_your_app_api_key")
        >>> client.set_content_key("vxk_your_sdk_key_here")   # apps with end-to-end encryption
        >>> if await client.authenticate_with_key("YOUR-LICENSE-KEY"):
        ...     data = await client.download_file_to_memory("product_id", "file.bin")

    Not thread-safe: use one client per thread, or a lock.
    """

    def __init__(self, base_url: str = "https://vaultix.cc/api"):
        """
        Initialize a new Vaultix client.

        Args:
            base_url: The base URL of the Vaultix API (default: https://vaultix.cc/api)
        """
        self._base_url = base_url.rstrip('/')
        self._api_key: Optional[str] = None
        self._current_session = Session()
        self._debug_mode = False
        self._ssl_verify = True
        self._certificate_pinning_enabled = False
        self._pinned_certificates: List[str] = []
        self._min_tls_version = "1.2"
        self._request_signing_enabled = False
        self._request_signing_key: Optional[str] = None
        self._last_error = ""
        self._require_signed_responses = True
        self._response_clock_skew = response_signing.DEFAULT_CLOCK_SKEW_SECONDS
        self._last_response_rejected = False
        self._extra_response_key: Optional[Tuple[str, str]] = None
        self._content_key: Optional[zk1.ContentKey] = None
        self._last_signed_at = 0
        # (productId, fileName) received as verified zk1 files; is_valid_file_hash
        # never sends their plain hash. Cleared by clear_content_key() and end_session().
        self._verified_zk1_files = set()
        self._last_status = 0
        self._last_headers: Dict[str, bytes] = {}
        self._last_error_body = b""
        self._transport: Optional[Callable[..., RawResponse]] = None  # tests only; None = urllib
        self._persistent_token_dir = Path.home() / ".vaultix"

    # =========================================================================
    # Configuration
    # =========================================================================

    def set_api_key(self, key: str) -> None:
        """Set the application API key (prefixed with 'ap_'). It is only used to
        create a session and is dropped from the client after a successful login."""
        self._api_key = key

    def clear_api_key(self) -> None:
        """Clear the API key from the client"""
        self._api_key = None

    @property
    def debug_mode(self) -> bool:
        """Debug output (never shows credentials, keys or request bodies)"""
        return self._debug_mode

    @debug_mode.setter
    def debug_mode(self, value: bool) -> None:
        self._debug_mode = value

    def set_debug_mode(self, value: bool) -> None:
        self._debug_mode = value

    @property
    def ssl_verify(self) -> bool:
        """TLS certificate verification (on by default)"""
        return self._ssl_verify

    @ssl_verify.setter
    def ssl_verify(self, value: bool) -> None:
        self._ssl_verify = value

    def enable_certificate_pinning(self, cert_hashes: List[str]) -> None:
        """Only accept servers whose certificate public key matches one of these
        pins: SHA-256 of the DER SubjectPublicKeyInfo, as 64 hex characters (the
        C++ SDK's format) or as "sha256/<base64>"."""
        self._certificate_pinning_enabled = True
        self._pinned_certificates = list(cert_hashes)

    def disable_certificate_pinning(self) -> None:
        """Disable certificate pinning"""
        self._certificate_pinning_enabled = False

    def set_min_tls_version(self, version: str) -> None:
        """Minimum TLS version: "1.2" (default) or "1.3" """
        self._min_tls_version = version

    def enable_request_signing(self, signing_key: str) -> None:
        """Add X-Request-Timestamp and X-Request-Signature (HMAC-SHA256 over
        METHOD|ENDPOINT|BODY|TIMESTAMP) to every request"""
        self._request_signing_enabled = True
        self._request_signing_key = signing_key

    def disable_request_signing(self) -> None:
        """Disable request signing"""
        self._request_signing_enabled = False

    # =========================================================================
    # Response verification (on by default)
    # =========================================================================

    def set_require_signed_responses(self, require: bool) -> None:
        """Every request carries a fresh random X-Vaultix-Nonce. Vaultix signs
        each response (Ed25519) over that nonce, the method, path and query that
        were sent, the status code, a SHA-256 of the full body, the file
        encryption headers and the Content-Type. The SDK checks that signature
        with the Vaultix public key built into vaultix/response_signing.py, so
        a fake server (DNS redirect, locally trusted CA, proxy) cannot answer
        "login OK", hand out files, or replay an old response. A response that
        fails the check makes the call fail; get_last_error() then starts with
        "Server response could not be verified".

        Turning this off is ONLY for local testing against your own test
        server; never ship a build with set_require_signed_responses(False).
        End-to-end encrypted deliveries are verified even then."""
        self._require_signed_responses = bool(require)

    def get_require_signed_responses(self) -> bool:
        return self._require_signed_responses

    def set_response_clock_skew_tolerance(self, seconds: int) -> None:
        """Allowed difference between this computer's clock and the server's
        signing time, in seconds (default 600). Values <= 0 restore the default."""
        self._response_clock_skew = int(seconds) if seconds and int(seconds) > 0 \
            else response_signing.DEFAULT_CLOCK_SKEW_SECONDS

    def testing_set_extra_response_key(self, key_id: Optional[str], public_key_hex: Optional[str]) -> bool:
        """TESTING ONLY. NEVER SHIP AN APP THAT CALLS THIS.

        Trusts one extra Ed25519 response-signing key next to the production
        key built into the SDK, for Vaultix SDK tests against a test backend
        that signs with its own key (the Python counterpart of the C++ build
        flags VAULTIX_TESTING_EXTRA_RESPONSE_KEY_ID / _HEX). Whoever holds the
        matching private key can then answer every request of this client.

        key_id must be "vx-sig-" + the first 16 hex characters of SHA-256 of
        the raw 32-byte public key. Pass (None, None) to remove the key.
        Returns False (nothing changed) for an invalid key."""
        if key_id is None and public_key_hex is None:
            self._extra_response_key = None
            return True
        try:
            raw = bytes.fromhex(public_key_hex or "")
        except ValueError:
            return False
        if (len(raw) != 32 or zk1.weak_signing_key(raw) or key_id != response_signing.key_id_for(raw)
                or key_id in response_signing.TRUSTED_RESPONSE_KEYS):
            return False
        self._extra_response_key = (key_id, raw.hex())
        return True

    def _trusted_response_keys(self) -> Dict[str, str]:
        keys = dict(response_signing.TRUSTED_RESPONSE_KEYS)
        if self._extra_response_key is not None:
            keys[self._extra_response_key[0]] = self._extra_response_key[1]
        return keys

    def _verify_response(self, method: str, path_and_query: str, status: int, body_hash: str,
                         headers: Dict[str, bytes], nonce: str) -> Tuple[bool, str]:
        return response_signing.verify(method=method, path_and_query=path_and_query, status=status,
                                       body_hash=body_hash, headers=headers, nonce=nonce,
                                       trusted=self._trusted_response_keys(),
                                       clock_skew_seconds=self._response_clock_skew)

    # =========================================================================
    # End-to-end encryption
    # =========================================================================

    def set_content_key(self, vxk: str) -> bool:
        """Apps with end-to-end encryption need the content key ("vxk_...", 96
        characters, App Settings) to download files, folders and encrypted
        variables. It holds the key that opens the content and the app's
        signing key, which approves the team members whose signature every
        file and value must carry. Kept in memory only. Returns False (current
        key unchanged) if the key, its version or its checksum is invalid."""
        try:
            key = zk1.ContentKey.from_sdk_key(vxk)
        except zk1.Zk1Error:
            self._last_error = "Invalid content key: use the vxk_ key from App Settings (96 characters)"
            return False
        self.clear_content_key()
        self._content_key = key
        self._last_error = ""
        return True

    def clear_content_key(self) -> None:
        """Forget the content key (and which files arrived end-to-end encrypted)."""
        self._content_key = None
        self._verified_zk1_files.clear()

    def has_content_key(self) -> bool:
        return self._content_key is not None

    def get_content_key_fingerprint(self) -> str:
        """"XXXX-XXXX-XXXX-XXXX", must match the fingerprint in App Settings; "" without a key."""
        return self._content_key.fingerprint if self._content_key is not None else ""

    def get_last_signed_at(self) -> int:
        """Signing time (Unix milliseconds) of the file or folder returned by the
        last download call, if it was a verified end-to-end encrypted download;
        0 otherwise (failure, legacy file). Vaultix cannot fake content but could
        serve an older, genuinely signed version: keep the newest value you have
        seen per file and refuse an older one if that matters to your app."""
        return self._last_signed_at

    # =========================================================================
    # Async plumbing
    # =========================================================================

    async def _run(self, func: Callable, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, functools.partial(func, *args))

    # =========================================================================
    # Authentication
    # =========================================================================

    async def authenticate_with_username(self, username: str, password: str) -> bool:
        """Authenticate with username and password. Returns True on success."""
        return await self._run(self._authenticate_with_username, username, password)

    async def authenticate_with_key(self, user_key: str) -> bool:
        """Authenticate with a license key. Returns True on success."""
        return await self._run(self._authenticate_with_key, user_key)

    async def try_auto_login(self) -> bool:
        """Sign in with the auto-login token saved by an earlier login (if the
        app allows auto-login). Returns True on success."""
        return await self._run(self._try_auto_login)

    async def refresh_token(self) -> bool:
        """Sign in again with the stored license key (key logins only)."""
        return await self._run(self._refresh_token)

    def end_session(self) -> None:
        """Log out on the server (blocking request) and clear the session.
        Keeps the auto-login token; use clear_auto_login_token() for that."""
        if self._current_session.is_valid:
            response = self._request_json("/app_auth/logout", "POST", b"")
            if isinstance(response, dict):
                message = str(response.get("message") or "")
                if "successfully" not in message:
                    self._last_error = message or "Failed to terminate session"
        self._current_session = Session()
        self._verified_zk1_files.clear()
        self._log("Session ended")

    def clear_auto_login_token(self) -> None:
        """Revoke the auto-login token on the server (blocking request) and delete it locally."""
        api_key = self._current_session.app_api_key or self._api_key
        if not api_key:
            self._log("No API key available for token lookup")
            return
        token = self._load_persistent_token(api_key)
        if token:
            body = json.dumps({"token": token, "hwid": self._hwid()}).encode("utf-8")
            self._perform_request("/app_auth/clear_autologin", "POST", body, {"X-API-Key": api_key})
        self._delete_persistent_token(api_key)
        self._log("Auto-login token cleared")

    def _login_api_key(self) -> Optional[str]:
        return self._api_key or self._current_session.app_api_key or None

    def _login(self, endpoint: str, payload: Dict[str, Any], *, username: Optional[str] = None,
               key: Optional[str] = None) -> bool:
        api_key = self._login_api_key()
        if not api_key:
            self._last_error = "API key not set"
            return False
        hwid = payload.get("hwid", "")
        data = self._request_json(endpoint, "POST", json.dumps(payload).encode("utf-8"), {"X-API-Key": api_key},
                                  use_session=False)
        if not isinstance(data, dict):
            if self._last_status == 403 and "Safety" in self._last_error:
                self._last_error += f" ({_SAFETY_UNSUPPORTED})"
            elif data is not None:
                self._last_error = "Failed to parse authentication response"
            return False
        return self._start_session(data, hwid, api_key, username=username, key=key)

    def _start_session(self, data: Dict[str, Any], hwid: str, api_key: str, *, username: Optional[str] = None,
                       key: Optional[str] = None) -> bool:
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            self._last_error = "No access token received"
            return False
        if data.get("safetyEnabled") is True:
            self._last_error = _SAFETY_UNSUPPORTED
            return False
        app_id = str(data.get("appId") or "")
        subscriptions = [s for s in (data.get("subscriptions") or []) if isinstance(s, str)]
        self._current_session = Session(
            hwid=hwid, session_token=token, session_id=str(data.get("sessionId") or ""), is_valid=True,
            app_id=app_id,
            app_user=AppUser(id=str(data.get("appUserId") or ""), app_id=app_id, username=username, key=key,
                             subscriptions=subscriptions),
            token_expiry=_opt_str(data.get("expiresAt")), app_api_key=api_key)
        self._api_key = None  # kept in the session only (auto-login, refresh)
        persistent = data.get("persistentToken")
        if isinstance(persistent, str) and persistent:
            self._save_persistent_token(persistent, api_key)
        self._last_error = ""
        self._log("Authentication successful")
        return True

    def _authenticate_with_username(self, username: str, password: str) -> bool:
        return self._login("/app_auth/login", {"username": username, "password": password, "hwid": self._hwid()},
                           username=username)

    def _authenticate_with_key(self, user_key: str) -> bool:
        return self._login("/app_auth/login_key", {"key": user_key, "hwid": self._hwid()}, key=user_key)

    def _try_auto_login(self) -> bool:
        api_key = self._login_api_key()
        if not api_key:
            self._last_error = "API key not set"
            return False
        token = self._load_persistent_token(api_key)
        if not token:
            self._last_error = "No saved token found"
            return False
        hwid = self._hwid()
        body = json.dumps({"token": token, "hwid": hwid}).encode("utf-8")
        data = self._request_json("/app_auth/autologin", "POST", body, {"X-API-Key": api_key}, use_session=False)
        if not isinstance(data, dict):
            # An unverifiable response says nothing about the saved token; keep it.
            if not self._last_response_rejected:
                self._delete_persistent_token(api_key)
            if data is not None:
                self._last_error = "Failed to parse auto-login response"
            return False
        if not self._start_session(data, hwid, api_key):
            if self._last_error == "No access token received":
                self._delete_persistent_token(api_key)
            return False
        return True

    def _refresh_token(self) -> bool:
        user = self._current_session.app_user
        if user.username:
            self._last_error = "Password re-entry required after token expiration"
            return False
        if user.key:
            return self._authenticate_with_key(user.key)
        self._last_error = "No stored credentials for refresh"
        return False

    # =========================================================================
    # Session State
    # =========================================================================

    @property
    def is_session_valid(self) -> bool:
        """Check if the current session is valid"""
        return self._current_session.is_valid

    async def is_token_expired(self) -> bool:
        """True without a session, or when the session token's expiry time has passed"""
        return self._is_token_expired()

    def _is_token_expired(self) -> bool:
        if not self._current_session.is_valid or not self._current_session.token_expiry:
            return True
        try:
            expiry = datetime.fromisoformat(self._current_session.token_expiry)
        except ValueError:
            return True
        now = datetime.now(timezone.utc)
        if expiry.tzinfo is None:
            now = now.replace(tzinfo=None)
        return now >= expiry

    def get_current_session(self) -> Session:
        """Get the current session information"""
        return self._current_session

    def get_last_error(self) -> str:
        """Why the last call failed; "" after a call that succeeded"""
        return self._last_error

    def _need_session(self) -> bool:
        if not self._current_session.is_valid:
            self._last_error = "No valid session"
            return False
        return True

    # =========================================================================
    # File Operations
    # =========================================================================

    async def get_file_list(self, product_id: str) -> List[FileInfo]:
        """Files of a product, as far as the server lists them for this session"""
        return await self._run(self._get_file_list, product_id)

    async def get_file_info(self, product_id: str, file_name: str) -> Optional[FileInfo]:
        """Information about one file, or None"""
        return await self._run(self._get_file_info, product_id, file_name)

    async def download_file(self, product_id: str, file_name: str, output_path: str) -> bool:
        """Download a file to output_path. End-to-end encrypted files are written
        to "<output_path>.vxpart" and renamed only after every check passed;
        on any failure nothing is left behind and False is returned."""
        return await self._run(self._download_file, product_id, file_name, output_path)

    async def download_file_to_memory(self, product_id: str, file_name: str) -> bytes:
        """Download a file into memory. Returns b"" on any failure; on success
        get_last_error() is "" (so an empty file is not an error)."""
        return await self._run(self._download_file_to_memory, product_id, file_name)

    async def stream_file(self, product_id: str, file_name: str,
                          progress_callback: Optional[Callable[[bytes, int, int], None]] = None) -> bool:
        """Download a file (verified in full first) and hand it to
        progress_callback(chunk, received, total) in 4 KB chunks."""
        data = await self._run(self._download_file_to_memory, product_id, file_name)
        return self._stream_chunks(data, progress_callback)

    async def is_valid_file_hash(self, product_id: str, file_name: str, file_path: str) -> bool:
        """Ask the server whether the local file matches the stored file. With a
        content key this sends the keyed hash HMAC(hashKey, SHA-256(file)), so
        Vaultix never learns the checksum; files of apps without end-to-end
        encryption are then checked once more with the plain SHA-256, except
        files this client already received as verified end-to-end encrypted
        files (then False)."""
        return await self._run(self._is_valid_file_hash, product_id, file_name, file_path)

    def _get_file_list(self, product_id: str) -> List[FileInfo]:
        if not self._need_session():
            return []
        data = self._request_json(f"/files?productId={_url_encode(product_id)}", "GET", None,
                                  {"X-Product-ID": product_id})
        if isinstance(data, dict) and isinstance(data.get("files"), list):
            data = data["files"]
        if not isinstance(data, list):
            if data is not None:
                self._last_error = "Unexpected file list response"
            return []
        return [_file_info(item) for item in data if isinstance(item, dict)]

    def _get_file_info(self, product_id: str, file_name: str) -> Optional[FileInfo]:
        if not self._need_session():
            return None
        endpoint = f"/files/info/{_url_encode(file_name)}?productId={_url_encode(product_id)}"
        data = self._request_json(endpoint, "GET", None, {"X-Product-ID": product_id})
        if not isinstance(data, dict):
            if data is not None:
                self._last_error = "Failed to parse JSON response"
            return None
        return _file_info(data)

    def _download(self, target: str, kind: str, product_id: str, name: str, output_path: str = "") -> Any:
        """One file or folder download. Returns bytes (memory) or bool (file)."""
        self._last_signed_at = 0
        failed: Any = b"" if target == _Zk1Download.MEMORY else False
        if not self._need_session():
            return failed
        route = "files" if kind == "file" else "folders"
        endpoint = f"/{route}/download/{_url_encode(name)}?productId={_url_encode(product_id)}"
        download = _Zk1Download(self, target, kind, name, product_id, output_path)
        body = self._perform_request(endpoint, "GET", None, {"X-Product-ID": product_id}, download)
        if download.is_delivery:
            if not download.succeeded:
                return failed
            self._log(f"End-to-end encrypted {kind} verified and decrypted: {name}")
            return download.take_memory() if target == _Zk1Download.MEMORY else True
        if body is None:
            self._explain_e2ee_refusal()
            return failed
        # Legacy app: AES-256-GCM with the key in the (signed) response header.
        key = self._last_headers.get("x-encryption-key", b"")
        what = "file" if kind == "file" else "folder"
        if not key:
            self._last_error = f"Missing encryption key in response headers; refusing unencrypted {what} data"
            return failed
        try:
            plain = _legacy_decrypt(body, key)
        except ValueError as exc:
            self._last_error = f"Failed to decrypt {what}: {exc}"
            return failed
        if target == _Zk1Download.MEMORY:
            self._last_error = ""
            return plain
        try:
            parent = os.path.dirname(os.path.abspath(output_path))
            os.makedirs(parent, exist_ok=True)
            with open(output_path, "wb") as handle:
                handle.write(plain)
        except OSError:
            self._last_error = "Failed to open output file: " + output_path
            return False
        self._last_error = ""
        return True

    def _download_file(self, product_id: str, file_name: str, output_path: str) -> bool:
        return self._download(_Zk1Download.FILE, "file", product_id, file_name, output_path)

    def _download_file_to_memory(self, product_id: str, file_name: str) -> bytes:
        return self._download(_Zk1Download.MEMORY, "file", product_id, file_name)

    def _stream_chunks(self, data: bytes, callback: Optional[Callable[[bytes, int, int], None]]) -> bool:
        if not data and self._last_error:
            return False
        total = len(data)
        for start in range(0, total, _STREAM_CHUNK):
            chunk = data[start:start + _STREAM_CHUNK]
            if callback is not None:
                callback(chunk, start + len(chunk), total)
        return True

    def _explain_e2ee_refusal(self) -> None:
        """409 e2ee_sdk_update_required: the item is end-to-end encrypted."""
        if self._last_status != 409 or self._last_response_rejected:
            return
        try:
            code = json.loads(self._last_error_body.decode("utf-8")).get("code")
        except (ValueError, AttributeError, UnicodeDecodeError):
            code = None
        if code == "e2ee_sdk_update_required":
            self._last_error = NEED_CONTENT_KEY if self._content_key is None else _Zk1Download.failure(
                "the server did not receive this request's one-time key (X-Vaultix-Eph) and asked for a newer "
                "SDK (e2ee_sdk_update_required)")

    def _is_valid_file_hash(self, product_id: str, file_name: str, file_path: str) -> bool:
        if not self._need_session():
            return False
        digest = hashlib.sha256()
        try:
            with open(file_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
                    digest.update(chunk)
        except OSError:
            self._last_error = "Failed to open file: " + file_path
            return False
        file_hash = digest.digest()
        plain_request = {"productId": product_id, "fileName": file_name, "hash": file_hash.hex()}
        # End-to-end encryption: Vaultix stores only the keyed hash of zk1 files
        # (docs/E2EE_FORMAT.md section 5). Files of apps without it answer
        # "plain_hash_required": then once more with the plain SHA-256, unless
        # this client already received the file as a verified zk1 delivery.
        keyed = self._content_key is not None
        request = plain_request
        if keyed:
            request = {"productId": product_id, "fileName": file_name,
                       "keyedHash": zk1.keyed_hash(self._content_key.hash_key, file_hash).hex()}
        for attempt in range(2):
            data = self._request_json("/files/verify-hash", "POST", json.dumps(request).encode("utf-8"),
                                      {"X-Product-ID": product_id})
            if not isinstance(data, dict):
                if data is not None:
                    self._last_error = "Failed to parse verification response"
                return False
            valid = data.get("valid") is True
            if not valid and keyed and attempt == 0 and data.get("code") == "plain_hash_required":
                if (product_id, file_name) in self._verified_zk1_files:
                    self._last_error = ("verify-hash: the server asked for the plain hash of an end-to-end "
                                        "encrypted file")
                    self._log(self._last_error)
                    return False
                self._log("Not an end-to-end encrypted file: checking the plain hash")
                request = plain_request
                continue
            self._log(f"Hash verification result: {'VALID' if valid else 'INVALID'}")
            return valid
        return False

    # =========================================================================
    # Folder Operations
    # =========================================================================

    async def get_folder_list(self, product_id: str) -> List[FolderInfo]:
        """Folders of a product, as far as the server lists them for this session"""
        return await self._run(self._get_folder_list, product_id)

    async def get_folder_info(self, product_id: str, folder_name: str) -> Optional[FolderInfo]:
        """Information about one folder, or None"""
        return await self._run(self._get_folder_info, product_id, folder_name)

    async def download_folder(self, product_id: str, folder_name: str, output_path: str) -> bool:
        """Download a folder as a ZIP archive to output_path (same rules as download_file)"""
        return await self._run(self._download_folder, product_id, folder_name, output_path)

    async def download_folder_to_memory(self, product_id: str, folder_name: str) -> bytes:
        """Download a folder as ZIP bytes; b"" on any failure"""
        return await self._run(self._download_folder_to_memory, product_id, folder_name)

    def _get_folder_list(self, product_id: str) -> List[FolderInfo]:
        if not self._need_session():
            return []
        data = self._request_json(f"/folders?productId={_url_encode(product_id)}", "GET")
        if isinstance(data, dict) and isinstance(data.get("folders"), list):
            data = data["folders"]
        if not isinstance(data, list):
            if data is not None:
                self._last_error = "Unexpected folder list response"
            return []
        return [_folder_info(item) for item in data if isinstance(item, dict)]

    def _get_folder_info(self, product_id: str, folder_name: str) -> Optional[FolderInfo]:
        if not self._need_session():
            return None
        endpoint = f"/folders/info/{_url_encode(folder_name)}?productId={_url_encode(product_id)}"
        data = self._request_json(endpoint, "GET")
        if not isinstance(data, dict):
            if data is not None:
                self._last_error = "Failed to parse JSON response"
            return None
        return _folder_info(data)

    def _folder_exists(self, product_id: str, folder_name: str) -> bool:
        info = self._get_folder_info(product_id, folder_name)
        if info is None or not info.id:
            if info is not None or not self._last_error:
                self._last_error = "Folder not found: " + folder_name
            return False
        return True

    def _download_folder(self, product_id: str, folder_name: str, output_path: str) -> bool:
        self._last_signed_at = 0
        if not self._need_session() or not self._folder_exists(product_id, folder_name):
            return False
        return self._download(_Zk1Download.FILE, "folder", product_id, folder_name, output_path)

    def _download_folder_to_memory(self, product_id: str, folder_name: str) -> bytes:
        self._last_signed_at = 0
        if not self._need_session() or not self._folder_exists(product_id, folder_name):
            return b""
        return self._download(_Zk1Download.MEMORY, "folder", product_id, folder_name)

    # =========================================================================
    # Product Information
    # =========================================================================

    async def get_product_variables(self, product_id: str) -> Dict[str, str]:
        """Product variables {name: value}. End-to-end encrypted values are opened
        with the content key and must carry a valid signature of an approved
        team member; any failure returns an empty dict."""
        return await self._run(self._get_product_variables, product_id)

    async def get_product_status(self, product_id: str) -> ProductStatusInfo:
        """Get product status"""
        return await self._run(self._get_product_status, product_id)

    async def get_product_news(self, product_id: str) -> ProductNewsInfo:
        """Get product news"""
        return await self._run(self._get_product_news, product_id)

    async def get_account_info(self) -> Optional[AccountInfo]:
        """Display name and owner's note of the signed-in user, or None"""
        return await self._run(self._get_account_info)

    def _get_product_variables(self, product_id: str) -> Dict[str, str]:
        if not self._need_session():
            return {}
        app_id = self._current_session.app_id
        if not app_id:
            self._last_error = "Missing appId in session"
            return {}
        endpoint = f"/apps/{_url_encode(app_id)}/products/{_url_encode(product_id)}/variables"
        download = _Zk1Download(self, _Zk1Download.VARIABLES, "vars", "", product_id)
        body = self._perform_request(endpoint, "GET", None, None, download)
        if download.is_delivery:
            if not download.succeeded:
                return {}
            variables, download.variables = download.variables, []
            self._log(f"Product variables: {len(variables)} (values not shown)")
            return dict(variables)
        if body is None:
            self._explain_e2ee_refusal()
            return {}
        try:
            items = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._last_error = "Failed to parse JSON response"
            return {}
        if isinstance(items, dict) and isinstance(items.get("variables"), list):
            items = items["variables"]
        if not isinstance(items, list):
            self._last_error = "Unexpected variables response"
            return {}
        result: Dict[str, str] = {}
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            if item.get("enc") is not None:
                # zk1 values only ever arrive inside a one-time delivery.
                self._last_error = _Zk1Download.failure(
                    f"variable '{item['name']}' arrived without the one-time delivery encryption")
                return {}
            value = item.get("value")
            result[item["name"]] = value if isinstance(value, str) else _scalar_text(value)
        self._last_error = ""
        return result

    def _get_product_status(self, product_id: str) -> ProductStatusInfo:
        status = ProductStatusInfo()
        data = self._request_json(f"/api/products/{_url_encode(product_id)}/status", "GET")
        if isinstance(data, dict) and isinstance(data.get("status"), dict):
            info = data["status"]
            status.has_status = True
            status.name = _scalar_text(info.get("name"))
            status.color = _scalar_text(info.get("color"))
            status.action = _scalar_text(info.get("action"))
        return status

    def _get_product_news(self, product_id: str) -> ProductNewsInfo:
        news = ProductNewsInfo()
        data = self._request_json(f"/api/products/{_url_encode(product_id)}/news", "GET")
        if isinstance(data, dict) and isinstance(data.get("news"), dict):
            info = data["news"]
            news.has_news = True
            news.headline = _scalar_text(info.get("headline"))
            news.content = _scalar_text(info.get("content"))
            news.updated_at = _scalar_text(info.get("updatedAt"))
        return news

    def _get_account_info(self) -> Optional[AccountInfo]:
        if not self._need_session():
            return None
        data = self._request_json("/me", "GET")
        if not isinstance(data, dict):
            return None
        return AccountInfo(username=_scalar_text(data.get("username")), note=_scalar_text(data.get("note")))

    # =========================================================================
    # User & Subscription
    # =========================================================================

    def has_product_access(self, product_id: str) -> bool:
        """True if the login response listed a subscription to this product"""
        return product_id in self._current_session.app_user.subscriptions

    async def get_user_products(self) -> List[Dict[str, str]]:
        """Products the user has access to (each a dict with "id", "name", ...)"""
        return await self._run(self._get_user_products)

    async def get_user_subscription_by_product(self, product_id: str) -> SubscriptionInfo:
        """Subscription details for a product (empty subscription_id if none)"""
        return await self._run(self._get_user_subscription_by_product, product_id)

    def _get_user_products(self) -> List[Dict[str, str]]:
        if not self._need_session():
            return []
        data = self._request_json("/products", "GET")
        if isinstance(data, dict) and isinstance(data.get("products"), list):
            data = data["products"]
        if not isinstance(data, list):
            return []
        products = []
        for item in data:
            if isinstance(item, dict):
                product = {key: _scalar_text(value) for key, value in item.items()}
                product.setdefault("id", "")
                product.setdefault("name", "")
                products.append(product)
        return products

    def _get_user_subscription_by_product(self, product_id: str) -> SubscriptionInfo:
        subscription = SubscriptionInfo()
        if not self._need_session():
            return subscription
        data = self._request_json(f"/products/{_url_encode(product_id)}/user-subscription", "GET")
        if not isinstance(data, dict):
            if self._last_status == 404 and not self._last_response_rejected:
                self._last_error = "No subscription found for this product"
            return subscription
        subscription.subscription_id = _scalar_text(data.get("subscriptionId"))
        subscription.app_user_id = _scalar_text(data.get("appUserId"))
        subscription.product_id = _scalar_text(data.get("productId"))
        subscription.status = _scalar_text(data.get("status"))
        subscription.expires_at = _opt_str(data.get("expiresAt")) or None
        subscription.is_paused = data.get("isPaused") is True
        subscription.paused_at = _opt_str(data.get("pausedAt")) or None
        subscription.paused_until = _opt_str(data.get("pausedUntil")) or None
        subscription.downloads = _as_int(data.get("downloads"))
        subscription.created_at = _scalar_text(data.get("createdAt"))
        subscription.updated_at = _scalar_text(data.get("updatedAt"))
        if not subscription.subscription_id:
            self._last_error = "No subscription found for this product"
        return subscription

    # =========================================================================
    # Decryption (downloads of apps without end-to-end encryption)
    # =========================================================================

    async def decrypt_file(self, input_path: str, output_path: str, key: str, iv: str = "") -> bool:
        """Decrypt a file in the Vaultix download format of apps without
        end-to-end encryption (AES-256-GCM; the IV is embedded in the data, so
        iv is ignored)."""
        return await self._run(self._decrypt_file, input_path, output_path, key, iv)

    def _decrypt_file(self, input_path: str, output_path: str, key: str, iv: str = "") -> bool:
        try:
            with open(input_path, "rb") as handle:
                encrypted = handle.read()
        except OSError:
            self._last_error = "Failed to open input file: " + input_path
            return False
        try:
            plain = self.decrypt_data(encrypted, key, iv)
        except ValueError as exc:
            self._last_error = str(exc)
            return False
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "wb") as handle:
                handle.write(plain)
        except OSError:
            self._last_error = "Failed to open output file: " + output_path
            return False
        return True

    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: str, iv: str = "") -> bytes:
        """Decrypt data in the Vaultix download format of apps without
        end-to-end encryption. Raises ValueError on failure; iv is ignored."""
        return _legacy_decrypt(bytes(encrypted_data), key.encode("utf-8"))

    # =========================================================================
    # HTTP
    # =========================================================================

    def _transport_call(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> RawResponse:
        if self._transport is not None:
            return self._transport(method, url, headers, body)
        transport = UrllibTransport(ssl_verify=self._ssl_verify, min_tls_version=self._min_tls_version,
                                    pins=self._pinned_certificates if self._certificate_pinning_enabled else None)
        return transport(method, url, headers, body)

    def _sign_request(self, method: str, endpoint: str, body: bytes, timestamp: str) -> str:
        message = f"{method}|{endpoint}|{body.decode('utf-8', 'replace')}|{timestamp}"
        return hmac.new((self._request_signing_key or "").encode("utf-8"), message.encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _perform_request(self, endpoint: str, method: str = "GET", body: Optional[bytes] = None,
                         headers: Optional[Dict[str, str]] = None, zk1_download: Optional[_Zk1Download] = None,
                         *, use_session: bool = True) -> Optional[bytes]:
        """One API request. Returns the body of a verified 2xx/3xx response, or
        None (get_last_error() says why). With zk1_download set, the request
        carries a fresh X-Vaultix-Eph key and a zk1 delivery is decrypted while
        it streams; the result is then in zk1_download and None is returned."""
        self._last_error = ""
        self._last_response_rejected = False
        self._last_status = 0
        self._last_headers = {}
        self._last_error_body = b""
        url = self._base_url + endpoint
        request_headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"VaultixSDK-Python/{__version__}",
        }
        # Fresh nonce per request: Vaultix signs the response over it, so a
        # response is only ever valid for this one request. zk1 deliveries are
        # always verified, so downloads always send one.
        nonce = ""
        if self._require_signed_responses or zk1_download is not None:
            nonce = response_signing.generate_nonce()
            request_headers["X-Vaultix-Nonce"] = nonce
        if zk1_download is not None:
            zk1_download.reset()
            request_headers["X-Vaultix-Eph"] = zk1_download.prepare_request()
        if self._request_signing_enabled and self._request_signing_key:
            timestamp = str(int(time.time() * 1000))
            request_headers["X-Request-Timestamp"] = timestamp
            request_headers["X-Request-Signature"] = self._sign_request(method, endpoint, body or b"", timestamp)
        if use_session and self._current_session.is_valid and self._current_session.session_token:
            request_headers["Authorization"] = f"Bearer {self._current_session.session_token}"
        elif self._api_key:
            request_headers["X-API-Key"] = self._api_key
        for name, value in (headers or {}).items():
            request_headers[name] = value

        if self._debug_mode:
            self._log(f"{method} {url}")
            if body:
                self._log(f"Data: {len(body)} bytes (not shown)")
            for name, value in request_headers.items():
                shown = value if name.lower() in _DEBUG_VISIBLE_HEADERS else "[redacted]"
                self._log(f"Header: {name}: {shown}")

        path_and_query = response_signing.path_and_query_from_url(url)
        try:
            raw = self._transport_call(method, url, request_headers, body)
        except Exception as exc:  # DNS, TLS, pinning, timeouts, refused connections
            self._last_error = f"Connection error: {exc}"
            if zk1_download is not None:
                zk1_download.client_secret = None
            self._log(self._last_error)
            return None

        try:
            status = raw.status
            headers_lower: Dict[str, bytes] = {}
            for name, value in raw.headers:
                headers_lower[name.lower()] = value.encode("latin-1", "replace").strip(b" \t\r\n")
            self._last_status = status
            if zk1_download is not None and headers_lower.get("x-encryption-key", b"").startswith(b"zk1d."):
                if zk1_download.engage(status, headers_lower, method, path_and_query, nonce, raw.redirects):
                    try:
                        while True:
                            chunk = raw.read(_READ_CHUNK)
                            if not chunk or not zk1_download.feed(chunk):
                                break
                    except (OSError, http.client.HTTPException, ValueError) as exc:
                        zk1_download.fail(f"Connection error: {exc}")
                    zk1_download.finish()
                self._last_response_rejected = zk1_download.rejected
                self._last_error = "" if zk1_download.succeeded else zk1_download.error
                if zk1_download.succeeded:
                    self._log(f"End-to-end encrypted {zk1_download.kind} delivery verified and decrypted")
                else:
                    self._log(self._last_error)
                return None
            if zk1_download is not None:
                zk1_download.client_secret = None
            data = raw.read()
        except (OSError, http.client.HTTPException, ValueError) as exc:
            self._last_error = f"Connection error: {exc}"
            self._log(self._last_error)
            return None
        finally:
            raw.close()

        self._log(f"Response: HTTP {status}, {len(data)} bytes")
        # Verify that the response really comes from Vaultix and answers exactly
        # this request, before anything in it is used (status codes and error
        # bodies included).
        if self._require_signed_responses:
            if raw.redirects > 0:
                verified, reason = False, "the request was redirected"
            else:
                verified, reason = self._verify_response(method, path_and_query, status,
                                                         hashlib.sha256(data).hexdigest(), headers_lower, nonce)
            if not verified:
                self._last_error = f"Server response could not be verified (HTTP {status}): {reason}"
                self._last_response_rejected = True
                self._log(self._last_error)
                return None
            self._log("Response signature verified")
        self._last_headers = headers_lower
        if status >= 400:
            self._last_error_body = data
            self._last_error = f"HTTP Error {status}: {data.decode('utf-8', 'replace')}"
            debug_info = headers_lower.get("x-debug-info")
            if debug_info:
                self._last_error += f" [Debug: {debug_info.decode('latin-1')}]"
            self._log(self._last_error)
            return None
        return data

    def _request_json(self, endpoint: str, method: str = "GET", body: Optional[bytes] = None,
                      headers: Optional[Dict[str, str]] = None, *, use_session: bool = True) -> Any:
        """Parsed JSON of a verified response, or None (get_last_error() says why)."""
        data = self._perform_request(endpoint, method, body, headers, use_session=use_session)
        if data is None:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._last_error = "Failed to parse JSON response"
            return None

    # =========================================================================
    # Private Helpers
    # =========================================================================

    def _hwid(self) -> str:
        """Hardware ID based on machine info"""
        machine_info = f"{platform.node()}-{platform.node()}"
        return hashlib.sha256(machine_info.encode()).hexdigest()

    async def _get_hwid(self) -> str:
        return self._hwid()

    @staticmethod
    def _compute_sha256_file(file_path: str) -> str:
        """Compute SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _persistent_token_path(self, api_key: str) -> Path:
        app = hashlib.sha256(b"vaultix-autologin:" + api_key.encode("utf-8")).hexdigest()[:16]
        return self._persistent_token_dir / f"autologin-{app}.dat"

    def _save_persistent_token(self, token: str, api_key: str) -> None:
        try:
            path = self._persistent_token_path(api_key)
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(self._obfuscate(token))
        except OSError:
            pass

    def _load_persistent_token(self, api_key: str) -> Optional[str]:
        try:
            path = self._persistent_token_path(api_key)
            if path.exists():
                return self._deobfuscate(path.read_text())
        except OSError:
            pass
        return None

    def _delete_persistent_token(self, api_key: str) -> None:
        try:
            self._persistent_token_path(api_key).unlink()
        except OSError:
            pass

    @staticmethod
    def _obfuscate(data: str) -> str:
        """Obfuscate data for storage (not encryption)"""
        alphabet = string.ascii_letters + string.digits
        garbage = "".join(secrets.choice(alphabet) for _ in range(10 + secrets.randbelow(41)))
        return base64.b64encode(f"{garbage}|{data}|{garbage}".encode()).decode()

    @staticmethod
    def _deobfuscate(obfuscated: str) -> Optional[str]:
        try:
            parts = base64.b64decode(obfuscated.encode()).decode().split("|")
            if len(parts) >= 3:
                return parts[1]
        except (ValueError, UnicodeDecodeError):
            pass
        return None

    def _log(self, message: str) -> None:
        if self._debug_mode:
            print(f"[VaultixSDK] {message}")


class SyncVaultixClient(VaultixClient):
    """Synchronous version of VaultixClient: the same calls without await."""

    def authenticate_with_username(self, username: str, password: str) -> bool:
        return self._authenticate_with_username(username, password)

    def authenticate_with_key(self, user_key: str) -> bool:
        return self._authenticate_with_key(user_key)

    def try_auto_login(self) -> bool:
        return self._try_auto_login()

    def refresh_token(self) -> bool:
        return self._refresh_token()

    def is_token_expired(self) -> bool:
        return self._is_token_expired()

    def get_file_list(self, product_id: str) -> List[FileInfo]:
        return self._get_file_list(product_id)

    def get_file_info(self, product_id: str, file_name: str) -> Optional[FileInfo]:
        return self._get_file_info(product_id, file_name)

    def download_file(self, product_id: str, file_name: str, output_path: str) -> bool:
        return self._download_file(product_id, file_name, output_path)

    def download_file_to_memory(self, product_id: str, file_name: str) -> bytes:
        return self._download_file_to_memory(product_id, file_name)

    def stream_file(self, product_id: str, file_name: str,
                    progress_callback: Optional[Callable[[bytes, int, int], None]] = None) -> bool:
        return self._stream_chunks(self._download_file_to_memory(product_id, file_name), progress_callback)

    def is_valid_file_hash(self, product_id: str, file_name: str, file_path: str) -> bool:
        return self._is_valid_file_hash(product_id, file_name, file_path)

    def get_folder_list(self, product_id: str) -> List[FolderInfo]:
        return self._get_folder_list(product_id)

    def get_folder_info(self, product_id: str, folder_name: str) -> Optional[FolderInfo]:
        return self._get_folder_info(product_id, folder_name)

    def download_folder(self, product_id: str, folder_name: str, output_path: str) -> bool:
        return self._download_folder(product_id, folder_name, output_path)

    def download_folder_to_memory(self, product_id: str, folder_name: str) -> bytes:
        return self._download_folder_to_memory(product_id, folder_name)

    def get_product_variables(self, product_id: str) -> Dict[str, str]:
        return self._get_product_variables(product_id)

    def get_product_status(self, product_id: str) -> ProductStatusInfo:
        return self._get_product_status(product_id)

    def get_product_news(self, product_id: str) -> ProductNewsInfo:
        return self._get_product_news(product_id)

    def get_account_info(self) -> Optional[AccountInfo]:
        return self._get_account_info()

    def get_user_products(self) -> List[Dict[str, str]]:
        return self._get_user_products()

    def get_user_subscription_by_product(self, product_id: str) -> SubscriptionInfo:
        return self._get_user_subscription_by_product(product_id)

    def decrypt_file(self, input_path: str, output_path: str, key: str, iv: str = "") -> bool:
        return self._decrypt_file(input_path, output_path, key, iv)
