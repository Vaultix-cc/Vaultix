"""Verification of Vaultix response signatures (vaultix-resp-v1).

Every request carries a fresh random X-Vaultix-Nonce. Vaultix answers with
X-Vaultix-Signature (base64url Ed25519), X-Vaultix-Key-Id and
X-Vaultix-Signed-At (Unix seconds). The signature covers these 11 lines
joined by "\\n" (no field can contain a line break):

    vaultix-resp-v1
    key id
    nonce (as sent)
    signed_at (as received)
    HTTP method (as sent)
    path?query (as sent; no "?" when there is no query)
    status code
    SHA-256 hex of the complete response body ("zk1-stream" for zk1 deliveries)
    X-Encryption-Key value or ""
    X-Encryption-IV value or ""
    Content-Type value or ""

This matches backend/response_signing.py and the C++ SDK.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets
import time
from typing import Dict, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CANONICAL_VERSION = b"vaultix-resp-v1"
STREAM_BODY_MARKER = "zk1-stream"
DEFAULT_CLOCK_SKEW_SECONDS = 600

# Keys Vaultix signs responses with ("vx-sig-" + first 16 hex characters of
# sha256(raw public key) -> raw 32-byte Ed25519 public key, hex). A key
# rotation ships an SDK that lists the old and the new key side by side.
TRUSTED_RESPONSE_KEYS: Dict[str, str] = {
    "vx-sig-22545e6918734982": "c21b9ba40714e61eaaf8529941400264996decd9fb8480121d3e4c7533cf2d8c",
}

Field = Union[bytes, str, int]


def key_id_for(public_key_raw: bytes) -> str:
    return "vx-sig-" + hashlib.sha256(bytes(public_key_raw)).hexdigest()[:16]


def generate_nonce() -> str:
    """24 random bytes as 48 hex characters."""
    return secrets.token_hex(24)


def _field(value: Field) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, int):
        return str(value).encode("ascii")
    return value.encode("utf-8")


def canonical(key_id: Field, nonce: Field, signed_at: Field, method: Field, path_and_query: Field,
              status: Field, body_hash: Field, encryption_key: Field = b"", encryption_iv: Field = b"",
              content_type: Field = b"") -> Optional[bytes]:
    """The signed bytes, or None if a field contains a line break."""
    parts = [_field(part) for part in (key_id, nonce, signed_at, method, path_and_query, status, body_hash,
                                       encryption_key, encryption_iv, content_type)]
    if any(b"\n" in part or b"\r" in part for part in parts):
        return None
    return b"\n".join([CANONICAL_VERSION] + parts)


def path_and_query_from_url(url: str) -> str:
    """Path and query of a URL as they go on the request line (no "?" for an empty query)."""
    parts = urlsplit(url)
    path = parts.path or "/"
    return path + "?" + parts.query if parts.query else path


def decode_b64url_strict(text: str) -> Optional[bytes]:
    """Unpadded base64url (what the server sends), else None."""
    if len(text) % 4 == 1 or re.fullmatch(r"[A-Za-z0-9_-]*", text) is None:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def _printable(value: str) -> str:
    return "".join(c if (c.isascii() and c.isalnum()) or c in "-_" else "?" for c in value[:48])


def verify(*, method: str, path_and_query: str, status: int, body_hash: str,
           headers: Mapping[str, bytes], nonce: str, trusted: Mapping[str, str],
           clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
           now: Optional[float] = None) -> Tuple[bool, str]:
    """Check one response. headers: lower-case names -> raw value bytes (last
    occurrence, surrounding whitespace removed). Returns (ok, failure reason)."""
    def header(name: str) -> bytes:
        return headers.get(name, b"")

    signature = header("x-vaultix-signature").decode("latin-1")
    key_id = header("x-vaultix-key-id").decode("latin-1")
    signed_at = header("x-vaultix-signed-at").decode("latin-1")
    if not signature or not key_id or not signed_at:
        return False, "the response is not signed"
    public_hex = trusted.get(key_id)
    if public_hex is None:
        return False, f"unknown signing key '{_printable(key_id)}'"
    if len(signed_at) > 12 or not signed_at.isdigit() or not signed_at.isascii():
        return False, "invalid signing time"
    message = canonical(key_id, nonce, signed_at, method, path_and_query, status, body_hash,
                        header("x-encryption-key"), header("x-encryption-iv"), header("content-type"))
    raw_signature = decode_b64url_strict(signature)
    valid = False
    if message is not None and raw_signature is not None and len(raw_signature) == 64:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(raw_signature, message)
            valid = True
        except (InvalidSignature, ValueError):
            valid = False
    if not valid:
        return False, "invalid signature (the response was altered, replayed, or does not come from Vaultix)"
    skew = abs(int(time.time() if now is None else now) - int(signed_at))
    if skew > clock_skew_seconds:
        return False, (f"the signature time differs from this computer's clock by {skew} seconds "
                       f"(check the system date and time)")
    return True, ""
