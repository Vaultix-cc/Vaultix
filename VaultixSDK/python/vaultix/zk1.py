"""End-to-end encryption ("zk1") for the Vaultix Python SDK.

Files, folders and product variables of end-to-end encrypted apps are
encrypted and signed in the browser of the app's team. Vaultix stores only
ciphertext and re-encrypts every SDK download under a one-time X25519 key
(layer 3). This module is the SDK side of that format: it opens a delivery,
unseals the file key or value with the app's content key ("vxk_..."), checks
the uploader's signature against the app signing key in the content key, and
decrypts the content stream.

VaultixClient uses this module internally; integrations normally only call
VaultixClient.set_content_key(). It is public so the format can be checked
against the shared test vectors (tests/crypto_vectors/zk1.json in the Vaultix
backend), byte for byte, like the C++ SDK and the browser.

Rule for every function here: a failed check raises Zk1Error (or returns
False) and releases no plaintext.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import struct
from typing import Callable, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "Zk1Error", "ContentKey", "SignatureBlock", "StreamDecryptor", "DeliveryOpener",
    "b64u_encode", "b64u_decode", "hkdf", "x25519_generate", "x25519_public", "x25519_shared",
    "ed25519_verify", "sdk_key_decode", "hash_key_from_sdk_secret", "keyed_hash", "fingerprint",
    "seal_context", "unseal", "member_message", "upload_message", "variable_message",
    "verify_signature_block", "parse_delivery_header", "delivery_key", "stream_decrypt",
    "open_delivery", "split_file_delivery", "parse_file_key_payload", "sdk_unseal_file_key",
    "sdk_open_file", "sdk_open_variable", "open_variables", "NEED_CONTENT_KEY",
]

CHUNK_SIZE = 1024 * 1024          # plaintext bytes per stream chunk
TAG_BYTES = 16                    # AES-GCM tag after every chunk
HEADER_BYTES = 9                  # magic(4) || version(1) || u32be chunk size
STREAM_VERSION = 1
STORED_MAGIC = b"VXZ1"
DELIVERY_MAGIC = b"VXD1"
SEAL_VERSION = 1
SEALED_FILE_KEY_BYTES = 121       # 0x01 || eph pk || GCM(fk || sha256 || u64be size)
FILE_KEY_PAYLOAD_BYTES = 72       # fk || sha256 || u64be size
MAX_SEALED_BYTES = 65536          # a sealed variable value
SDK_KEY_CHARS = 96                # "vxk_" + b64u(0x02 || sk_sdk || aspk || checksum(4))
SDK_KEY_VERSION = 2
MAX_USER_ID_BYTES = 128
SIG_BLOCK_VERSION = 1
MIN_SIGNATURE_BLOCK_BYTES = 3 + 1 + 208
MAX_SIGNATURE_BLOCK_BYTES = 3 + MAX_USER_ID_BYTES + 208
MAX_VARS_PAYLOAD_BYTES = 64 * 1024 * 1024
DELIVERY_KINDS = ("file", "folder", "vars")
DELIVERY_HEADER_PREFIX = "zk1d."
APP_KEY_SALT = b"vaultix-e2ee-v1"

NEED_CONTENT_KEY = ("This app uses end-to-end encryption: call set_content_key with the vxk_ key "
                    "from App Settings")


class Zk1Error(ValueError):
    """A zk1 check failed. Nothing that failed a check is ever returned."""


# --------------------------------------------------------------------------
# Encoding and primitives
# --------------------------------------------------------------------------

_B64U_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def b64u_encode(data: bytes) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64u_decode(text: str, max_bytes: int) -> bytes:
    """Strict base64url without padding (no other characters, length limit)."""
    if (not isinstance(text, str) or not text or len(text) > 4 * max_bytes // 3 + 4
            or len(text) % 4 == 1 or any(ch not in _B64U_ALPHABET for ch in text)):
        raise Zk1Error("invalid base64url value")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise Zk1Error("invalid base64url value") from exc


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(bytes(ikm))


def _raw_public(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519_generate() -> Tuple[bytes, bytes]:
    """A fresh X25519 key pair (secret, public)."""
    key = X25519PrivateKey.generate()
    secret = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    return secret, _raw_public(key.public_key())


def x25519_public(secret: bytes) -> bytes:
    return _raw_public(X25519PrivateKey.from_private_bytes(bytes(secret)).public_key())


def x25519_shared(secret: bytes, peer_public: bytes) -> bytes:
    """X25519; refuses low-order peer keys (an all-zero shared secret)."""
    try:
        shared = X25519PrivateKey.from_private_bytes(bytes(secret)).exchange(
            X25519PublicKey.from_public_bytes(bytes(peer_public)))
    except ValueError as exc:
        raise Zk1Error("invalid X25519 public key") from exc
    if shared == bytes(32):
        raise Zk1Error("invalid X25519 public key")
    return shared


# Ed25519 points of small order (and the non-canonical encodings of the ones
# with x = 0). With such a "public key" a trivial signature verifies for any
# message in OpenSSL, so they are refused like non-canonical encodings (y >= p),
# as the browser and the backend do.
_SMALL_ORDER_ED25519 = frozenset(bytes.fromhex(h) for h in (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
))
_ED25519_P = 2 ** 255 - 19


def weak_signing_key(raw: bytes) -> bool:
    """True for a small-order or non-canonically encoded Ed25519 public key."""
    raw = bytes(raw)
    if len(raw) != 32 or raw in _SMALL_ORDER_ED25519:
        return True
    return (int.from_bytes(raw, "little") & ((1 << 255) - 1)) >= _ED25519_P


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Ed25519 (RFC 8032) verification; False for weak keys and malformed input."""
    if weak_signing_key(public_key) or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(signature), bytes(message))
        return True
    except (InvalidSignature, ValueError):
        return False


def _gcm_open(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(bytes(key)).decrypt(nonce, bytes(data), aad)
    except (InvalidTag, ValueError) as exc:
        raise Zk1Error("authentication failed") from exc


# --------------------------------------------------------------------------
# Content key (section 1): "vxk_" + b64u(0x02 || sk_sdk || aspk || checksum)
# --------------------------------------------------------------------------

def sdk_key_decode(vxk: str) -> Tuple[bytes, bytes]:
    """(sdk secret, app signing public key) of a version-2 vxk_ key.

    Checks the length, the version byte and the checksum; other versions (the
    52-character version-1 keys included) are refused."""
    if not isinstance(vxk, str):
        raise Zk1Error("invalid SDK key")
    value = vxk.strip(" \t\r\n\v\f")
    if len(value) != SDK_KEY_CHARS or not value.startswith("vxk_"):
        raise Zk1Error("invalid SDK key")
    raw = b64u_decode(value[4:], 69)
    body = raw[:65]
    if (len(raw) != 69 or raw[0] != SDK_KEY_VERSION
            or not hmac.compare_digest(hashlib.sha256(b"vaultix-vxk" + body).digest()[:4], raw[65:])):
        raise Zk1Error("invalid SDK key")
    return raw[1:33], raw[33:65]


def hash_key_from_sdk_secret(sdk_secret: bytes) -> bytes:
    """kh = HKDF(sk_sdk, "vaultix-e2ee-v1", "hash-key"): the key of keyed hashes."""
    return hkdf(sdk_secret, APP_KEY_SALT, b"hash-key")


def keyed_hash(hash_key: bytes, sha256_digest: bytes) -> bytes:
    """HMAC(kh, SHA-256(content)): what Vaultix stores instead of the plain hash."""
    return hmac.new(bytes(hash_key), bytes(sha256_digest), hashlib.sha256).digest()


def fingerprint(sdk_public: bytes, sign_public: bytes) -> str:
    """First 16 hex characters of SHA256("vaultix-fp" || pk_sdk || aspk), "XXXX-XXXX-XXXX-XXXX"."""
    digest = hashlib.sha256(b"vaultix-fp" + bytes(sdk_public) + bytes(sign_public)).hexdigest()[:16].upper()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


class ContentKey:
    """What the SDK holds of an app (from its vxk_ key). Never printed."""

    __slots__ = ("sdk_secret", "sign_public", "hash_key")

    def __init__(self, sdk_secret: bytes, sign_public: bytes):
        if len(sdk_secret) != 32 or len(sign_public) != 32:
            raise Zk1Error("invalid SDK key")
        self.sdk_secret = bytes(sdk_secret)      # sk_sdk: opens the sealed file keys and values
        self.sign_public = bytes(sign_public)    # aspk: approves the team members who sign content
        self.hash_key = hash_key_from_sdk_secret(self.sdk_secret)  # kh: keyed hashes

    @classmethod
    def from_sdk_key(cls, vxk: str) -> "ContentKey":
        secret, sign_public = sdk_key_decode(vxk)
        return cls(secret, sign_public)

    @property
    def sdk_public(self) -> bytes:
        return x25519_public(self.sdk_secret)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.sdk_public, self.sign_public)

    def __repr__(self) -> str:
        return f"ContentKey(fingerprint={self.fingerprint!r})"


def _as_content_key(key: Union[ContentKey, str]) -> ContentKey:
    return key if isinstance(key, ContentKey) else ContentKey.from_sdk_key(key)


# --------------------------------------------------------------------------
# Seal (section 3)
# --------------------------------------------------------------------------

def _utf8(text: str) -> bytes:
    try:
        return (text or "").encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Zk1Error("text is not valid Unicode") from exc


def seal_context(kind: str, name: str, product_id: str = "") -> bytes:
    """kind || 0x00 || scope || 0x00 || name. The scope is the product ID
    (variables, product files and folders) or "" (general files and folders)."""
    if kind not in ("file", "folder", "var"):
        raise Zk1Error(f"unknown kind {kind!r}")
    return kind.encode("ascii") + b"\x00" + _utf8(product_id) + b"\x00" + _utf8(name)


def unseal(app_secret: bytes, sealed: bytes, context: bytes) -> bytes:
    """Open 0x01 || e_pk || AEAD(k, 0^12, payload, context)."""
    sealed = bytes(sealed)
    if len(sealed) < 1 + 32 + TAG_BYTES or sealed[0] != SEAL_VERSION or not context:
        raise Zk1Error("unsupported sealed format")
    eph_public = sealed[1:33]
    try:
        app_public = x25519_public(app_secret)
        shared = x25519_shared(app_secret, eph_public)
        key = hkdf(shared, eph_public + app_public, b"vaultix-zk1-seal\x00" + bytes(context))
        return _gcm_open(key, bytes(12), sealed[33:], bytes(context))
    except Zk1Error as exc:
        raise Zk1Error("cannot open the sealed key") from exc


def parse_file_key_payload(payload: bytes) -> Tuple[bytes, bytes, int]:
    """(file key, SHA-256 of the plaintext, plaintext size)."""
    if len(payload) != FILE_KEY_PAYLOAD_BYTES:
        raise Zk1Error("invalid file key payload")
    return bytes(payload[:32]), bytes(payload[32:64]), struct.unpack(">Q", payload[64:])[0]


# --------------------------------------------------------------------------
# Signed content (sections 4 and 5)
# --------------------------------------------------------------------------

def _text(value: str) -> bytes:
    data = _utf8(value)
    if b"\x00" in data:
        raise Zk1Error("text fields must not contain NUL")
    return data


def member_message(app_id: str, user_id: str, enc_public: bytes, sign_public: bytes, issued_at_ms: int) -> bytes:
    return (b"vaultix-member-v1\x00" + _text(app_id) + b"\x00" + _text(user_id) + b"\x00"
            + bytes(enc_public) + bytes(sign_public) + struct.pack(">Q", issued_at_ms))


def upload_message(app_id: str, kind: str, scope: str, name: str, keyed_hash_value: bytes, size: int,
                   signed_at_ms: int) -> bytes:
    if kind not in ("file", "folder") or len(keyed_hash_value) != 32:
        raise Zk1Error("invalid upload message")
    return (b"vaultix-upload-v1\x00" + _text(app_id) + b"\x00" + kind.encode("ascii") + b"\x00" + _text(scope)
            + b"\x00" + _text(name) + b"\x00" + bytes(keyed_hash_value) + struct.pack(">QQ", size, signed_at_ms))


def variable_message(app_id: str, product_id: str, name: str, keyed_value_hash: bytes, signed_at_ms: int) -> bytes:
    if len(keyed_value_hash) != 32:
        raise Zk1Error("invalid variable message")
    return (b"vaultix-var-v1\x00" + _text(app_id) + b"\x00" + _text(product_id) + b"\x00" + _text(name) + b"\x00"
            + bytes(keyed_value_hash) + struct.pack(">Q", signed_at_ms))


class SignatureBlock:
    """0x01 || u16be(len userId) || userId || upk_enc || upk_sign || u64be(issuedAtMs)
    || certSig(64) || u64be(signedAtMs) || sig(64)"""

    __slots__ = ("user_id", "enc_public", "sign_public", "issued_at_ms", "cert_signature",
                 "signed_at_ms", "signature")

    @classmethod
    def parse(cls, raw: bytes) -> "SignatureBlock":
        raw = bytes(raw)
        if len(raw) < 3 or raw[0] != SIG_BLOCK_VERSION:
            raise Zk1Error("invalid signature block")
        (id_len,) = struct.unpack(">H", raw[1:3])
        if not 1 <= id_len <= MAX_USER_ID_BYTES or len(raw) != 3 + id_len + 32 + 32 + 8 + 64 + 8 + 64:
            raise Zk1Error("invalid signature block")
        block = cls()
        pos = 3
        try:
            block.user_id = raw[pos:pos + id_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Zk1Error("invalid signature block") from exc
        pos += id_len
        block.enc_public, pos = raw[pos:pos + 32], pos + 32
        block.sign_public, pos = raw[pos:pos + 32], pos + 32
        (block.issued_at_ms,), pos = struct.unpack(">Q", raw[pos:pos + 8]), pos + 8
        block.cert_signature, pos = raw[pos:pos + 64], pos + 64
        (block.signed_at_ms,), pos = struct.unpack(">Q", raw[pos:pos + 8]), pos + 8
        block.signature = raw[pos:pos + 64]
        return block


MessageFor = Callable[[int], bytes]


def verify_signature_block(raw: bytes, app_id: str, app_sign_public: bytes, message_for: MessageFor) -> SignatureBlock:
    """Parse the block, check certSig (the owner's approval of the member) with
    the app signing key over the member message for app_id, then sig with the
    member's signing key over message_for(signedAtMs)."""
    block = SignatureBlock.parse(raw)
    try:
        member = member_message(app_id, block.user_id, block.enc_public, block.sign_public, block.issued_at_ms)
    except Zk1Error:
        member = b""
    if not member or not ed25519_verify(app_sign_public, block.cert_signature, member):
        raise Zk1Error("the signer is not approved by the app owner")
    try:
        message = message_for(block.signed_at_ms)
    except Zk1Error:
        message = b""
    if not message or not ed25519_verify(block.sign_public, block.signature, message):
        raise Zk1Error("invalid signature")
    return block


# --------------------------------------------------------------------------
# Layer 3 header and key (section 8)
# --------------------------------------------------------------------------

def parse_delivery_header(value: str) -> Tuple[bytes, str, str]:
    """"zk1d.<b64u server pk>.<kind>.<objectId>" -> (server public key, kind, object id)."""
    if not isinstance(value, str) or not value.startswith(DELIVERY_HEADER_PREFIX):
        raise Zk1Error("invalid delivery header")
    parts = value[len(DELIVERY_HEADER_PREFIX):].split(".")
    if len(parts) != 3 or parts[1] not in DELIVERY_KINDS or not parts[2]:
        raise Zk1Error("invalid delivery header")
    server_public = b64u_decode(parts[0], 32)
    if len(server_public) != 32:
        raise Zk1Error("invalid delivery header")
    return server_public, parts[1], parts[2]


def delivery_key(client_secret: bytes, server_public: bytes, kind: str, object_id: str) -> bytes:
    """K = HKDF(X25519(c_sk, s_pk), c_pk || s_pk, "vaultix-zk1-deliver" 0x00 kind 0x00 objectId)."""
    client_public = x25519_public(client_secret)
    shared = x25519_shared(client_secret, server_public)
    info = b"vaultix-zk1-deliver\x00" + kind.encode("ascii") + b"\x00" + _utf8(object_id)
    return hkdf(shared, client_public + bytes(server_public), info)


# --------------------------------------------------------------------------
# Stream (section 6)
# --------------------------------------------------------------------------

def _chunk_nonce(index: int, last: bool) -> bytes:
    return bytes(7) + struct.pack(">I", index) + (b"\x01" if last else b"\x00")


Sink = Callable[[bytes], bool]


class StreamDecryptor:
    """Incremental decryption of a VXZ1 (stored) or VXD1 (delivery) stream.

    The sink only receives chunks whose tag verified, but the stream as a whole
    is authentic only when finish() returns True: on failure the caller must
    discard everything the sink received. The sink returns False to abort."""

    def __init__(self, key: bytes, magic: bytes, sink: Optional[Sink] = None, *, chunk_size: int = CHUNK_SIZE):
        self._aead = AESGCM(bytes(key))
        self._magic = bytes(magic)
        self._sink = sink
        self._chunk_size = chunk_size
        self._header = bytearray()
        self._header_checked = False
        self._pending = bytearray()
        self._index = 0
        self.plaintext_bytes = 0
        self.error = ""
        self._failed = False
        self._finished = False

    def _fail(self, message: str) -> bool:
        if not self._failed:
            self.error = message
        self._failed = True
        return False

    def _open_chunk(self, data: bytes, last: bool) -> bool:
        if len(data) < TAG_BYTES:
            return self._fail("stream too short" if self._index == 0 else "truncated stream")
        if self._index > 0xFFFFFFFF:
            return self._fail("too many chunks")
        try:
            plain = self._aead.decrypt(_chunk_nonce(self._index, last), bytes(data), bytes(self._header))
        except (InvalidTag, ValueError):
            return self._fail(f"chunk {self._index} failed authentication")
        self._index += 1
        self.plaintext_bytes += len(plain)
        if plain and self._sink is not None and not self._sink(plain):
            return self._fail("the decrypted data could not be stored")
        return True

    def update(self, data: bytes) -> bool:
        if self._failed:
            return False
        if self._finished:
            return self._fail("data after the end of the stream")
        data = memoryview(bytes(data)) if not isinstance(data, (bytes, bytearray)) else memoryview(data)
        need = HEADER_BYTES - len(self._header)
        if need > 0:
            self._header += data[:need]
            data = data[need:]
        if len(self._header) < HEADER_BYTES:
            return True
        if not self._header_checked:
            if bytes(self._header[:4]) != self._magic or self._header[4] != STREAM_VERSION:
                return self._fail("unsupported stream header")
            if struct.unpack(">I", bytes(self._header[5:9]))[0] != self._chunk_size:
                return self._fail("unsupported chunk size")
            self._header_checked = True
        if not len(data):
            return True
        # While more than one full chunk is buffered, the first one cannot be
        # the final chunk; the rest is decided at finish().
        self._pending += data
        full = self._chunk_size + TAG_BYTES
        offset = 0
        while len(self._pending) - offset > full:
            if not self._open_chunk(self._pending[offset:offset + full], False):
                return False
            offset += full
        if offset:
            del self._pending[:offset]
        return True

    def finish(self) -> bool:
        if self._failed:
            return False
        if self._finished:
            return True
        if len(self._header) < HEADER_BYTES or (self._index == 0 and len(self._pending) < TAG_BYTES):
            return self._fail("stream too short")
        if not self._open_chunk(self._pending, True):
            return False
        self._pending = bytearray()
        self._finished = True
        return True


def stream_decrypt(key: bytes, blob: bytes, magic: bytes, *, chunk_size: int = CHUNK_SIZE) -> bytes:
    """Decrypt a whole stream; raises Zk1Error on any defect (no partial plaintext)."""
    out: List[bytes] = []
    decryptor = StreamDecryptor(key, magic, lambda piece: out.append(piece) is None, chunk_size=chunk_size)
    if not decryptor.update(blob) or not decryptor.finish():
        raise Zk1Error(decryptor.error)
    return b"".join(out)


# --------------------------------------------------------------------------
# One layer-3 delivery, opened incrementally
# --------------------------------------------------------------------------

class DeliveryOpener:
    """One layer-3 delivery: VXD1 under the one-time key; for "file" and
    "folder" also the sealed file key, the signature block and the VXZ1
    content. The signature block is verified before any content is decrypted,
    and the content is checked against the sealed size and SHA-256 in
    finish(). Same failure rule as StreamDecryptor."""

    _PREFIX_BYTES = 2 + SEALED_FILE_KEY_BYTES + 2  # u16be(121) || sealed key || u16be(len signature block)

    def __init__(self, client_secret: bytes, expected_kind: str = ""):
        self._client_secret: Optional[bytes] = bytes(client_secret)
        self._expected_kind = expected_kind
        self.kind = ""
        self.object_id = ""
        self.scope = ""                 # file/folder: the scope the sealed key opened with
        self.error = ""
        self._key: Optional[ContentKey] = None
        self._app_id = ""
        self._name = ""
        self._product_id = ""
        self._sink: Optional[Sink] = None
        self._outer: Optional[StreamDecryptor] = None
        self._inner: Optional[StreamDecryptor] = None
        self._prefix = bytearray()
        self._sealed_opened = False
        self._file_key = b""
        self._signature = bytearray()
        self._signature_length = 0
        self._signed_at = 0
        self._content_sha256 = b""
        self._content_size = 0
        self._content_written = 0
        self._hash = None
        self._vars = bytearray()
        self._failed = False
        self._begun = False
        self._finished = False

    # -- results --------------------------------------------------------------

    @property
    def content_size(self) -> int:
        """file/folder: the sealed plaintext size, once known (else 0)."""
        return self._content_size if self._sealed_opened else 0

    @property
    def signed_at(self) -> int:
        """file/folder: signedAtMs, once the signature verified (else 0)."""
        return self._signed_at if self._inner is not None else 0

    @property
    def vars_payload(self) -> bytes:
        """"vars": the decrypted JSON, valid after finish()."""
        return bytes(self._vars)

    # -- state machine --------------------------------------------------------

    def _fail(self, message: str) -> bool:
        if not self._failed:
            self.error = message
        self._failed = True
        return False

    def set_file_context(self, key: ContentKey, app_id: str, name: str, product_id: str,
                         sink: Optional[Sink] = None) -> None:
        """file/folder: the content key, the app id (signed messages), and the
        name and product that were requested; the sealed key is opened with the
        product scope, else with the general scope ""."""
        self._key = key
        self._app_id = app_id
        self._name = name
        self._product_id = product_id
        self._sink = sink

    def begin(self, header_value: str) -> bool:
        """header_value: the X-Encryption-Key value of the response."""
        if self._failed:
            return False
        if self._begun or self._client_secret is None:
            return self._fail("delivery already started")
        try:
            server_public, kind, object_id = parse_delivery_header(header_value)
        except Zk1Error:
            return self._fail("invalid delivery header")
        if self._expected_kind and kind != self._expected_kind:
            return self._fail(f"unexpected delivery kind '{kind}' (asked for {self._expected_kind})")
        if kind != "vars" and self._key is None:
            return self._fail("no content key")
        secret, self._client_secret = self._client_secret, None  # one delivery per request key
        try:
            key = delivery_key(secret, server_public, kind, object_id)
        except Zk1Error:
            return self._fail("invalid server key in the delivery header")
        self.kind = kind
        self.object_id = object_id
        self._begun = True
        self._outer = StreamDecryptor(key, DELIVERY_MAGIC, self._on_payload)
        return True

    def update(self, data: bytes) -> bool:
        if self._failed:
            return False
        if not self._begun or self._finished:
            return self._fail("unexpected delivery data")
        if not self._outer.update(data):
            return self._fail(self._outer.error)
        return True

    def finish(self) -> bool:
        if self._failed:
            return False
        if not self._begun:
            return self._fail("delivery not started")
        if self._finished:
            return True
        if not self._outer.finish():
            return self._fail(self._outer.error)
        if self.kind != "vars":
            if self._inner is None:
                return self._fail("delivery too short")
            if not self._inner.finish():
                return self._fail(self._inner.error)
            if self._content_written != self._content_size:
                return self._fail("the file does not match its sealed size")
            if not hmac.compare_digest(self._hash.digest(), self._content_sha256):
                return self._fail("the file does not match its sealed SHA-256")
        self._finished = True
        return True

    # -- payload --------------------------------------------------------------

    def _open_sealed_key(self) -> bool:
        if self._key is None:
            return self._fail("no content key")
        sealed = bytes(self._prefix[2:2 + SEALED_FILE_KEY_BYTES])
        # A download by name gets the product's own file or, failing that, the
        # general file of that name: try the product scope, then the general
        # scope (zk1_reference.sdk_unseal_file_key).
        try:
            payload, scope = sdk_unseal_file_key(self._key.sdk_secret, sealed, self.kind, self._name,
                                                 self._product_id)
            file_key, digest, size = parse_file_key_payload(payload)
        except Zk1Error:
            return self._fail("cannot open the sealed file key (wrong content key, or it was sealed "
                              "for another name or product)")
        self.scope = scope
        self._file_key, self._content_sha256, self._content_size = file_key, digest, size
        self._sealed_opened = True
        at = 2 + SEALED_FILE_KEY_BYTES
        self._signature_length = struct.unpack(">H", bytes(self._prefix[at:at + 2]))[0]
        if not MIN_SIGNATURE_BLOCK_BYTES <= self._signature_length <= MAX_SIGNATURE_BLOCK_BYTES:
            return self._fail("invalid signature block in delivery")
        return True

    def _verify_signature(self) -> bool:
        khash = keyed_hash(self._key.hash_key, self._content_sha256)
        app_id, kind, scope, name, size = self._app_id, self.kind, self.scope, self._name, self._content_size
        try:
            block = verify_signature_block(bytes(self._signature), app_id, self._key.sign_public,
                                           lambda at: upload_message(app_id, kind, scope, name, khash, size, at))
        except Zk1Error as exc:
            return self._fail(f"signature check failed: {exc}")
        self._signed_at = block.signed_at_ms
        self._key = None  # not needed any more
        self._hash = hashlib.sha256()
        self._inner = StreamDecryptor(self._file_key, STORED_MAGIC, self._on_content)
        self._file_key = b""
        return True

    def _on_payload(self, data: bytes) -> bool:
        if self._failed:
            return False
        if self.kind == "vars":
            if len(data) > MAX_VARS_PAYLOAD_BYTES - len(self._vars):
                return self._fail("variables payload too large")
            self._vars += data
            return True
        # u16be(len sealed) || sealed || u16be(len sig) || signature block || VXZ1 stream
        data = memoryview(data)
        if len(self._prefix) < self._PREFIX_BYTES:
            take = self._PREFIX_BYTES - len(self._prefix)
            had = len(self._prefix)
            self._prefix += data[:take]
            data = data[take:]
            if had < 2 <= len(self._prefix) and struct.unpack(">H", bytes(self._prefix[:2]))[0] != SEALED_FILE_KEY_BYTES:
                return self._fail("invalid sealed key in delivery")
            if len(self._prefix) < self._PREFIX_BYTES:
                return True
        if not self._sealed_opened and not self._open_sealed_key():
            return False
        if self._inner is None:
            take = self._signature_length - len(self._signature)
            self._signature += data[:take]
            data = data[take:]
            if len(self._signature) < self._signature_length:
                return True
            if not self._verify_signature():
                return False
        if not len(data):
            return True
        if not self._inner.update(data):
            return self._fail(self._inner.error)
        return True

    def _on_content(self, data: bytes) -> bool:
        if self._failed:
            return False
        if len(data) > self._content_size - self._content_written:
            return self._fail("the file is larger than its sealed size")
        self._hash.update(data)
        self._content_written += len(data)
        if self._sink is not None and not self._sink(data):
            return self._fail("the decrypted file could not be stored")
        return True


# --------------------------------------------------------------------------
# Whole-buffer helpers (zk1_reference.py), used by tests and integrations
# --------------------------------------------------------------------------

def open_delivery(client_secret: bytes, header_value: str, body: bytes,
                  *, expected_kind: Optional[str] = None) -> Tuple[str, str, bytes]:
    """(kind, object id, payload) of a layer-3 delivery."""
    server_public, kind, object_id = parse_delivery_header(header_value)
    if expected_kind and kind != expected_kind:
        raise Zk1Error("unexpected delivery kind")
    key = delivery_key(client_secret, server_public, kind, object_id)
    return kind, object_id, stream_decrypt(key, body, DELIVERY_MAGIC)


def split_file_delivery(payload: bytes) -> Tuple[bytes, bytes, bytes]:
    """(sealed SDK copy, signature block, stored stream) of a file/folder delivery payload."""
    payload = bytes(payload)
    if len(payload) < 2:
        raise Zk1Error("delivery too short")
    size = struct.unpack(">H", payload[:2])[0]
    if size != SEALED_FILE_KEY_BYTES or len(payload) < 2 + size + 2:
        raise Zk1Error("invalid sealed key in delivery")
    sealed, rest = payload[2:2 + size], payload[2 + size:]
    sig_len = struct.unpack(">H", rest[:2])[0]
    if len(rest) < 2 + sig_len:
        raise Zk1Error("invalid signature block in delivery")
    return sealed, rest[2:2 + sig_len], rest[2 + sig_len:]


def sdk_unseal_file_key(app_secret: bytes, sealed: bytes, kind: str, name: str,
                        product_id: str) -> Tuple[bytes, str]:
    """(payload, scope): product scope first, then the general scope ""."""
    try:
        return unseal(app_secret, sealed, seal_context(kind, name, product_id)), product_id
    except Zk1Error:
        if not product_id:
            raise
    return unseal(app_secret, sealed, seal_context(kind, name, "")), ""


def sdk_open_file(key: Union[ContentKey, str], app_id: str, kind: str, name: str, product_id: str,
                  sealed: bytes, signature: bytes, blob: bytes) -> Tuple[bytes, int]:
    """Unseal (product scope, then general), verify the owner-approved
    signature, decrypt, check size and SHA-256. Returns (plaintext, signedAtMs)."""
    key = _as_content_key(key)
    payload, scope = sdk_unseal_file_key(key.sdk_secret, sealed, kind, name, product_id)
    file_key, digest, size = parse_file_key_payload(payload)
    khash = keyed_hash(key.hash_key, digest)
    block = verify_signature_block(signature, app_id, key.sign_public,
                                   lambda at: upload_message(app_id, kind, scope, name, khash, size, at))
    data = stream_decrypt(file_key, blob, STORED_MAGIC)
    if len(data) != size or not hmac.compare_digest(hashlib.sha256(data).digest(), digest):
        raise Zk1Error("file does not match its sealed hash")
    return data, block.signed_at_ms


def sdk_open_variable(key: Union[ContentKey, str], app_id: str, product_id: str, name: str,
                      sealed: bytes, signature: bytes) -> str:
    """Unseal a variable value and verify its signature (variable message)."""
    key = _as_content_key(key)
    data = unseal(key.sdk_secret, sealed, seal_context("var", name, product_id))
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Zk1Error("the value is not valid UTF-8") from exc
    khash = keyed_hash(key.hash_key, hashlib.sha256(data).digest())
    verify_signature_block(signature, app_id, key.sign_public,
                           lambda at: variable_message(app_id, product_id, name, khash, at))
    return value


def _reject_constant(name: str):
    raise ValueError(f"invalid JSON constant {name}")


_VAR_FIELDS = ("name", "enc", "value", "sig")


def _variable_pairs(pairs):
    seen = set()
    for field, _ in pairs:
        if field in _VAR_FIELDS:
            if field in seen:
                raise ValueError("duplicate field")
            seen.add(field)
    return dict(pairs)


def open_variables(payload: Union[bytes, str], key: Optional[ContentKey], app_id: str,
                   product_id: str) -> List[Tuple[str, str]]:
    """The JSON of a "vars" delivery -> [(name, value)]. zk1 values are opened
    with key and product_id and their signature blocks verified for app_id;
    plain values pass through. Any failure raises Zk1Error and returns nothing."""
    try:
        text = payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else payload
        items = json.loads(text, object_pairs_hook=_variable_pairs, parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Zk1Error("invalid variables payload") from exc
    if not isinstance(items, list):
        raise Zk1Error("invalid variables payload")
    result: List[Tuple[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            raise Zk1Error("invalid variables payload")
        for field in _VAR_FIELDS:
            value = item.get(field)
            if field in item and not isinstance(value, str) and (value is not None or field == "name"):
                raise Zk1Error("invalid variables payload")
            if isinstance(value, str):
                try:
                    _utf8(value)  # lone surrogates from \u escapes are not text
                except Zk1Error as exc:
                    raise Zk1Error("invalid variables payload") from exc
        if "name" not in item:
            raise Zk1Error("a variable has no name")
        name = item["name"]
        enc, value, sig = item.get("enc"), item.get("value"), item.get("sig")
        if enc is None:
            result.append((name, value if value is not None else ""))
            continue
        if enc != "zk1":
            raise Zk1Error(f"variable '{name}' uses an unknown encoding")
        if key is None:
            raise Zk1Error(NEED_CONTENT_KEY)
        try:
            sealed = b64u_decode(value, MAX_SEALED_BYTES) if value is not None else b""
            plain = unseal(key.sdk_secret, sealed, seal_context("var", name, product_id))
            text_value = plain.decode("utf-8")
        except (Zk1Error, UnicodeDecodeError) as exc:
            raise Zk1Error(f"cannot open variable '{name}' (wrong content key, or it was sealed for "
                           f"another name or product)") from exc
        try:
            block = b64u_decode(sig, MAX_SIGNATURE_BLOCK_BYTES) if sig is not None else None
        except Zk1Error:
            block = None
        if block is None:
            raise Zk1Error(f"variable '{name}' has no valid signature block")
        khash = keyed_hash(key.hash_key, hashlib.sha256(plain).digest())
        try:
            verify_signature_block(block, app_id, key.sign_public,
                                   lambda at: variable_message(app_id, product_id, name, khash, at))
        except Zk1Error as exc:
            raise Zk1Error(f"variable '{name}': signature check failed: {exc}") from exc
        result.append((name, text_value))
    return result
