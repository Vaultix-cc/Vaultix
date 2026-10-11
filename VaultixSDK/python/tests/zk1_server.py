"""Test-only counterpart of the SDK: what the browser (uploads) and the Vaultix
backend (layer-3 deliveries, response signatures) produce. test_zk1_vectors.py
checks these helpers against the shared vectors too, so the offline client
tests below run against byte-exact data."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit, parse_qs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from vaultix import response_signing, zk1
from vaultix._transport import RawResponse


def pattern(length: int, seed: int = 0) -> bytes:
    """Vector plaintext: byte i = (i * 31 + 7 + seed) mod 256."""
    return bytes(((i * 31 + 7 + seed) & 0xFF) for i in range(length))


def ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def seal(app_public: bytes, payload: bytes, context: bytes, eph_secret: Optional[bytes] = None) -> bytes:
    eph_secret = eph_secret or os.urandom(32)
    eph_public = zk1.x25519_public(eph_secret)
    key = zk1.hkdf(zk1.x25519_shared(eph_secret, app_public), eph_public + app_public,
                   b"vaultix-zk1-seal\x00" + context)
    return bytes([1]) + eph_public + AESGCM(key).encrypt(bytes(12), payload, context)


def stream_encrypt(key: bytes, data: bytes, magic: bytes, chunk_size: int = zk1.CHUNK_SIZE,
                   version: int = 1) -> bytes:
    header = magic + bytes([version]) + struct.pack(">I", chunk_size)
    count = max(1, -(-len(data) // chunk_size))
    aead = AESGCM(key)
    out = [header]
    for i in range(count):
        nonce = bytes(7) + struct.pack(">I", i) + (b"\x01" if i == count - 1 else b"\x00")
        out.append(aead.encrypt(nonce, data[i * chunk_size:(i + 1) * chunk_size], header))
    return b"".join(out)


def signature_block(user_id: str, enc_public: bytes, sign_public: bytes, issued_at_ms: int, cert: bytes,
                    signed_at_ms: int, signature: bytes) -> bytes:
    user = user_id.encode("utf-8")
    return (b"\x01" + struct.pack(">H", len(user)) + user + enc_public + sign_public
            + struct.pack(">Q", issued_at_ms) + cert + struct.pack(">Q", signed_at_ms) + signature)


def sdk_key_encode(secret: bytes, sign_public: bytes) -> str:
    body = bytes([2]) + secret + sign_public
    return "vxk_" + zk1.b64u_encode(body + hashlib.sha256(b"vaultix-vxk" + body).digest()[:4])


def delivery(client_public: bytes, kind: str, object_id: str, payload: bytes,
             server_secret: Optional[bytes] = None) -> Tuple[str, bytes]:
    """(X-Encryption-Key value, VXD1 body) of a layer-3 response."""
    server_secret = server_secret or os.urandom(32)
    server_public = zk1.x25519_public(server_secret)
    shared = zk1.x25519_shared(server_secret, client_public)
    info = b"vaultix-zk1-deliver\x00" + kind.encode() + b"\x00" + object_id.encode()
    key = zk1.hkdf(shared, client_public + server_public, info)
    header = f"zk1d.{zk1.b64u_encode(server_public)}.{kind}.{object_id}"
    return header, stream_encrypt(key, payload, zk1.DELIVERY_MAGIC)


def file_payload(sealed: bytes, block: bytes, blob: bytes) -> bytes:
    return struct.pack(">H", len(sealed)) + sealed + struct.pack(">H", len(block)) + block + blob


class Member:
    """A team member approved by the app owner."""

    def __init__(self, app: "SampleApp", user_id: str, issued_at_ms: int = 1_759_100_000_000):
        seed = os.urandom(32)
        self.user_id = user_id
        self.enc_public = zk1.x25519_public(zk1.hkdf(seed, b"vaultix-personal-v1", b"enc"))
        self.sign_seed = zk1.hkdf(seed, b"vaultix-personal-v1", b"sign")
        self.sign_public = ed25519_public(self.sign_seed)
        self.issued_at_ms = issued_at_ms
        self.cert = ed25519_sign(app.sign_seed, zk1.member_message(
            app.app_id, user_id, self.enc_public, self.sign_public, issued_at_ms))

    def block(self, message: bytes, signed_at_ms: int) -> bytes:
        return signature_block(self.user_id, self.enc_public, self.sign_public, self.issued_at_ms, self.cert,
                               signed_at_ms, ed25519_sign(self.sign_seed, message))


class SampleApp:
    """App keys derived like zk1_reference.AppKeys.from_entropy."""

    def __init__(self, app_id: str = "app-1", entropy: Optional[bytes] = None):
        entropy = entropy or os.urandom(32)
        self.app_id = app_id
        self.sdk_secret = zk1.hkdf(entropy, b"vaultix-e2ee-v1", b"app-key")
        self.sdk_public = zk1.x25519_public(self.sdk_secret)
        self.sign_seed = zk1.hkdf(entropy, b"vaultix-e2ee-v1", b"app-sign")
        self.sign_public = ed25519_public(self.sign_seed)
        self.hash_key = zk1.hash_key_from_sdk_secret(self.sdk_secret)
        self.sdk_key = sdk_key_encode(self.sdk_secret, self.sign_public)
        self.member = Member(self, "user-b")

    def upload(self, kind: str, scope: str, name: str, data: bytes, signed_at_ms: int = 1_760_000_000_000,
               signer: Optional[Member] = None) -> Tuple[bytes, bytes, bytes]:
        """(sealed SDK copy, signature block, stored VXZ1 stream)."""
        file_key = os.urandom(32)
        digest = hashlib.sha256(data).digest()
        payload = file_key + digest + struct.pack(">Q", len(data))
        sealed = seal(self.sdk_public, payload, zk1.seal_context(kind, name, scope))
        khash = zk1.keyed_hash(self.hash_key, digest)
        message = zk1.upload_message(self.app_id, kind, scope, name, khash, len(data), signed_at_ms)
        block = (signer or self.member).block(message, signed_at_ms)
        return sealed, block, stream_encrypt(file_key, data, zk1.STORED_MAGIC)

    def variable(self, product_id: str, name: str, value: str, signed_at_ms: int = 1_760_000_100_000,
                 signer: Optional[Member] = None) -> Tuple[bytes, bytes]:
        data = value.encode("utf-8")
        sealed = seal(self.sdk_public, data, zk1.seal_context("var", name, product_id))
        khash = zk1.keyed_hash(self.hash_key, hashlib.sha256(data).digest())
        block = (signer or self.member).block(
            zk1.variable_message(self.app_id, product_id, name, khash, signed_at_ms), signed_at_ms)
        return sealed, block


def legacy_encrypt(data: bytes, key: str) -> bytes:
    salt, iv = os.urandom(16), os.urandom(12)
    derived = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000).derive(key.encode())
    sealed = AESGCM(derived).encrypt(iv, data, None)
    return salt + iv + sealed[-16:] + sealed[:-16]


class _Body:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def read(self, size: int = -1) -> bytes:
        end = len(self.data) if size < 0 else min(len(self.data), self.pos + size)
        out, self.pos = self.data[self.pos:end], end
        return out

    def close(self):
        pass


class FakeVaultix:
    """A transport that answers like the Vaultix backend, signed with a test key."""

    def __init__(self, app: SampleApp, product_id: str = "prod-1"):
        self.app = app
        self.product_id = product_id
        self.signing_seed = os.urandom(32)
        self.public_key = ed25519_public(self.signing_seed)
        self.key_id = response_signing.key_id_for(self.public_key)
        self.files: Dict[Tuple[str, str], dict] = {}
        self.variables: List[dict] = []
        self.e2ee_app = True
        self.requests: List[dict] = []
        # misbehaviour switches
        self.sign = True
        self.replay_nonce: Optional[str] = None
        self.redirects = 0
        self.clock_offset = 0
        self.tamper_payload = None      # callable(bytes) -> bytes on the delivery payload
        self.hash_answer: Optional[dict] = None

    # -- content ----------------------------------------------------------------

    def add_zk1(self, kind: str, scope: str, name: str, data: bytes, record_id: str = "rec-1",
                signed_at_ms: int = 1_760_000_000_000) -> None:
        sealed, block, blob = self.app.upload(kind, scope, name, data, signed_at_ms)
        self.files[(kind, name)] = {"zk1": True, "id": record_id, "sealed": sealed, "block": block, "blob": blob,
                                    "keyed": zk1.keyed_hash(self.app.hash_key, hashlib.sha256(data).digest()).hex()}

    def add_legacy(self, kind: str, name: str, data: bytes, key: str = "enc_key_test_0123") -> None:
        self.files[(kind, name)] = {"zk1": False, "id": "rec-legacy", "key": key, "blob": legacy_encrypt(data, key),
                                    "sha": hashlib.sha256(data).hexdigest()}

    def add_variable(self, name: str, value: str, zk1_value: bool = True) -> None:
        if zk1_value:
            sealed, block = self.app.variable(self.product_id, name, value)
            self.variables.append({"id": f"v{len(self.variables)}", "name": name, "enc": "zk1",
                                   "value": zk1.b64u_encode(sealed), "sig": zk1.b64u_encode(block)})
        else:
            self.variables.append({"id": f"v{len(self.variables)}", "name": name, "enc": None, "value": value,
                                   "sig": None})

    # -- transport --------------------------------------------------------------

    def _respond(self, method: str, url: str, request_headers: Dict[str, str], status: int,
                 headers: List[Tuple[str, str]], body: bytes, streamed: bool = False) -> RawResponse:
        lower = {k.lower(): v for k, v in request_headers.items()}
        nonce = self.replay_nonce or lower.get("x-vaultix-nonce", "")
        if self.sign and nonce:
            signed_at = int(time.time()) + self.clock_offset
            header_map = {k.lower(): v for k, v in headers}
            canonical = response_signing.canonical(
                self.key_id, nonce, signed_at, method, response_signing.path_and_query_from_url(url), status,
                "zk1-stream" if streamed else hashlib.sha256(body).hexdigest(),
                header_map.get("x-encryption-key", ""), header_map.get("x-encryption-iv", ""),
                header_map.get("content-type", ""))
            signature = zk1.b64u_encode(ed25519_sign(self.signing_seed, canonical))
            headers = headers + [("X-Vaultix-Signature", signature), ("X-Vaultix-Key-Id", self.key_id),
                                 ("X-Vaultix-Signed-At", str(signed_at))]
        return RawResponse(status, headers, _Body(body), self.redirects)

    def _json(self, method, url, request_headers, status, value) -> RawResponse:
        return self._respond(method, url, request_headers, status, [("content-type", "application/json")],
                             json.dumps(value).encode())

    def __call__(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> RawResponse:
        self.requests.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        parts = urlsplit(url)
        path = parts.path[len("/api"):] if parts.path.startswith("/api") else parts.path
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        lower = {k.lower(): v for k, v in headers.items()}
        if path in ("/app_auth/login_key", "/app_auth/login", "/app_auth/autologin"):
            return self._json(method, url, headers, 200, {
                "access_token": "token-1", "token_type": "bearer", "appId": self.app.app_id, "appUserId": "user-1",
                "subscriptions": [self.product_id], "expiresAt": "2999-01-01T00:00:00", "sessionId": "session-1"})
        if path == "/app_auth/logout":
            return self._json(method, url, headers, 200, {"message": "Logged out successfully"})
        if path.startswith("/folders/info/"):
            name = unquote(path[len("/folders/info/"):])
            if ("folder", name) not in self.files:
                return self._json(method, url, headers, 404, {"detail": "Folder not found"})
            return self._json(method, url, headers, 200, {"id": "folder-1", "name": name, "appId": self.app.app_id,
                                                          "productId": query.get("productId", ""),
                                                          "totalSize": "1.0 KB", "fileCount": 2})
        for kind, prefix in (("file", "/files/download/"), ("folder", "/folders/download/")):
            if path.startswith(prefix):
                return self._download(method, url, headers, kind, unquote(path[len(prefix):]))
        if path.endswith("/variables"):
            if not self.e2ee_app:
                items = [{"id": v["id"], "name": v["name"], "value": v["value"], "enc": v["enc"]}
                         for v in self.variables]
                return self._json(method, url, headers, 200, items)
            eph = lower.get("x-vaultix-eph")
            if not eph:
                return self._json(method, url, headers, 409, {"detail": "update", "code": "e2ee_sdk_update_required"})
            payload = json.dumps(self.variables, separators=(",", ":")).encode()
            header, data = delivery(zk1.b64u_decode(eph, 32), "vars", self.product_id, payload)
            return self._respond(method, url, headers, 200, [("content-type", "application/octet-stream"),
                                                             ("X-Encryption-Key", header)], data, streamed=True)
        if path == "/files/verify-hash":
            if self.hash_answer is not None:
                return self._json(method, url, headers, 200, self.hash_answer)
            request = json.loads(body)
            record = self.files.get(("file", request["fileName"]))
            if record is None:
                return self._json(method, url, headers, 404, {"detail": "File not found"})
            if record["zk1"]:
                given, stored, code = request.get("keyedHash"), record["keyed"], "keyed_hash_required"
            else:
                given, stored, code = request.get("hash"), record["sha"], "plain_hash_required"
            answer = {"valid": bool(given) and given == stored}
            if not given:
                answer["code"] = code
            return self._json(method, url, headers, 200, answer)
        return self._json(method, url, headers, 404, {"detail": "Not Found"})

    def _download(self, method, url, headers, kind, name) -> RawResponse:
        record = self.files.get((kind, name))
        if record is None:
            return self._json(method, url, headers, 404, {"detail": "File not found"})
        if not record["zk1"]:
            return self._respond(method, url, headers, 200, [
                ("content-type", "application/octet-stream"), ("X-Encryption-Key", record["key"]),
                ("X-Encryption-IV", "legacy-iv")], record["blob"])
        eph = {k.lower(): v for k, v in headers.items()}.get("x-vaultix-eph")
        if not eph:
            return self._json(method, url, headers, 409, {"detail": "update", "code": "e2ee_sdk_update_required"})
        payload = file_payload(record["sealed"], record["block"], record["blob"])
        if self.tamper_payload is not None:
            payload = self.tamper_payload(payload)
        header, data = delivery(zk1.b64u_decode(eph, 32), kind, record["id"], payload)
        return self._respond(method, url, headers, 200, [("content-type", "application/octet-stream"),
                                                         ("X-Encryption-Key", header)], data, streamed=True)
