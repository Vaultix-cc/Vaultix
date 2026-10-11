"""HTTP transport of the Vaultix Python SDK (standard library urllib).

A transport is a callable (method, url, headers, body) -> RawResponse. The
client replaces it only in tests; it never changes what is verified.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ssl
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization

DEFAULT_TIMEOUT_SECONDS = 30


class RawResponse:
    """Status, headers in the order received, a readable body, and how many
    redirects were followed to get it."""

    def __init__(self, status: int, headers: List[Tuple[str, str]], stream, redirects: int = 0):
        self.status = status
        self.headers = headers
        self._stream = stream
        self.redirects = redirects

    def read(self, size: int = -1) -> bytes:
        if self._stream is None:
            return b""
        return self._stream.read(size) if size >= 0 else self._stream.read()

    def close(self) -> None:
        if self._stream is not None:
            try:
                self._stream.close()
            except Exception:
                pass
            self._stream = None


class _CountingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            self.count += 1
        return new


class CertificatePinError(ssl.SSLError):
    pass


def spki_sha256(der_certificate: bytes) -> bytes:
    """SHA-256 of the certificate's DER SubjectPublicKeyInfo (the C++ SDK's pin)."""
    public_key = x509.load_der_x509_certificate(der_certificate).public_key()
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).digest()


def _pin_matches(digest: bytes, pins: Sequence[str]) -> bool:
    hex_digest = digest.hex()
    b64_digest = base64.b64encode(digest).decode("ascii")
    for pin in pins:
        pin = pin.strip()
        if pin.lower() == hex_digest or pin == "sha256/" + b64_digest:
            return True
    return False


def _pinned_connection_class(pins: Sequence[str]):
    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            super().connect()
            der = self.sock.getpeercert(binary_form=True)
            if not der or not _pin_matches(spki_sha256(der), pins):
                self.sock.close()
                raise CertificatePinError("Certificate pinning failed - no matching certificate found")

    return PinnedHTTPSConnection


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, pins: Sequence[str]):
        super().__init__(context=context)
        self._context_for_pins = context
        self._connection_class = _pinned_connection_class(list(pins))

    def https_open(self, req):
        return self.do_open(self._connection_class, req, context=self._context_for_pins)


class UrllibTransport:
    """Blocking HTTP(S) with TLS verification, a minimum TLS version, optional
    certificate pinning and a socket timeout. Redirects are followed and
    counted; the client refuses signed responses that came through one."""

    def __init__(self, *, ssl_verify: bool = True, min_tls_version: str = "1.2",
                 pins: Optional[Sequence[str]] = None, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.ssl_verify = ssl_verify
        self.min_tls_version = min_tls_version
        self.pins = list(pins or [])
        self.timeout = timeout

    def _context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if not self.ssl_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_3 if self.min_tls_version == "1.3" else ssl.TLSVersion.TLSv1_2
        return context

    def __call__(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> RawResponse:
        context = self._context()
        redirects = _CountingRedirectHandler()
        https = _PinnedHTTPSHandler(context, self.pins) if self.pins else urllib.request.HTTPSHandler(context=context)
        opener = urllib.request.build_opener(https, redirects)
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            response = opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            # 4xx/5xx still carry a (signed) answer: hand it to the client as is.
            return RawResponse(error.code, list(error.headers.items()) if error.headers else [], error,
                               redirects.count)
        return RawResponse(response.status, list(response.headers.items()), response, redirects.count)
