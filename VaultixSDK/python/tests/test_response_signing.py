"""Response signature verification against the golden vectors shared by the
backend and the C++ SDK (backend/tests/response_signing_golden.json; a public
TEST key, never trusted by the SDK itself)."""

import hashlib

from vaultix import response_signing as rs

KEY_ID = "vx-sig-93a08c6579dcf5bd"
PUBLIC_HEX = "3446279cd5e1d6e691c3e35db837c803c6272056951e15c280e531bd167d26a8"
GOLDEN = [
    {
        "nonce": "3f9a1c0e5b7d2468ace013579bdf2468", "signed_at": 1790000000, "method": "GET",
        "path_and_query": "/api/files/download/Tools%20Valuables.json?productId=74d8b072-46fe-4c29-a53d-3f2aabfff895",
        "status": 200, "body_hex": "676f6c64656e20626f647900ff0a", "encryption_key": "enc_key_golden_0123",
        "encryption_iv": "iv_golden_4567", "content_type": "application/octet-stream",
        "body_sha256": "36f190070daa04fa3aa09be9810680c694ba0a3e890a9b85d89aa5508041e2e5",
        "canonical": "vaultix-resp-v1\nvx-sig-93a08c6579dcf5bd\n3f9a1c0e5b7d2468ace013579bdf2468\n1790000000\nGET\n"
                     "/api/files/download/Tools%20Valuables.json?productId=74d8b072-46fe-4c29-a53d-3f2aabfff895\n200\n"
                     "36f190070daa04fa3aa09be9810680c694ba0a3e890a9b85d89aa5508041e2e5\nenc_key_golden_0123\n"
                     "iv_golden_4567\napplication/octet-stream",
        "signature": "G9b5q6DWTEGobUM4ftkx1kMqj3usucWwsIg8JwtJUbCvv6WJzX_XwAgc3_pI4h0oWd2qbI-GAgWMMDR2QWRxAQ",
    },
    {
        "nonce": "Zm9vYmFyX2Jhei1xdXV4LTEyMzQ1Ng", "signed_at": 1790000123, "method": "POST",
        "path_and_query": "/api/app_auth/login_key", "status": 401,
        "body_hex": "7b2264657461696c223a22496e76616c6964206b6579227d", "encryption_key": "", "encryption_iv": "",
        "content_type": "application/json",
        "body_sha256": "53c4c95ff90d3fb42ad4f6e9f732a95d1100c6682367ee3674ae74f98badb28d",
        "canonical": "vaultix-resp-v1\nvx-sig-93a08c6579dcf5bd\nZm9vYmFyX2Jhei1xdXV4LTEyMzQ1Ng\n1790000123\nPOST\n"
                     "/api/app_auth/login_key\n401\n53c4c95ff90d3fb42ad4f6e9f732a95d1100c6682367ee3674ae74f98badb28d\n\n\n"
                     "application/json",
        "signature": "OZNc9qnVt_KQLcJ7RX8nJoKrhriV35RJA5SCZgbiIbE8MtvRRbGC2kp4OiB4tVqexQjomnalqZEfGPxDioGcDA",
    },
]
TRUSTED = {KEY_ID: PUBLIC_HEX}


def _headers(v, **override):
    headers = {"x-vaultix-signature": v["signature"], "x-vaultix-key-id": KEY_ID,
               "x-vaultix-signed-at": str(v["signed_at"]), "x-encryption-key": v["encryption_key"],
               "x-encryption-iv": v["encryption_iv"], "content-type": v["content_type"]}
    headers.update(override)
    return {k: val.encode() for k, val in headers.items() if val is not None}


def _verify(v, *, headers=None, now=None, trusted=TRUSTED, **fields):
    args = dict(method=v["method"], path_and_query=v["path_and_query"], status=v["status"],
                body_hash=hashlib.sha256(bytes.fromhex(v["body_hex"])).hexdigest(), nonce=v["nonce"])
    args.update(fields)
    return rs.verify(headers=_headers(v) if headers is None else headers, trusted=trusted,
                     now=v["signed_at"] if now is None else now, **args)


def test_key_id_and_canonical_match_golden():
    assert rs.key_id_for(bytes.fromhex(PUBLIC_HEX)) == KEY_ID
    for v in GOLDEN:
        assert hashlib.sha256(bytes.fromhex(v["body_hex"])).hexdigest() == v["body_sha256"]
        canonical = rs.canonical(KEY_ID, v["nonce"], v["signed_at"], v["method"], v["path_and_query"], v["status"],
                                 v["body_sha256"], v["encryption_key"], v["encryption_iv"], v["content_type"])
        assert canonical == v["canonical"].encode()


def test_golden_signatures_verify():
    for v in GOLDEN:
        assert _verify(v) == (True, "")


def test_every_covered_field_is_checked():
    for v in GOLDEN:
        for change in (dict(method="PUT"), dict(path_and_query=v["path_and_query"] + "x"), dict(status=500),
                       dict(body_hash=hashlib.sha256(b"other").hexdigest()), dict(nonce=v["nonce"][::-1]),
                       dict(body_hash="zk1-stream")):
            ok, reason = _verify(v, **change)
            assert not ok and reason.startswith("invalid signature"), change
        for header in ("x-encryption-key", "x-encryption-iv", "content-type"):
            ok, reason = _verify(v, headers=_headers(v, **{header: "changed"}))
            assert not ok and reason.startswith("invalid signature"), header


def test_refusals():
    v = GOLDEN[0]
    assert _verify(v, headers=_headers(v, **{"x-vaultix-signature": None})) == (False, "the response is not signed")
    assert _verify(v, trusted={}) == (False, f"unknown signing key '{KEY_ID}'")
    ok, reason = _verify(v, headers=_headers(v, **{"x-vaultix-key-id": "vx-sig-\n<evil>"}))
    assert not ok and reason == "unknown signing key 'vx-sig-??evil?'"
    for bad_time in ("-1", "1790000000.5", "1" * 13, " 1790000000", "1790000000x"):
        assert _verify(v, headers=_headers(v, **{"x-vaultix-signed-at": bad_time})) == (False, "invalid signing time")
    ok, reason = _verify(v, now=v["signed_at"] + 601)
    assert not ok and "differs from this computer's clock by 601 seconds" in reason
    assert _verify(v, now=v["signed_at"] - 600) == (True, "")
    assert rs.verify(method="GET", path_and_query="/", status=200, body_hash="x", headers=_headers(v), nonce="n",
                     trusted=TRUSTED, clock_skew_seconds=10, now=v["signed_at"] + 11)[0] is False
    for bad_sig in (v["signature"] + "A", v["signature"][:-1], v["signature"].replace("_", "/"), v["signature"] + "="):
        ok, reason = _verify(v, headers=_headers(v, **{"x-vaultix-signature": bad_sig}))
        assert not ok, bad_sig
    assert rs.canonical("k", "n\n", 1, "GET", "/", 200, "h") is None


def test_production_key_list():
    for key_id, public_hex in rs.TRUSTED_RESPONSE_KEYS.items():
        assert rs.key_id_for(bytes.fromhex(public_hex)) == key_id
    assert rs.TRUSTED_RESPONSE_KEYS == {
        "vx-sig-22545e6918734982": "c21b9ba40714e61eaaf8529941400264996decd9fb8480121d3e4c7533cf2d8c"}


def test_path_and_query():
    assert rs.path_and_query_from_url("https://vaultix.cc/api/files/download/a%20b?productId=p") == \
        "/api/files/download/a%20b?productId=p"
    assert rs.path_and_query_from_url("https://vaultix.cc/api/me") == "/api/me"
    assert rs.path_and_query_from_url("https://vaultix.cc/api/me?") == "/api/me"
    assert rs.path_and_query_from_url("http://127.0.0.1:5098") == "/"
