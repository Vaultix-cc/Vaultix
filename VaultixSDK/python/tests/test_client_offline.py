"""VaultixClient against a fake backend (tests/zk1_server.FakeVaultix): the
request flow, response verification, zk1 downloads, variables and hash checks,
without a network. The fake signs with its own key, trusted through the
client's testing hook."""

import asyncio
import hashlib
import io
import zipfile

import pytest

from vaultix import NEED_CONTENT_KEY, SyncVaultixClient, VaultixClient, zk1
from zk1_server import FakeVaultix, SampleApp, pattern

PRODUCT = "prod-1"


def make(tmp_path, *, content_key=True, login=True):
    app = SampleApp()
    server = FakeVaultix(app, PRODUCT)
    client = SyncVaultixClient("https://vaultix.test/api")
    client._transport = server
    client._persistent_token_dir = tmp_path / "tokens"
    assert client.testing_set_extra_response_key(server.key_id, server.public_key.hex())
    if content_key:
        assert client.set_content_key(app.sdk_key)
    client.set_api_key("ap_test")
    if login:
        assert client.authenticate_with_key("KEY-1"), client.get_last_error()
    return app, server, client


def test_login_sends_api_key_and_nonce_and_drops_api_key(tmp_path):
    app, server, client = make(tmp_path)
    request = server.requests[-1]
    assert request["url"] == "https://vaultix.test/api/app_auth/login_key"
    assert request["headers"]["X-API-Key"] == "ap_test"
    assert len(request["headers"]["X-Vaultix-Nonce"]) == 48
    session = client.get_current_session()
    assert session.is_valid and session.app_id == app.app_id and session.app_user.subscriptions == [PRODUCT]
    assert client._api_key is None and session.app_api_key == "ap_test"
    assert client.has_product_access(PRODUCT)


def test_content_key_api():
    app = SampleApp()
    client = VaultixClient()
    assert not client.has_content_key() and client.get_content_key_fingerprint() == ""
    assert client.set_content_key(app.sdk_key)
    fingerprint = client.get_content_key_fingerprint()
    assert fingerprint == zk1.fingerprint(app.sdk_public, app.sign_public) and len(fingerprint) == 19
    assert not client.set_content_key(app.sdk_key[:-1])  # invalid: the old key stays
    assert client.get_last_error().startswith("Invalid content key")
    assert client.has_content_key() and client.get_content_key_fingerprint() == fingerprint
    client.clear_content_key()
    assert not client.has_content_key()


def test_testing_hook_validates_the_key():
    client = VaultixClient()
    public = bytes.fromhex("8a781c8e59ff5b6fcb11345e070ab62a76edc1803e42231faeebd9c6253ff0dd")
    assert not client.testing_set_extra_response_key("vx-sig-0000000000000000", public.hex())
    assert not client.testing_set_extra_response_key("vx-sig-22545e6918734982", public.hex())
    assert client.testing_set_extra_response_key("vx-sig-ecc0f0aeb1047e3e", public.hex())
    assert client.testing_set_extra_response_key(None, None) and client._extra_response_key is None


def test_zk1_file_to_memory_and_disk(tmp_path):
    app, server, client = make(tmp_path)
    data = pattern(3 * zk1.CHUNK_SIZE + 123, 4)
    server.add_zk1("file", PRODUCT, "game.dll", data, signed_at_ms=1_760_000_000_777)
    assert client.download_file_to_memory(PRODUCT, "game.dll") == data
    assert client.get_last_error() == "" and client.get_last_signed_at() == 1_760_000_000_777
    request = server.requests[-1]
    assert request["url"] == f"https://vaultix.test/api/files/download/game.dll?productId={PRODUCT}"
    assert request["headers"]["Authorization"] == "Bearer token-1"
    first_eph = request["headers"]["X-Vaultix-Eph"]
    out = tmp_path / "out" / "game.dll"
    assert client.download_file(PRODUCT, "game.dll", str(out)), client.get_last_error()
    assert out.read_bytes() == data and not (tmp_path / "out" / "game.dll.vxpart").exists()
    assert server.requests[-1]["headers"]["X-Vaultix-Eph"] != first_eph  # a new one-time key per request
    chunks = []
    assert client.stream_file(PRODUCT, "game.dll", lambda c, r, t: chunks.append((len(c), r, t)))
    assert sum(n for n, _, _ in chunks) == len(data) and chunks[-1][1:] == (len(data), len(data))


def test_general_file_and_empty_file(tmp_path):
    app, server, client = make(tmp_path)
    server.add_zk1("file", "", "shared.bin", b"")
    assert client.download_file_to_memory(PRODUCT, "shared.bin") == b"" and client.get_last_error() == ""
    assert client.get_last_signed_at() > 0


def test_zk1_failures_release_nothing(tmp_path):
    app, server, client = make(tmp_path)
    data = pattern(2 * zk1.CHUNK_SIZE + 5, 1)
    server.add_zk1("file", PRODUCT, "game.dll", data)
    out = tmp_path / "game.dll"
    out.write_bytes(b"previous version")

    def expect_failure(message_part):
        assert client.download_file_to_memory(PRODUCT, "game.dll") == b""
        assert message_part in client.get_last_error()
        assert client.get_last_signed_at() == 0
        assert not client.download_file(PRODUCT, "game.dll", str(out))
        assert message_part in client.get_last_error()
        assert out.read_bytes() == b"previous version" and not (tmp_path / "game.dll.vxpart").exists()

    # content changed after signing (re-encrypted by a server with valid layer 3)
    def swap_last_byte(payload):
        return payload[:-1] + bytes([payload[-1] ^ 1])
    server.tamper_payload = swap_last_byte
    expect_failure("End-to-end encrypted download failed: chunk 2 failed authentication")
    # another file's key and signature (wrong name)
    other = SampleApp(app.app_id)
    sealed, block, blob = other.upload("file", PRODUCT, "game.dll", data)
    server.tamper_payload = None
    server.files[("file", "game.dll")].update(sealed=sealed, block=block, blob=blob)
    expect_failure("cannot open the sealed file key")
    # signed by a member the owner never approved
    sealed, block, blob = app.upload("file", PRODUCT, "game.dll", data, signer=other.member)
    server.files[("file", "game.dll")].update(sealed=sealed, block=block, blob=blob)
    expect_failure("signature check failed: the signer is not approved by the app owner")
    # no content key
    server.add_zk1("file", PRODUCT, "game.dll", data)
    client.clear_content_key()
    expect_failure(NEED_CONTENT_KEY)
    # a wrong content key
    assert client.set_content_key(SampleApp().sdk_key)
    expect_failure("cannot open the sealed file key (wrong content key")


def test_response_verification_refusals(tmp_path):
    app, server, client = make(tmp_path)
    server.add_zk1("file", PRODUCT, "game.dll", b"payload")
    server.add_variable("motd", "hi")
    for setting, expected in ((dict(sign=False), "the response is not signed"),
                              (dict(replay_nonce="0" * 48), "invalid signature"),
                              (dict(redirects=1), "the request was redirected"),
                              (dict(clock_offset=3600), "the signature time differs from this computer's clock")):
        for name, value in setting.items():
            setattr(server, name, value)
        assert client.download_file_to_memory(PRODUCT, "game.dll") == b""
        assert client.get_last_error().startswith("Server response could not be verified (HTTP 200): " + expected)
        assert client.get_product_variables(PRODUCT) == {}
        assert expected in client.get_last_error()
        assert client.get_file_info(PRODUCT, "game.dll") is None and expected in client.get_last_error()
        server.sign, server.replay_nonce, server.redirects, server.clock_offset = True, None, 0, 0
    # a fresh client without the testing hook trusts only the production key
    plain = SyncVaultixClient("https://vaultix.test/api")
    plain._transport = server
    plain.set_api_key("ap_test")
    assert not plain.authenticate_with_key("KEY-1")
    assert plain.get_last_error() == (f"Server response could not be verified (HTTP 200): unknown signing key "
                                      f"'{server.key_id}'")
    # clock tolerance
    server.clock_offset = 3600
    client.set_response_clock_skew_tolerance(7200)
    assert client.download_file_to_memory(PRODUCT, "game.dll") == b"payload"


def test_deliveries_are_verified_even_with_signed_responses_off(tmp_path):
    app, server, client = make(tmp_path)
    server.add_zk1("file", PRODUCT, "game.dll", b"payload")
    server.add_legacy("file", "old.bin", b"legacy payload")
    client.set_require_signed_responses(False)
    server.sign = False
    assert client.download_file_to_memory(PRODUCT, "old.bin") == b"legacy payload"
    assert client.download_file_to_memory(PRODUCT, "game.dll") == b""
    assert "the response is not signed" in client.get_last_error()


def test_folder_to_memory_and_disk(tmp_path):
    app, server, client = make(tmp_path)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("bin/app.exe", pattern(3000))
        zf.writestr("readme.txt", "hello")
    server.add_zk1("folder", PRODUCT, "Tools", archive.getvalue(), record_id="folder-1")
    data = client.download_folder_to_memory(PRODUCT, "Tools")
    assert data == archive.getvalue() and client.get_last_signed_at() > 0
    assert client.download_folder(PRODUCT, "Tools", str(tmp_path / "Tools.zip"))
    with zipfile.ZipFile(tmp_path / "Tools.zip") as zf:
        assert zf.read("readme.txt") == b"hello"
    assert client.download_folder_to_memory(PRODUCT, "Missing") == b""
    assert "Folder not found" in client.get_last_error()


def test_variables(tmp_path):
    app, server, client = make(tmp_path)
    server.add_variable("motd", "Hello from E2EE")
    server.add_variable("plain", "visible", zk1_value=False)
    assert client.get_product_variables(PRODUCT) == {"motd": "Hello from E2EE", "plain": "visible"}
    request = server.requests[-1]
    assert request["url"] == f"https://vaultix.test/api/apps/{app.app_id}/products/{PRODUCT}/variables"
    assert "X-Vaultix-Eph" in request["headers"]
    # one bad signature: no values at all
    sealed, block = SampleApp(app.app_id).variable(PRODUCT, "evil", "x")
    server.variables.append({"id": "v9", "name": "evil", "enc": "zk1", "value": zk1.b64u_encode(sealed),
                             "sig": zk1.b64u_encode(block)})
    assert client.get_product_variables(PRODUCT) == {}
    assert "cannot open variable 'evil'" in client.get_last_error()
    server.variables.pop()
    client.clear_content_key()
    assert client.get_product_variables(PRODUCT) == {} and client.get_last_error() == NEED_CONTENT_KEY
    # apps without end-to-end encryption: plain values pass through
    server.e2ee_app = False
    server.variables = [v for v in server.variables if v["enc"] is None]
    assert client.get_product_variables(PRODUCT) == {"plain": "visible"}


def test_is_valid_file_hash_rules(tmp_path):
    app, server, client = make(tmp_path)
    data = b"zk1 content"
    server.add_zk1("file", PRODUCT, "game.dll", data)
    server.add_legacy("file", "old.bin", b"legacy content")
    local = tmp_path / "local.bin"
    local.write_bytes(data)
    assert client.is_valid_file_hash(PRODUCT, "game.dll", str(local))
    sent = server.requests[-1]["body"]
    assert b"keyedHash" in sent and hashlib.sha256(data).hexdigest().encode() not in sent
    local.write_bytes(data + b"!")
    assert not client.is_valid_file_hash(PRODUCT, "game.dll", str(local))
    # legacy file: keyed hash first, then the plain SHA-256 once
    local.write_bytes(b"legacy content")
    assert client.is_valid_file_hash(PRODUCT, "old.bin", str(local))
    assert b'"hash"' in server.requests[-1]["body"] and b"keyedHash" in server.requests[-2]["body"]
    # a server asking for the plain hash of a file received as verified zk1: refused
    assert client.download_file_to_memory(PRODUCT, "game.dll") == data
    server.hash_answer = {"valid": False, "code": "plain_hash_required"}
    local.write_bytes(data)
    count = len(server.requests)
    assert not client.is_valid_file_hash(PRODUCT, "game.dll", str(local))
    assert client.get_last_error() == "verify-hash: the server asked for the plain hash of an end-to-end encrypted file"
    assert len(server.requests) == count + 1
    # without a content key: the plain hash
    server.hash_answer = None
    client.clear_content_key()
    local.write_bytes(b"legacy content")
    assert client.is_valid_file_hash(PRODUCT, "old.bin", str(local))
    assert not client.is_valid_file_hash(PRODUCT, "missing.bin", str(tmp_path / "nope"))
    assert client.get_last_error().startswith("Failed to open file")


def test_legacy_download_and_missing_key(tmp_path):
    app, server, client = make(tmp_path, content_key=False)
    server.add_legacy("file", "old.bin", pattern(5000))
    assert client.download_file_to_memory(PRODUCT, "old.bin") == pattern(5000)
    assert client.get_last_signed_at() == 0
    assert client.download_file(PRODUCT, "old.bin", str(tmp_path / "old.bin"))
    assert (tmp_path / "old.bin").read_bytes() == pattern(5000)
    blob = server.files[("file", "old.bin")]["blob"]
    assert VaultixClient.decrypt_data(blob, "enc_key_test_0123") == pattern(5000)
    with pytest.raises(ValueError):
        VaultixClient.decrypt_data(blob, "wrong key")


def test_sdk_update_required_message(tmp_path):
    app, server, client = make(tmp_path, content_key=False)
    server.add_zk1("file", PRODUCT, "game.dll", b"x")
    original = server.__call__

    def strip_eph(method, url, headers, body):  # a proxy dropping X-Vaultix-Eph
        headers = {k: v for k, v in headers.items() if k != "X-Vaultix-Eph"}
        return original(method, url, headers, body)
    client._transport = strip_eph
    assert client.download_file_to_memory(PRODUCT, "game.dll") == b""
    assert client.get_last_error() == NEED_CONTENT_KEY
    assert client.set_content_key(app.sdk_key)
    assert client.download_file_to_memory(PRODUCT, "game.dll") == b""
    assert "e2ee_sdk_update_required" in client.get_last_error()


def test_no_session_and_auto_login(tmp_path):
    app, server, client = make(tmp_path, login=False)
    assert client.download_file_to_memory(PRODUCT, "x") == b"" and client.get_last_error() == "No valid session"
    assert not client.try_auto_login() and client.get_last_error() == "No saved token found"
    client._save_persistent_token("persist-1", "ap_test")
    assert client.try_auto_login(), client.get_last_error()
    assert b'"token": "persist-1"' in server.requests[-1]["body"]
    client.end_session()
    assert not client.is_session_valid and server.requests[-1]["url"].endswith("/app_auth/logout")


def test_async_api(tmp_path):
    app = SampleApp()
    server = FakeVaultix(app, PRODUCT)
    server.add_zk1("file", PRODUCT, "game.dll", b"async payload")

    async def run():
        client = VaultixClient("https://vaultix.test/api")
        client._transport = server
        client.testing_set_extra_response_key(server.key_id, server.public_key.hex())
        client.set_content_key(app.sdk_key)
        client.set_api_key("ap_test")
        assert await client.authenticate_with_key("KEY-1")
        data = await client.download_file_to_memory(PRODUCT, "game.dll")
        chunks = []
        assert await client.stream_file(PRODUCT, "game.dll", lambda c, r, t: chunks.append(c))
        return data, b"".join(chunks)

    assert asyncio.run(run()) == (b"async payload", b"async payload")
