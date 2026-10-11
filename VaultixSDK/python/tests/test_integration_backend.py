"""Integration test against a running Vaultix test backend.

Skipped unless VAULTIX_SDK_FIXTURE points to a fixture JSON:

    {"baseUrl": "http://127.0.0.1:5098/api",
     "testResponseKey": {"keyId": "vx-sig-...", "publicKeyHex": "..."},
     "e2ee":   {"apiKey", "licenseKey", "productId", "contentKey", "wrongContentKey",
                "file": {"name", "sha256"}, "folder": {"name", "zipEntries": [...]},
                "variable": {"name", "value"}},
     "legacy": {"apiKey", "licenseKey", "productId", "file": {"name", "sha256", "size"}}}

The backend signs responses with the test key, which the client trusts only
through its testing hook. Read-only: logs in, downloads, verifies hashes.
"""

import copy
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import pytest

from vaultix import NEED_CONTENT_KEY, SyncVaultixClient
from vaultix._transport import UrllibTransport

FIXTURE = os.environ.get("VAULTIX_SDK_FIXTURE", "")
pytestmark = pytest.mark.skipif(not FIXTURE or not Path(FIXTURE).is_file(),
                                reason="set VAULTIX_SDK_FIXTURE to a test backend fixture")

UNVERIFIED = "Server response could not be verified (HTTP 200): "


@pytest.fixture(scope="module")
def fx():
    return json.loads(Path(FIXTURE).read_text())


def new_client(fx, app="e2ee", *, hook=True, content_key=True, login=True):
    client = SyncVaultixClient(fx["baseUrl"])
    if hook:
        key = fx["testResponseKey"]
        assert client.testing_set_extra_response_key(key["keyId"], key["publicKeyHex"])
    if content_key:
        assert client.set_content_key(fx["e2ee"]["contentKey"])
    client.set_api_key(fx[app]["apiKey"])
    if login:
        assert client.authenticate_with_key(fx[app]["licenseKey"]), client.get_last_error()
    return client


class Recorder:
    """The real transport, recording the request headers."""

    def __init__(self):
        self.headers = []

    def __call__(self, method, url, headers, body):
        self.headers.append(dict(headers))
        return UrllibTransport()(method, url, headers, body)


@pytest.fixture(scope="module")
def client(fx):
    client = new_client(fx)
    yield client
    client.end_session()


@pytest.fixture
def restore_key(client, fx):
    yield
    assert client.set_content_key(fx["e2ee"]["contentKey"])


def test_key_login(client, fx):
    session = client.get_current_session()
    assert client.is_session_valid and session.session_token and session.app_id
    assert fx["e2ee"]["productId"] in session.app_user.subscriptions
    assert client.get_content_key_fingerprint().count("-") == 3


def test_zk1_file_download_twice(client, fx):
    product, file = fx["e2ee"]["productId"], fx["e2ee"]["file"]
    recorder = Recorder()
    client._transport = recorder
    try:
        first = client.download_file_to_memory(product, file["name"])
        assert client.get_last_error() == "" and hashlib.sha256(first).hexdigest() == file["sha256"]
        signed_at = client.get_last_signed_at()
        assert signed_at > 0
        second = client.download_file_to_memory(product, file["name"])
        assert client.get_last_error() == "" and second == first and client.get_last_signed_at() == signed_at
    finally:
        client._transport = None
    ephs = [h["X-Vaultix-Eph"] for h in recorder.headers]
    nonces = [h["X-Vaultix-Nonce"] for h in recorder.headers]
    assert len(ephs) == 2 and ephs[0] != ephs[1] and nonces[0] != nonces[1]


def test_zk1_file_to_disk(client, fx, tmp_path):
    product, file = fx["e2ee"]["productId"], fx["e2ee"]["file"]
    out = tmp_path / "sub" / file["name"]
    assert client.download_file(product, file["name"], str(out)), client.get_last_error()
    assert hashlib.sha256(out.read_bytes()).hexdigest() == file["sha256"]
    assert not Path(str(out) + ".vxpart").exists()
    assert sorted(p.name for p in out.parent.iterdir()) == [file["name"]]
    assert client.get_last_signed_at() > 0


def _check_zip(fx, data):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for entry in fx["e2ee"]["folder"]["zipEntries"]:
            content = zf.read(entry["path"])
            assert len(content) == entry["size"]
            if "content" in entry:
                assert content.decode() == entry["content"]


def test_folder_download(client, fx, tmp_path):
    product, folder = fx["e2ee"]["productId"], fx["e2ee"]["folder"]["name"]
    data = client.download_folder_to_memory(product, folder)
    assert data and client.get_last_error() == "", client.get_last_error()
    assert client.get_last_signed_at() > 0
    _check_zip(fx, data)
    entries = {e["path"]: e for e in fx["e2ee"]["folder"]["zipEntries"]}
    assert entries["bin/app.exe"]["size"] == 3000 and entries["readme.txt"]["content"] == "hello"
    out = tmp_path / f"{folder}.zip"
    assert client.download_folder(product, folder, str(out)), client.get_last_error()
    assert out.read_bytes() == data and not Path(str(out) + ".vxpart").exists()


def test_variables(client, fx):
    variables = client.get_product_variables(fx["e2ee"]["productId"])
    assert client.get_last_error() == ""
    assert variables[fx["e2ee"]["variable"]["name"]] == fx["e2ee"]["variable"]["value"] == "Hello from E2EE"


def test_is_valid_file_hash(client, fx, tmp_path):
    product, file = fx["e2ee"]["productId"], fx["e2ee"]["file"]
    data = client.download_file_to_memory(product, file["name"])
    local = tmp_path / "local.bin"
    local.write_bytes(data)
    assert client.is_valid_file_hash(product, file["name"], str(local)), client.get_last_error()
    local.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    assert not client.is_valid_file_hash(product, file["name"], str(local))
    assert client.get_last_error() == ""  # a valid "no" from the server


def test_without_content_key_fails_clearly(client, fx, tmp_path, restore_key):
    product, file = fx["e2ee"]["productId"], fx["e2ee"]["file"]
    client.clear_content_key()
    assert client.download_file_to_memory(product, file["name"]) == b""
    assert client.get_last_error() == NEED_CONTENT_KEY
    assert client.get_last_signed_at() == 0
    out = tmp_path / "f.bin"
    assert not client.download_file(product, file["name"], str(out))
    assert client.get_last_error() == NEED_CONTENT_KEY and list(tmp_path.iterdir()) == []
    assert client.download_folder_to_memory(product, fx["e2ee"]["folder"]["name"]) == b""
    assert client.get_last_error() == NEED_CONTENT_KEY
    assert client.get_product_variables(product) == {} and client.get_last_error() == NEED_CONTENT_KEY


def test_wrong_content_key_fails(client, fx, tmp_path, restore_key):
    product, file = fx["e2ee"]["productId"], fx["e2ee"]["file"]
    assert client.set_content_key(fx["e2ee"]["wrongContentKey"])
    assert client.download_file_to_memory(product, file["name"]) == b""
    assert client.get_last_error().startswith("End-to-end encrypted download failed: cannot open the sealed file key")
    out = tmp_path / "f.bin"
    assert not client.download_file(product, file["name"], str(out)) and list(tmp_path.iterdir()) == []
    assert client.get_product_variables(product) == {}
    assert "cannot open variable" in client.get_last_error()


def test_legacy_app(fx, tmp_path):
    legacy = fx["legacy"]
    client = new_client(fx, "legacy", content_key=False)
    try:
        data = client.download_file_to_memory(legacy["productId"], legacy["file"]["name"])
        assert client.get_last_error() == ""
        assert len(data) == legacy["file"]["size"] and hashlib.sha256(data).hexdigest() == legacy["file"]["sha256"]
        assert client.get_last_signed_at() == 0
        out = tmp_path / legacy["file"]["name"]
        assert client.download_file(legacy["productId"], legacy["file"]["name"], str(out))
        assert out.read_bytes() == data
        assert client.is_valid_file_hash(legacy["productId"], legacy["file"]["name"], str(out))
        # with a content key: keyed hash first, then the plain SHA-256 (not a zk1 file)
        assert client.set_content_key(fx["e2ee"]["contentKey"])
        assert client.is_valid_file_hash(legacy["productId"], legacy["file"]["name"], str(out))
        out.write_bytes(data + b"x")
        assert not client.is_valid_file_hash(legacy["productId"], legacy["file"]["name"], str(out))
    finally:
        client.end_session()


def test_without_testing_hook_every_call_is_refused(client, fx, tmp_path):
    key_id = fx["testResponseKey"]["keyId"]
    expected = f"{UNVERIFIED}unknown signing key '{key_id}'"
    plain = new_client(fx, hook=False, login=False)
    assert not plain.authenticate_with_key(fx["e2ee"]["licenseKey"])
    assert plain.get_last_error() == expected and not plain.is_session_valid
    # even with a valid session borrowed from the verified client
    plain._current_session = copy.deepcopy(client.get_current_session())
    product, file = fx["e2ee"]["productId"], fx["e2ee"]["file"]
    assert plain.download_file_to_memory(product, file["name"]) == b"" and plain.get_last_error() == expected
    assert not plain.download_file(product, file["name"], str(tmp_path / "x")) and list(tmp_path.iterdir()) == []
    assert plain.get_product_variables(product) == {} and plain.get_last_error() == expected
    assert plain.download_folder_to_memory(product, fx["e2ee"]["folder"]["name"]) == b""
    assert plain.get_last_error() == expected
    assert plain.get_file_info(product, file["name"]) is None and plain.get_last_error() == expected
    (tmp_path / "local.bin").write_bytes(b"x")
    assert not plain.is_valid_file_hash(product, file["name"], str(tmp_path / "local.bin"))
    assert plain.get_last_error() == expected
    assert plain.get_account_info() is None and plain.get_last_error() == expected
