# Vaultix Python SDK

The Python client library for [Vaultix](https://vaultix.cc): license keys or accounts, end-to-end encrypted file and folder delivery, product variables, product status and news.

- **End-to-end encrypted downloads.** Files, folders and variables of end-to-end encrypted apps are opened only with your `vxk_` content key, after the uploader's signature, size and SHA-256 check out. Every download uses a new one-time X25519 key; files are decrypted while they stream and never land at their final path unverified.
- **Signed responses.** Vaultix signs every response with Ed25519 over a per-request nonce, the request, the status, the body hash and the encryption headers. The SDK checks it with the public key built into `vaultix/response_signing.py`, so a fake server, proxy or replayed response can't answer "login OK" or hand out files.
- **Apps without end-to-end encryption** keep working with the same calls.

How the encryption works: [vaultix.cc/docs/encryption](https://vaultix.cc/docs/encryption)

## Requirements

- Python 3.8 or newer
- [`cryptography`](https://pypi.org/project/cryptography/) 3.4 or newer (installed with the SDK). HTTP uses the standard library.

## Install from source

The SDK is not published on PyPI. Install it from a copy of this repository:

```bash
git clone https://github.com/Vaultix-cc/Vaultix.git
cd Vaultix/VaultixSDK/python
pip install .
```

To ship it with your app instead, build a wheel (`pip wheel . --no-deps -w dist`) or copy the `vaultix/` folder into your project and install `cryptography`.

## Quick start

```python
import asyncio
from vaultix import VaultixClient

async def main():
    client = VaultixClient("https://vaultix.cc/api")
    client.set_api_key("ap_your_app_api_key")               # App Settings -> App API key
    if not client.set_content_key("vxk_your_sdk_key_here"):  # App Settings -> End-to-end encryption
        raise SystemExit("Invalid content key")

    if not await client.authenticate_with_key("YOURAPP-XXXX-XXXX-XXXX-XXXX"):
        raise SystemExit(client.get_last_error())

    # Verified and decrypted in memory; b"" on any failure.
    payload = await client.download_file_to_memory("product_id", "game.dll")
    if not payload and client.get_last_error():
        raise SystemExit(client.get_last_error())

    for name, value in (await client.get_product_variables("product_id")).items():
        print(name, "=", value)

    client.end_session()

asyncio.run(main())
```

`SyncVaultixClient` has the same calls without `await`:

```python
from vaultix import SyncVaultixClient

client = SyncVaultixClient("https://vaultix.cc/api")
client.set_api_key("ap_your_app_api_key")
client.set_content_key("vxk_your_sdk_key_here")
if client.authenticate_with_key("YOURAPP-XXXX-XXXX-XXXX-XXXX"):
    ok = client.download_file("product_id", "game.dll", "./game.dll")
```

Compare `client.get_content_key_fingerprint()` with the fingerprint shown in App Settings once, to be sure the key belongs to your app.

## API

| Area | Calls |
|---|---|
| **Setup** | `set_api_key`, `set_content_key`, `clear_content_key`, `has_content_key`, `get_content_key_fingerprint` |
| **Sign-in** | `authenticate_with_key`, `authenticate_with_username`, `try_auto_login`, `refresh_token`, `end_session`, `clear_auto_login_token`, `is_session_valid`, `is_token_expired`, `get_current_session` |
| **Files** | `get_file_info`, `download_file`, `download_file_to_memory`, `stream_file`, `is_valid_file_hash`, `get_last_signed_at`, `get_file_list` |
| **Folders** | `get_folder_info`, `download_folder`, `download_folder_to_memory`, `get_folder_list` |
| **Product** | `get_product_variables`, `get_product_status`, `get_product_news`, `has_product_access`, `get_user_products`, `get_user_subscription_by_product`, `get_account_info` |
| **Security** | `set_require_signed_responses` (on by default), `set_response_clock_skew_tolerance`, `enable_certificate_pinning`, `set_min_tls_version`, `enable_request_signing`, `ssl_verify` |
| **Diagnostics** | `get_last_error`, `debug_mode` (debug output never shows credentials, keys or request bodies) |
| **Older downloads** | `decrypt_file`, `decrypt_data` (the download format of apps without end-to-end encryption) |

Calls that talk to the server are coroutines on `VaultixClient` and plain methods on `SyncVaultixClient`. `end_session` and `clear_auto_login_token` are plain methods on both (each sends at most one short request).

### Downloads

- `download_file` / `download_folder` write end-to-end encrypted content to `<output_path>.vxpart` and rename it only after every check passed. On any failure they return `False`, delete the partial file and leave an existing file at `output_path` as it was. Missing parent directories are created.
- `download_file_to_memory` / `download_folder_to_memory` return `b""` on any failure; on success `get_last_error()` is `""`, so an empty file is not an error.
- `stream_file` downloads and verifies the whole file first, then calls `progress_callback(chunk, received, total)` with 4 KB chunks.
- `get_last_signed_at()` returns the signing time (Unix ms) of the last verified end-to-end encrypted download, `0` otherwise. Vaultix cannot fake content, but keep the newest value per file if your app must refuse older versions. Rolling a file back in the dashboard signs it again with a new time, so rollbacks pass this check.
- `is_valid_file_hash` compares a keyed hash (`HMAC(hashKey, SHA-256(file))`) when a content key is set, so Vaultix never learns your files' checksums. Files of apps without end-to-end encryption are then checked once more with the plain SHA-256, except files this client already received as verified end-to-end encrypted downloads (then the result is `False`).
- Without a content key, an end-to-end encrypted download fails with: `This app uses end-to-end encryption: call set_content_key with the vxk_ key from App Settings`. Other failures start with `End-to-end encrypted download failed:` and name the check that failed.

### Response verification

- Every request carries a fresh random `X-Vaultix-Nonce`. A response that is unsigned, signed by an unknown key, altered, answers another request, came through a redirect, or was signed more than 10 minutes away from this computer's clock is refused; `get_last_error()` then starts with `Server response could not be verified`.
- `set_response_clock_skew_tolerance(seconds)` changes the 10-minute window (600 seconds).
- `set_require_signed_responses(False)` is only for local testing against your own server; never ship it. End-to-end encrypted deliveries are verified even then.
- `testing_set_extra_response_key(key_id, public_key_hex)` trusts one extra response key, for SDK tests against a test backend. Never ship an app that calls it.

### Apps without end-to-end encryption

Apps created before end-to-end encryption keep working with the same calls; their downloads arrive AES-256-GCM encrypted, with the key in a signed response header. Turn encryption on in App Settings after your users have a build with `set_content_key`.

## Limitations

- **C++ only:** approved-build checks and the Safety heartbeat (tamper protection). Signing in to an app that requires them fails with the server's error.
- `get_file_list` and `get_folder_list` return an empty list for app users: the Vaultix API lists files and folders only for dashboard sessions (`get_last_error()` holds the HTTP error). Use `get_file_info` / `get_folder_info` with a known name.
- `get_product_variables` returns a dict, so of two variables with the same name only the last one is kept.
- `download_file_to_memory`, `download_folder_to_memory` and `stream_file` hold the whole file in memory. Files of apps without end-to-end encryption are also decrypted in memory by `download_file` and `download_folder`.
- Python cannot reliably erase secrets: the content key and decrypted data stay in process memory until they are garbage collected.
- The hardware ID sent at sign-in is a SHA-256 of the computer's network name, not the C++ SDK's hardware ID.
- The auto-login token is saved in `~/.vaultix/` (obfuscated, not encrypted).
- A client is not thread-safe: use one client per thread, or a lock.

## Examples

| Example | Shows |
|---|---|
| `example_01_basic_auth.py` | Sign in with a key or username and password |
| `example_02_file_operations.py` | Download, stream and verify files, download folders |
| `example_03_subscription.py` | Subscriptions and product access |
| `example_04_product_info.py` | Variables, product status and news |
| `example_05_auto_login.py` | Staying signed in across restarts |
| `example_06_complete_app.py` | A small launcher putting it all together |

Replace the placeholder keys and IDs at the top of each example with your own, then run it, for example `python examples/example_02_file_operations.py` (the examples import the SDK from this folder).

## Tests

```bash
pip install pytest
python -m pytest tests
```

- `tests/test_response_signing.py`, `tests/test_client_offline.py` and `tests/test_zk1_vectors.py` run offline.
- `tests/test_zk1_vectors.py` checks the encryption byte for byte against the shared zk1 test vectors in `tests/vectors/zk1.json` (`VAULTIX_ZK1_VECTORS` points to another copy).
- `tests/test_integration_backend.py` runs against a Vaultix test backend described by the JSON file in `VAULTIX_SDK_FIXTURE`, and is skipped without it.

## Links

[How the encryption works](https://vaultix.cc/docs/encryption) · [REST API](https://vaultix.cc/docs/api-overview) · support@vaultix.cc
