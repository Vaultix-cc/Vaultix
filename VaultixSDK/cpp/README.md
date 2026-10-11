# Vaultix C++ SDK

The client library for [Vaultix](https://vaultix.cc): license keys or accounts, HWID binding, end-to-end encrypted file and folder delivery, product variables, product status and news. It is the same SDK the Vaultix dashboard offers for download.

- **End-to-end encrypted downloads.** Files, folders and variables of end-to-end encrypted apps are opened only with your `vxk_` content key, after the uploader's signature, size and SHA-256 check out. Every download uses a new one-time X25519 key; content is decrypted while it streams and never lands on disk unverified.
- **Signed responses.** Vaultix signs every response with Ed25519 over a per-request nonce, the request, the status, the body hash and the encryption headers. The SDK checks it with the public key built into `VaultixClient.cpp`, so a fake server, proxy or replayed response can't answer "login OK" or hand out files.
- **Tamper protection.** Approved-build checks and an integrity heartbeat when your app requires them.

How the encryption works: [vaultix.cc/docs/encryption](https://vaultix.cc/docs/encryption)

## Requirements

- C++17
- OpenSSL (libssl, libcrypto) and libcurl
- CMake 3.16+ (or add the two source files to your own build)
- Windows or Linux

```bash
# Debian / Ubuntu
sudo apt-get install g++ cmake libssl-dev libcurl4-openssl-dev

# Windows (vcpkg)
vcpkg install openssl curl
```

## Add it to your project

**CMake, from a copy of this folder:**

```cmake
add_subdirectory(third_party/vaultix-sdk)   # this folder
target_link_libraries(your_app PRIVATE Vaultix::vaultix_sdk)
```

**CMake, straight from GitHub (CMake 3.18+):**

```cmake
include(FetchContent)
FetchContent_Declare(vaultix_sdk
    GIT_REPOSITORY https://github.com/Vaultix-cc/Vaultix.git
    GIT_TAG main
    SOURCE_SUBDIR VaultixSDK/cpp)
FetchContent_MakeAvailable(vaultix_sdk)
target_link_libraries(your_app PRIVATE Vaultix::vaultix_sdk)
```

**Without CMake:** compile `src/VaultixClient.cpp` with `include/` on the include path and link OpenSSL and libcurl (on Windows also `ole32`, `oleaut32`, `wbemuuid`).

Build the examples on their own:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Quick start

```cpp
#include "VaultixClient.h"
#include <iostream>

int main() {
    Vaultix::VaultixClient client("https://vaultix.cc/api");
    client.SetApiKey("ap_your_app_key");                 // App Settings -> App API key
    if (!client.SetContentKey("vxk_your_sdk_key")) {      // App Settings -> End-to-end encryption
        std::cerr << "Invalid content key\n";
        return 1;
    }

    if (!client.AuthenticateWithKey("YOURAPP-XXXX-XXXX-XXXX-XXXX")) {
        std::cerr << client.GetLastError() << "\n";
        return 1;
    }

    // Verified and decrypted in memory; empty on any failure.
    std::vector<uint8_t> payload = client.DownloadFileToMemory("product_id", "game.dll");
    if (payload.empty() && !client.GetLastError().empty()) {
        std::cerr << client.GetLastError() << "\n";
        return 1;
    }

    for (const auto& [name, value] : client.GetProductVariables("product_id")) {
        std::cout << name << " = " << value << "\n";
    }

    client.EndSession();
}
```

Compare `client.GetContentKeyFingerprint()` with the fingerprint shown in App Settings once, to be sure the key belongs to your app.

## API

| Area | Functions |
|---|---|
| **Setup** | `SetApiKey`, `SetContentKey`, `ClearContentKey`, `HasContentKey`, `GetContentKeyFingerprint` |
| **Sign-in** | `AuthenticateWithKey`, `AuthenticateWithUsername`, `TryAutoLogin`, `RefreshToken`, `EndSession`, `ClearAutoLoginToken`, `IsSessionValid`, `IsTokenExpired` |
| **Files** | `GetFileList`, `GetFileInfo`, `DownloadFile`, `DownloadFileToMemory`, `StreamFile`, `IsValidFileHash`, `GetLastSignedAt` |
| **Folders** | `GetFolderList`, `GetFolderInfo`, `DownloadFolder`, `DownloadFolderToMemory` |
| **Product** | `GetProductVariables`, `GetProductStatus`, `GetProductNews`, `HasProductAccess`, `GetUserProducts`, `GetUserSubscriptionByProduct`, `GetAccountInfo` |
| **Security** | `SetRequireSignedResponses` (on by default), `SetResponseClockSkewTolerance`, `EnableCertificatePinning`, `SetMinTlsVersion`, `SetSafetyClientVersion`, `SendSafetyHeartbeat` |
| **Diagnostics** | `GetLastError`, `SetDebugMode` (debug output never shows credentials, keys or request bodies) |

### Downloads

- `DownloadFile` / `DownloadFolder` write to `<outputPath>.vxpart` and rename it only after every check passed. The `*ToMemory` functions return an empty vector on any failure; on success `GetLastError()` is empty, so an empty file is not an error.
- `GetLastSignedAt()` returns the signing time (Unix ms) of the last verified end-to-end encrypted download. Vaultix cannot fake content, but keep the newest value per file if your app must refuse older versions. Rolling a file back in the dashboard signs it again with a new time, so rollbacks pass this check.
- `IsValidFileHash` compares a keyed hash (`HMAC(hashKey, SHA-256(file))`), so Vaultix never learns your files' checksums.

### Apps without end-to-end encryption

Apps created before end-to-end encryption keep working with the same calls; their downloads arrive AES-256-GCM encrypted, with the key in a signed response header. Turn encryption on in App Settings after your users have a build with `SetContentKey`.

## Examples

| Example | Shows |
|---|---|
| `example_01_basic_auth` | Sign in with a key or username and password |
| `example_02_file_operations` | List, download, stream and verify files and folders |
| `example_03_subscription` | Subscriptions and product access |
| `example_04_product_info` | Variables, product status and news |
| `example_05_auto_login` | Staying signed in across restarts |
| `example_06_complete_app` | A small launcher putting it all together |

Replace the placeholder keys and IDs at the top of each example with your own.

## Links

[Documentation](https://vaultix.cc/docs/cpp-client) · [REST API](https://vaultix.cc/docs/api-overview) · [Changelog](https://vaultix.cc/changelog) · support@vaultix.cc
