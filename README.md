# Vaultix SDKs

Client libraries for [Vaultix](https://vaultix.cc): license keys or accounts, HWID binding, end-to-end encrypted file and folder delivery, product variables, product status and news.

| Language | Folder | Requires |
|---|---|---|
| C++ | [VaultixSDK/cpp](VaultixSDK/cpp/) | C++17, OpenSSL, libcurl, CMake 3.16+ |
| C# | [VaultixSDK/csharp](VaultixSDK/csharp/) | .NET 8 |
| Python | [VaultixSDK/python](VaultixSDK/python/) | Python 3.8+, `cryptography` |
| Java | [VaultixSDK/java](VaultixSDK/java/) | Java 17, Maven |

All four SDKs (version 2.0.0) open end-to-end encrypted files, folders and variables, verify every server response and keep working with apps that don't use end-to-end encryption. The C++ SDK is the one the Vaultix dashboard offers for download. The SDKs are not published to NuGet, PyPI or Maven; build them from this repository.

## What every SDK does

- **End-to-end encrypted downloads.** New Vaultix apps are end-to-end encrypted. With your app's `vxk_` content key (App Settings -> End-to-end encryption) the SDK opens files, folders and variables, but only after the uploader's signature, the size and the SHA-256 check out. Every download uses a new one-time X25519 key and is decrypted while it streams; files on disk appear only after every check passed.
- **Signed responses.** Vaultix signs every response with Ed25519 over a per-request nonce, the request, the status and the body. The SDKs check it with the Vaultix public key built in, so a fake server, proxy or replayed response is refused.
- **Keyed file hashes.** The hash check compares `HMAC(hashKey, SHA-256(file))`, so Vaultix never learns your files' checksums.
- **Signing time.** After a download you can read when the file was signed, and refuse older versions if your app needs to. Rollbacks in the dashboard are signed again with a new time.

**C++ only for now:** approved-build checks and the integrity heartbeat (Safety). Apps that turn them on need the C++ SDK.

How the encryption works: [vaultix.cc/docs/encryption](https://vaultix.cc/docs/encryption)

## Quick start

### C++

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

### C#

```csharp
using Vaultix.SDK;

using var client = new VaultixClient("https://vaultix.cc/api");
client.SetApiKey("ap_your_app_key");                    // App Settings -> App API key
if (!client.SetContentKey("vxk_your_sdk_key_here"))     // App Settings -> End-to-end encryption
{
    Console.Error.WriteLine(client.GetLastError());
    return;
}

if (!await client.AuthenticateWithKeyAsync("YOURAPP-XXXX-XXXX-XXXX-XXXX"))
{
    Console.Error.WriteLine(client.GetLastError());
    return;
}

// Verified and decrypted in memory; null on any failure.
byte[]? payload = await client.DownloadFileToMemoryAsync("product_id", "game.dll");
if (payload == null)
{
    Console.Error.WriteLine(client.GetLastError());
    return;
}

foreach (var (name, value) in await client.GetProductVariablesAsync("product_id"))
{
    Console.WriteLine($"{name} = {value}");
}

await client.EndSessionAsync();
```

### Python

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

### Java

```java
import com.vaultix.sdk.VaultixClient;
import java.util.Map;

public class Launcher {
    public static void main(String[] args) throws Exception {
        try (VaultixClient client = new VaultixClient("https://vaultix.cc/api")) {
            client.setApiKey("ap_your_app_key");                  // App Settings -> App API key
            if (!client.setContentKey("vxk_your_sdk_key")) {       // App Settings -> End-to-end encryption
                System.err.println("Invalid content key");
                return;
            }

            if (!client.authenticateWithKey("YOURAPP-XXXX-XXXX-XXXX-XXXX")) {
                System.err.println(client.getLastError());
                return;
            }

            // Verified and decrypted in memory; an empty array on any failure.
            byte[] payload = client.downloadFileToMemory("product_id", "game.dll");
            if (!client.getLastError().isEmpty()) {
                System.err.println(client.getLastError());
                return;
            }

            for (Map.Entry<String, String> variable : client.getProductVariables("product_id").entrySet()) {
                System.out.println(variable.getKey() + " = " + variable.getValue());
            }

            client.endSession();
        }
    }
}
```

Each folder's README has the full API, build steps, tests and examples.

## Build

```bash
# C++
cd VaultixSDK/cpp && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

# C#
cd VaultixSDK/csharp && dotnet build -c Release

# Python
cd VaultixSDK/python && pip install .

# Java
cd VaultixSDK/java && mvn package
```

## Good to know

- Listing files and folders (`GetFileList`, `GetFolderList` and their equivalents) currently returns an empty list for app users; download by name instead.
- Every folder has examples for signing in, files and folders, subscriptions, product information, auto-login and a complete app.

## Links

[Documentation](https://vaultix.cc/docs) · [C++ client docs](https://vaultix.cc/docs/cpp-client) · [REST API](https://vaultix.cc/docs/api-overview) · [Changelog](https://vaultix.cc/changelog) · support@vaultix.cc
