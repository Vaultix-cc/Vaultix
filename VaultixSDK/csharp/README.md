# Vaultix C# SDK

The C# client library for [Vaultix](https://vaultix.cc): license keys or accounts, auto-login, end-to-end encrypted file, folder and variable delivery, product status and news.

- **End-to-end encrypted downloads.** Files, folders and variables of end-to-end encrypted apps are opened only with your `vxk_` content key, after the uploader's signature, size and SHA-256 check out. Every download uses a new one-time X25519 key and is decrypted while it streams; a file on disk is renamed into place only after every check passed.
- **Signed responses.** Vaultix signs every response with Ed25519 over a per-request nonce, the request, the status, the body hash and the encryption headers. The SDK checks it with the public key built into the SDK (the same key as the C++ SDK), so a fake server, proxy or replayed response can't answer "login OK" or hand out files.
- **Apps without end-to-end encryption** keep working with the same calls.

How the encryption works: [vaultix.cc/docs/encryption](https://vaultix.cc/docs/encryption)

## Requirements

- .NET 8 (`net8.0`)
- NuGet packages, restored automatically: `BouncyCastle.Cryptography` 2.5.1 (X25519, Ed25519) and `Newtonsoft.Json` 13.0.3
- A platform where `System.Security.Cryptography.AesGcm` is supported (AES-256-GCM). The tests run on Linux.

## Build from source

The SDK is not published on NuGet. Build it from this repository:

```bash
git clone https://github.com/Vaultix-cc/Vaultix.git
cd Vaultix/VaultixSDK/csharp
dotnet build -c Release
```

Then reference the project from your app's `.csproj`:

```xml
<ItemGroup>
  <ProjectReference Include="path/to/Vaultix/VaultixSDK/csharp/VaultixSDK.csproj" />
</ItemGroup>
```

Or reference `bin/Release/net8.0/VaultixSDK.dll` and add the two packages above to your project.

## Quick start

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

Compare `client.GetContentKeyFingerprint()` with the fingerprint shown in App Settings once, to be sure the key belongs to your app. The decoded key is kept in memory only and zeroed when it is replaced, cleared or the client is disposed.

## API

| Area | Members |
|---|---|
| **Setup** | `SetApiKey`, `ClearApiKey`, `SetContentKey`, `ClearContentKey`, `HasContentKey`, `GetContentKeyFingerprint` |
| **Sign-in** | `AuthenticateWithKeyAsync`, `AuthenticateWithUsernameAsync`, `TryAutoLoginAsync`, `RefreshTokenAsync`, `EndSession` / `EndSessionAsync`, `ClearAutoLoginToken` / `ClearAutoLoginTokenAsync`, `IsSessionValid`, `IsTokenExpiredAsync`, `GetCurrentSession` |
| **Files** | `GetFileListAsync`, `GetFileInfoAsync`, `DownloadFileAsync`, `DownloadFileToMemoryAsync`, `StreamFileAsync`, `IsValidFileHashAsync`, `GetLastSignedAt` |
| **Folders** | `GetFolderListAsync`, `GetFolderInfoAsync`, `DownloadFolderAsync`, `DownloadFolderToMemoryAsync` |
| **Product** | `GetProductVariablesAsync`, `GetProductStatusAsync`, `GetProductNewsAsync`, `HasProductAccess`, `GetUserProductsAsync`, `GetUserSubscriptionByProductAsync`, `GetAccountInfoAsync` |
| **Security** | `SetRequireSignedResponses` / `RequireSignedResponses` (on by default), `SetResponseClockSkewTolerance`, `EnableCertificatePinning`, `SetMinTlsVersion`, `SslVerify`, `EnableRequestSigning` |
| **Other** | `DecryptData`, `DecryptFileAsync`, `GetLastError`, `DebugMode` (debug output never shows credentials, keys or request bodies) |

### Downloads

- `DownloadFileAsync` / `DownloadFolderAsync` write to `<outputPath>.vxpart` and rename it only after every check passed; on failure nothing is left behind. The `*ToMemoryAsync` methods return `null` on any failure; on success `GetLastError()` is empty, so an empty file is an empty array, not an error.
- An end-to-end encrypted file must carry a signature of a team member the app owner approved (checked with the signing key in your content key), covering this app, the name, the product (or the general file of that name), the size and the keyed hash. The content is then checked against the sealed size and SHA-256.
- Without a content key, or with the key of another app, downloads of an end-to-end encrypted app fail with a clear `GetLastError()` message.
- `StreamFileAsync` downloads and verifies the whole file first, then hands it to your callback in 4 KiB chunks, so the callback never sees unverified data.
- `GetLastSignedAt()` returns the signing time (Unix ms) of the last verified end-to-end encrypted download, 0 otherwise. Vaultix cannot fake content, but keep the newest value per file if your app must refuse older versions.
- `IsValidFileHashAsync` with a content key sends a keyed hash (`HMAC(hashKey, SHA-256(file))`), so Vaultix never learns your files' checksums. For a file of an app without end-to-end encryption it then checks once more with the plain SHA-256, except for a file this client already received as a verified end-to-end encrypted download.
- `GetProductVariablesAsync` returns an empty dictionary if any encrypted value cannot be opened or verified.

### Response verification

Every request carries a fresh random `X-Vaultix-Nonce`, and every response must carry a valid Vaultix signature over it. A response that fails the check makes the call fail; `GetLastError()` then starts with `Server response could not be verified`. End-to-end encrypted deliveries are always verified, also with `SetRequireSignedResponses(false)`. Turn the check off only for local testing against your own test server.

`SetResponseClockSkewTolerance(seconds)` sets the allowed difference between the computer's clock and the signing time (default 600 seconds).

`TrustResponseKeyForTestingOnly(keyId, publicKeyHex)` trusts one extra signing key, for a test backend that signs with its own key. Never call it in a build you ship.

### Apps without end-to-end encryption

Apps created before end-to-end encryption keep working with the same calls; their downloads arrive AES-256-GCM encrypted, with the key in a signed response header, and the SDK decrypts them. `DecryptData` / `DecryptFileAsync` decrypt that format directly (the IV is embedded in the data). Turn encryption on in App Settings after your users have a build that calls `SetContentKey`.

## Limitations

- **C++ only:** approved-build checks (Safety) and the integrity heartbeat. An app with Safety turned on refuses this SDK's login ("Safety client attestation is required"); use the C++ SDK for such apps.
- `GetFileListAsync` and `GetFolderListAsync`: the current Vaultix API answers these requests from app users with HTTP 401, so they return an empty list (the C++ SDK returns an empty list as well). Downloads and info by name work.
- The hardware ID is a SHA-256 of the machine and user name. It differs from the C++ SDK's hardware ID: in an app that binds licenses to the hardware ID, a license first used with a C++ build does not match a C# build on the same device.
- Auto-login tokens are saved obfuscated, not encrypted, in the user's application data folder (one file per app).
- `FolderInfo.TotalSize` is approximate: the server sends a formatted size such as "2.5 MB".
- The client is not thread-safe. Use one instance per thread, or a lock.

## Upgrading from 1.0.0

- Targets `net8.0` and needs the `BouncyCastle.Cryptography` package.
- Uses the current Vaultix API endpoints and checks every response signature.
- `DecryptData` / `DecryptFileAsync` now decrypt the Vaultix AES-256-GCM download format; the `iv` argument is ignored.
- New: `SetContentKey` and the other content key members, `GetLastSignedAt`, `DownloadFolderToMemoryAsync`, `GetFolderInfoAsync`, `GetAccountInfoAsync`, `EndSessionAsync`, `ClearAutoLoginTokenAsync` and the response verification settings.

## Examples

| Example | Shows |
|---|---|
| `Example01_BasicAuth.cs` | Sign in with a key or username and password |
| `Example02_FileOperations.cs` | File info, downloads, streaming, hash check and folders |
| `Example03_Subscription.cs` | Subscriptions and product access |
| `Example04_ProductInfo.cs` | Variables, product status and news |
| `Example05_AutoLogin.cs` | Staying signed in across restarts |
| `Example06_CompleteApp.cs` | A small launcher putting it all together |

Replace the placeholder keys and IDs at the top of each example with your own, then run one:

```bash
dotnet run --project examples -- 2
```

## Tests

```bash
# Unit and local mock-server tests, with the zk1 known-answer vectors in
# tests/VaultixSDK.Tests/vectors/zk1.json (VAULTIX_ZK1_VECTORS=/path/to/zk1.json uses another copy)
dotnet test tests/VaultixSDK.Tests

# Integration tests against a running Vaultix test backend (skipped without a fixture file)
VAULTIX_SDK_FIXTURE=/path/to/sdk-fixture.json dotnet test tests/VaultixSDK.Tests
```

## Links

[Documentation](https://vaultix.cc/docs) · [REST API](https://vaultix.cc/docs/api-overview) · [Changelog](https://vaultix.cc/changelog) · support@vaultix.cc
