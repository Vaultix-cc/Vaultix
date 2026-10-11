# Vaultix Java SDK

The Java client library for [Vaultix](https://vaultix.cc): license keys or accounts, HWID binding, end-to-end encrypted file, folder and variable delivery, product status and news. Version 2.0.0 uses the same API endpoints as the C++ SDK, including end-to-end encrypted downloads and response verification.

- **End-to-end encrypted downloads.** Files, folders and variables of end-to-end encrypted apps are opened only with your `vxk_` content key, after the uploader's signature, size and SHA-256 check out. Every download uses a new one-time X25519 key; content is decrypted while it streams, and files written to disk stay in `<path>.vxpart` until every check passed.
- **Signed responses.** Vaultix signs every response with Ed25519 over a per-request nonce, the request, the status, the body hash and the encryption headers. The SDK checks it with the public key built into `ResponseSigning.java`, so a fake server, proxy or replayed response can't answer "login OK" or hand out files.
- **Few dependencies.** HTTP (`java.net.http`) and all cryptography (X25519, Ed25519, AES-256-GCM, HMAC-SHA256, SHA-256) come from the JDK; HKDF is implemented in the SDK. The only runtime dependency is Gson.

How the encryption works: [vaultix.cc/docs/encryption](https://vaultix.cc/docs/encryption)

## Requirements

- JDK 17 or newer
- Maven (tested with Maven 3.9 and Eclipse Temurin 17)

## Build from source

The SDK is not published to Maven Central or any other package registry. Build it from this folder:

```bash
cd VaultixSDK/java
mvn package        # target/vaultix-sdk-2.0.0.jar (runs the unit tests)
mvn install        # also copies it into your local Maven repository (~/.m2)
```

After `mvn install`, other Maven projects on the same machine can use it:

```xml
<dependency>
    <groupId>com.vaultix</groupId>
    <artifactId>vaultix-sdk</artifactId>
    <version>2.0.0</version>
</dependency>
```

Without Maven, put `target/vaultix-sdk-2.0.0.jar` and Gson 2.10.1 on your classpath.

## Quick start

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

Compare `client.getContentKeyFingerprint()` with the fingerprint shown in App Settings once, to be sure the key belongs to your app.

## API

| Area | Methods |
|---|---|
| **Setup** | `setApiKey`, `clearApiKey`, `setContentKey`, `clearContentKey`, `hasContentKey`, `getContentKeyFingerprint` |
| **Sign-in** | `authenticateWithKey`, `authenticateWithUsername`, `tryAutoLogin`, `refreshToken`, `endSession`, `clearAutoLoginToken`, `isSessionValid`, `isTokenExpired`, `getCurrentSession` |
| **Files** | `getFileInfo`, `downloadFile`, `downloadFileToMemory`, `streamFile`, `isValidFileHash`, `getLastSignedAt`, `getFileList` |
| **Folders** | `getFolderInfo`, `downloadFolder`, `downloadFolderToMemory`, `getFolderList` |
| **Product** | `getProductVariables`, `getProductStatus`, `getProductNews`, `hasProductAccess`, `getUserProducts`, `getUserSubscriptionByProduct`, `getAccountInfo` |
| **Security** | `setRequireSignedResponses` (on by default), `setResponseClockSkewTolerance`, `enableCertificatePinning`, `disableCertificatePinning`, `setMinTlsVersion`, `setSslVerify`, `enableRequestSigning`, `disableRequestSigning`, `setTestingExtraResponseKey` (tests only) |
| **Diagnostics** | `getLastError`, `setDebugMode` (debug output never shows credentials, keys, tokens or request bodies) |

`com.vaultix.sdk.Zk1` holds the end-to-end encryption format (keys, sealed keys, signature blocks, streams, deliveries). The client uses it internally; you only need it to decrypt content yourself.

### Downloads

- `downloadFile` and `downloadFolder` write end-to-end encrypted content to `<outputPath>.vxpart` and rename it only after every check passed; on failure the `.vxpart` file is deleted and an existing file at `outputPath` stays as it was. Missing parent directories are created.
- `downloadFileToMemory` and `downloadFolderToMemory` return an empty array on any failure. On success `getLastError()` is `""`, so an empty file is not an error.
- `streamFile` downloads and verifies the whole file first, then passes it to your callback in 4 KB chunks.
- `getLastSignedAt()` returns the signing time (Unix ms) of the last verified end-to-end encrypted download, `0` otherwise. Vaultix cannot fake content, but keep the newest value per file if your app must refuse older versions.
- `isValidFileHash` sends a keyed hash (`HMAC(hashKey, SHA-256(file))`) when a content key is set, so Vaultix never learns your files' checksums. Files of apps without end-to-end encryption are then checked once more with the plain SHA-256, except files this client already received as verified end-to-end encrypted files.
- `getProductVariables` returns the variables in server order. End-to-end encrypted values must open with the content key and carry a valid signature; if any value fails, the map is empty and `getLastError()` says why.

Typical errors:

| `getLastError()` starts with | Meaning |
|---|---|
| `Server response could not be verified` | The response signature is missing, unknown, invalid, or too far from this computer's clock (default tolerance 600 s). |
| `This app uses end-to-end encryption: call setContentKey` | The app is end-to-end encrypted and no content key is set. |
| `End-to-end encrypted download failed:` | Wrong content key, wrong name or product, a bad signature, or damaged or incomplete content. Nothing was returned or saved. |

### Apps without end-to-end encryption

Apps created before end-to-end encryption keep working with the same calls; their downloads arrive AES-256-GCM encrypted, with the key in a signed response header. A content key is not needed for them. Turn encryption on in App Settings after your users have a build that calls `setContentKey`.

### Testing against your own backend

`setTestingExtraResponseKey(keyId, publicKeyHex)` trusts one extra response-signing key, for a Vaultix test backend that signs with its own key. Never call it in a build you ship. `setRequireSignedResponses(false)` is for local testing only; end-to-end encrypted downloads are verified even then.

## Changes from 1.x

- Uses the API endpoints of the C++ SDK; adds end-to-end encrypted downloads and response verification.
- `downloadFileToMemory` returns an empty array instead of `null` on failure.
- Requires JDK 17 (was 11). Apache HttpClient and SLF4J are no longer dependencies.
- New: `setContentKey` and related methods, `getLastSignedAt`, `streamFile`, `getFolderInfo`, `downloadFolderToMemory`, `getAccountInfo`, `setRequireSignedResponses`, `setResponseClockSkewTolerance`.
- Auto-login tokens are stored per app API key in `~/.vaultix/autologin-<id>.dat`.

## Limitations

- **C++ only:** approved-build checks and the Safety heartbeat. Apps with Safety turned on refuse sign-ins from this SDK ("Safety client attestation is required").
- `getFileList` and `getFolderList` call the same endpoints as the C++ SDK. For app user sessions the current backend answers them with HTTP 401, so they return an empty list with `getLastError()` set. Use `getFileInfo` and `getFolderInfo` with a known name.
- Like the C++ SDK, the client accepts a response in the format of apps without end-to-end encryption for any app; such a response is still signed by Vaultix.
- The SDK wipes the byte arrays it owns (content key, file keys, buffers). Java cannot reliably wipe `String`s (such as the `vxk_` key you pass in) or key objects inside the JDK.
- The `*ToMemory` methods and `streamFile` hold the whole file in memory (at most about 2 GB per array).
- A `VaultixClient` is not thread-safe: use one per thread or synchronize calls yourself.
- `setSslVerify(false)` turns off certificate and host name checks; use it only for local testing.

## Examples

`src/main/java/com/vaultix/examples`:

| Example | Shows |
|---|---|
| `Example01_BasicAuth` | Sign in with a key or username and password |
| `Example02_FileOperations` | Download, stream and verify files and folders |
| `Example03_Subscription` | Subscriptions and product access |
| `Example04_ProductInfo` | Variables, product status and news |
| `Example05_AutoLogin` | Staying signed in across restarts |
| `Example06_CompleteApp` | A small launcher putting it all together |

Replace the placeholder keys, IDs and names at the top of each example with your own.

## Tests

```bash
mvn test
```

The unit tests need no network: they check the cryptography against the shared vectors (`src/test/resources/vectors/zk1.json`, or another copy with `-Dvaultix.vectors=PATH`), the response signature against its golden vector, and the client against a local mock server. The integration test runs only when `-Dvaultix.fixture=PATH` points to a fixture file describing a running Vaultix test backend.

## Links

[End-to-end encryption](https://vaultix.cc/docs/encryption) · [REST API](https://vaultix.cc/docs/api-overview) · [Changelog](https://vaultix.cc/changelog) · support@vaultix.cc
