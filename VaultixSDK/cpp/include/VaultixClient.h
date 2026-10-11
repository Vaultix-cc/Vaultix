#ifndef VAULTIX_CLIENT_H
#define VAULTIX_CLIENT_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>
#include <set>
#include <utility>
#include <cstddef>
#include <cstdint>
#include <curl/curl.h>

// Windows.h defines DecryptFile as a macro, undefine it to avoid conflicts
#ifdef _WIN32
#ifdef DecryptFile
#undef DecryptFile
#endif
#endif

namespace Vaultix {

    // End-to-end encryption ("zk1", docs/E2EE_FORMAT.md). The download
    // functions use this internally; it is declared here so the SDK test
    // binary can check it against the shared vectors. Integrations normally
    // only call VaultixClient::SetContentKey().
    namespace zk1 {
        const size_t kChunkSize = 1048576;        // plaintext bytes per stream chunk
        const size_t kTagBytes = 16;              // AES-GCM tag after every chunk
        const size_t kHeaderBytes = 9;            // magic(4) || version(1) || u32be chunk size
        const size_t kSealedFileKeyBytes = 121;   // 0x01 || eph pk || GCM(fk || sha256 || u64be size)
        const size_t kMaxSealedBytes = 65536;     // a sealed variable value
        const size_t kSdkKeyChars = 96;           // "vxk_" + b64u(0x02 || sk_sdk || aspk || checksum(4))
        const size_t kMaxUserIdBytes = 128;
        const size_t kMinSignatureBlockBytes = 3 + 1 + 208;                 // 1-byte user id
        const size_t kMaxSignatureBlockBytes = 3 + kMaxUserIdBytes + 208;   // 339

        // Receives authenticated plaintext; return false to abort.
        typedef std::function<bool(const uint8_t* data, size_t length)> Sink;

        // What the SDK holds of an app (from its vxk_ key).
        struct ContentKey {
            uint8_t sdkSecret[32];    // sk_sdk: opens the sealed file keys and values
            uint8_t signPublic[32];   // aspk: approves the team members who sign content
            uint8_t hashKey[32];      // kh = HKDF(sk_sdk, "vaultix-e2ee-v1", "hash-key"): keyed hashes
        };
        // Decodes a vxk_ key (version 2 only) and derives kh; false (and a
        // wiped key) for anything else.
        bool ContentKeyFromSdkKey(const std::string& vxk, ContentKey& key);
        void WipeContentKey(ContentKey& key);

        void Wipe(void* data, size_t length);     // OPENSSL_cleanse
        bool X25519Generate(uint8_t secret[32], uint8_t publicKey[32]);
        bool X25519Public(const uint8_t secret[32], uint8_t publicKey[32]);
        // false (and zeroed output) for low-order peers, i.e. an all-zero result
        bool X25519Shared(const uint8_t secret[32], const uint8_t peerPublic[32], uint8_t shared[32]);
        bool HkdfSha256(const uint8_t* ikm, size_t ikmLength, const uint8_t* salt, size_t saltLength,
                        const uint8_t* info, size_t infoLength, uint8_t* out, size_t outLength);
        // in = ciphertext || tag(16); out receives inLength - 16 bytes
        bool AesGcmDecrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aadLength,
                           const uint8_t* in, size_t inLength, uint8_t* out);
        // out receives inLength + 16 bytes (ciphertext || tag)
        bool AesGcmEncrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aadLength,
                           const uint8_t* in, size_t inLength, uint8_t* out);
        bool HmacSha256(const uint8_t* key, size_t keyLength, const uint8_t* data, size_t length, uint8_t out[32]);
        // Ed25519 (RFC 8032) verification of a 64-byte signature.
        bool Ed25519Verify(const uint8_t publicKey[32], const uint8_t* message, size_t messageLength,
                           const uint8_t signature[64]);
        std::string B64uEncode(const uint8_t* data, size_t length);
        bool B64uDecode(const std::string& text, std::vector<uint8_t>& out, size_t maxBytes);
        // "vxk_" key, version 2: checks the version byte and the checksum.
        bool SdkKeyDecode(const std::string& vxk, uint8_t secret[32], uint8_t signPublic[32]);
        bool HashKey(const uint8_t sdkSecret[32], uint8_t hashKey[32]);
        // SHA256("vaultix-fp" || pk_sdk || aspk)[0:8] as "XXXX-XXXX-XXXX-XXXX"
        std::string Fingerprint(const uint8_t sdkPublic[32], const uint8_t signPublic[32]);
        // kind 0x00 scope 0x00 name for "file", "folder", "var"; empty for another kind.
        // scope = the product id, or "" for a general file or folder.
        std::vector<uint8_t> SealContext(const std::string& kind, const std::string& name,
                                         const std::string& productId = "");
        bool Unseal(const uint8_t appSecret[32], const uint8_t* sealed, size_t sealedLength,
                    const std::vector<uint8_t>& context, std::vector<uint8_t>& payload);

        // Signed messages (docs/E2EE_FORMAT.md sections 4 and 5). Empty if a
        // text contains 0x00 or (upload) the kind is not "file" or "folder".
        std::vector<uint8_t> MemberMessage(const std::string& appId, const std::string& userId,
                                           const uint8_t encPublic[32], const uint8_t signPublic[32],
                                           uint64_t issuedAtMs);
        std::vector<uint8_t> UploadMessage(const std::string& appId, const std::string& kind,
                                           const std::string& scope, const std::string& name,
                                           const uint8_t keyedHash[32], uint64_t size, uint64_t signedAtMs);
        std::vector<uint8_t> VariableMessage(const std::string& appId, const std::string& productId,
                                             const std::string& name, const uint8_t keyedHash[32],
                                             uint64_t signedAtMs);

        // 0x01 || u16be(len userId) || userId || upk_enc || upk_sign || u64be(issuedAtMs)
        //      || certSig(64) || u64be(signedAtMs) || sig(64)
        struct SignatureBlock {
            std::string userId;
            uint8_t encPublic[32] = { 0 };
            uint8_t signPublic[32] = { 0 };
            uint64_t issuedAtMs = 0;
            uint8_t certSignature[64] = { 0 };
            uint64_t signedAtMs = 0;
            uint8_t signature[64] = { 0 };
        };
        bool ParseSignatureBlock(const uint8_t* data, size_t length, SignatureBlock& block);
        // The message the signer must have signed, for the block's signedAtMs.
        typedef std::function<std::vector<uint8_t>(uint64_t signedAtMs)> MessageFor;
        // Parses the block, checks certSig with the app signing key (aspk) over
        // the member message for appId, then sig with the member's upk_sign
        // over messageFor(signedAtMs).
        bool VerifySignatureBlock(const uint8_t* data, size_t length, const std::string& appId,
                                  const uint8_t appSignPublic[32], const MessageFor& messageFor,
                                  SignatureBlock& block, std::string& error);
        // "zk1d.<b64u server pk>.<kind>.<objectId>"
        bool ParseDeliveryHeader(const std::string& value, uint8_t serverPublic[32],
                                 std::string& kind, std::string& objectId);
        bool DeliveryKey(const uint8_t clientSecret[32], const uint8_t serverPublic[32],
                         const std::string& kind, const std::string& objectId, uint8_t key[32]);

        // Incremental stream decryption ("VXZ1" stored, "VXD1" delivery). The
        // sink only sees chunks whose tag verified, but the stream as a whole
        // is authentic only when Finish() returns true: on failure the caller
        // must discard everything the sink received.
        class StreamDecryptor {
        public:
            StreamDecryptor(const uint8_t key[32], const char magic[4], Sink sink);
            ~StreamDecryptor();
            bool Update(const uint8_t* data, size_t length);
            bool Finish();   // call at the end of the data
            const std::string& Error() const;
            uint64_t PlaintextBytes() const;
        private:
            struct Impl;
            std::unique_ptr<Impl> impl;
        public:
            StreamDecryptor(const StreamDecryptor&) = delete;
            StreamDecryptor& operator=(const StreamDecryptor&) = delete;
        };

        // One layer-3 delivery: VXD1 under the one-time key; for "file" and
        // "folder" also the sealed file key, the signature block and the VXZ1
        // content. The signature block is verified before the content is
        // decrypted (the sink sees nothing before that), and the content is
        // checked against the sealed size and SHA-256. Same failure rule as above.
        class DeliveryOpener {
        public:
            DeliveryOpener(const uint8_t clientSecret[32], const std::string& expectedKind);
            ~DeliveryOpener();
            // file/folder: the content key, the app id (signed messages), and
            // the name and product that were requested; the sealed key is
            // opened with the product scope, else with the general scope "".
            void SetFileContext(const ContentKey& key, const std::string& appId, const std::string& name,
                                const std::string& productId, Sink contentSink);
            bool Begin(const std::string& headerValue);   // the X-Encryption-Key value
            bool Update(const uint8_t* data, size_t length);
            bool Finish();
            const std::string& Error() const;
            const std::string& Kind() const;
            const std::string& ObjectId() const;
            const std::string& Scope() const;     // file/folder: productId or "" (general), once opened
            uint64_t ContentSize() const; // file/folder: the sealed plaintext size, once known
            uint64_t SignedAt() const;    // file/folder: signedAtMs, once the signature verified (else 0)
            std::string& VarsPayload();   // "vars": the JSON, valid after Finish()
        private:
            struct Impl;
            std::unique_ptr<Impl> impl;
        public:
            DeliveryOpener(const DeliveryOpener&) = delete;
            DeliveryOpener& operator=(const DeliveryOpener&) = delete;
        };

        // The JSON of a "vars" delivery -> (name, value). zk1 values are opened
        // with key (may be null if the list has none) and the product id, and
        // their signature blocks ("sig") verified for appId. Any failure: false
        // and no values at all.
        bool OpenVariables(const std::string& json, const ContentKey* key, const std::string& appId,
                           const std::string& productId,
                           std::vector<std::pair<std::string, std::string>>& out, std::string& error);
    }

    // File structure
    struct FileInfo {
        std::string id;
        std::string name;
        std::string appId;
        size_t size;
        bool encrypted;
        std::string encryptionKey;
        std::string encryptionIV;
        int downloads;
        std::string uploadedAt;
    };
    
    struct FolderInfo {
        std::string id;
        std::string name;
        std::string appId;
        size_t totalSize;
        int fileCount;
        int downloads;
        std::string uploadedAt;
    };

    // App User structure (NEW)
    struct AppUser {
        std::string id;
        std::string appId;
        std::string username;  // Empty if using key-based auth
        std::string key;       // Empty if using username/password auth
        std::vector<std::string> subscriptions;  // Product IDs user has access to
    };

    // Subscription structure (NEW)
    struct SubscriptionInfo {
        std::string subscriptionId;
        std::string appUserId;
        std::string productId;
        std::string status;
        std::string expiresAt;  // ISO format or empty for lifetime
        bool isPaused;
        std::string pausedAt;
        std::string pausedUntil;
        int downloads;
        std::string createdAt;
        std::string updatedAt;
    };

    // Session structure
    struct Session {
        std::string hwid;
        std::string sessionToken;
        std::string sessionId;
        bool isValid;
        std::string appId;
        // NEW FIELDS
        AppUser appUser;
        std::string tokenExpiry;  // When token expires (ISO format)
        std::string appApiKey;    // Store API key for operations that need it (e.g., clear_autologin)
    };

    class VaultixClient {
    private:
        std::string baseUrl;
        std::string apiKey;
        Session currentSession;
        bool debugMode;
        bool sslVerify;
        bool certificatePinningEnabled;
        std::vector<std::string> pinnedCertificates;  // SHA-256 hashes of pinned certificates
        std::string minTlsVersion;  // "1.2" or "1.3"
        bool requestSigningEnabled;
        std::string requestSigningKey;
        bool safetySessionEnabled;
        bool safetyRefreshInProgress;
        std::string safetyClientVersion;
        std::vector<uint8_t> safetyPrivateKey;
        std::vector<uint8_t> safetyPublicKey;
        std::string safetyPublicKeyDer;
        std::string safetyCertificate;
        std::string safetyCertificateChain;
        bool requireSignedResponses;        // default true, see SetRequireSignedResponses()
        long responseClockSkewSeconds;      // default 600, see SetResponseClockSkewTolerance()
        bool lastResponseRejected;          // last performRequest() failed signature verification
        zk1::ContentKey contentKey;         // zk1 app keys, memory only, see SetContentKey()
        bool haveContentKey;
        uint64_t lastSignedAt;              // see GetLastSignedAt()
        // (productId, fileName) this client received as verified zk1 files;
        // IsValidFileHash never sends their plain hash. Cleared by
        // ClearContentKey() and EndSession().
        std::set<std::pair<std::string, std::string>> verifiedZk1Files;

        // One download that may arrive as a zk1 delivery (VaultixClient.cpp).
        struct Zk1Download;

        // Internal HTTP methods. With zk1 set, the request carries a fresh
        // X-Vaultix-Eph key and a zk1 delivery is decrypted while it streams
        // (the result is then in *zk1 and the return value is empty).
        std::string performRequest(const std::string& endpoint,
                                  const std::string& method = "GET",
                                  const std::string& postData = "",
                                  std::map<std::string, std::string> headers = {},
                                  std::map<std::string, std::string>* responseHeaders = nullptr,
                                  Zk1Download* zk1 = nullptr);

        std::string getHWID();

        // Security helpers
        static CURLcode sslContextCallback(CURL* curl, void* sslctx, void* parm);
        bool verifyCertificatePin(const std::string& certHash);
        std::string signRequest(const std::string& method, const std::string& endpoint, const std::string& body, const std::string& timestamp);
        bool prepareSafetyAttestation(std::string& attestationToken);
        bool refreshSafetyAttestation();
        bool performSafetyHeartbeat();
        std::string hashCurrentExecutable();
        std::string signSafetyMessage(const std::string& message);
        bool validateSafetyCertificateChain(const std::string& leafCertificate,
                                            const std::string& rootCertificate);
        bool verifyResponseSignature(const std::string& method,
                                     const std::string& pathAndQuery,
                                     long statusCode,
                                     const std::string& body,
                                     const std::map<std::string, std::string>& lowerCaseHeaders,
                                     const std::string& nonce,
                                     std::string& failureReason);
        // Same check with the body-hash field given ("zk1-stream" for deliveries).
        bool verifyResponseSignatureFields(const std::string& method,
                                           const std::string& pathAndQuery,
                                           long statusCode,
                                           const std::string& bodyHashField,
                                           const std::map<std::string, std::string>& lowerCaseHeaders,
                                           const std::string& nonce,
                                           std::string& failureReason);

    public:
        VaultixClient(const std::string& baseUrl = "https://vaultix.cc/api");
        ~VaultixClient();
        
        // Configuration - API key only kept in memory during session creation
        void SetApiKey(const std::string& key) { 
            // Clear any existing API key from memory
            if (!apiKey.empty()) {
                std::fill(apiKey.begin(), apiKey.end(), 0);
            }
            apiKey = key; 
        }
        
        // Clear sensitive data from memory
        void ClearApiKey() {
            if (!apiKey.empty()) {
                std::fill(apiKey.begin(), apiKey.end(), 0);
                apiKey.clear();
            }
        }

        // End-to-end encryption. Apps with end-to-end encryption need the
        // content key ("vxk_...", 96 characters, App Settings) to download
        // files, folders and encrypted variables. It holds the key that opens
        // the content and the app's signing key, which approves the team
        // members whose signature every file and value must carry. It is kept
        // in memory only and wiped when replaced or when the client is
        // destroyed. Returns false (current key unchanged) if the key, its
        // version or its checksum is invalid.
        bool SetContentKey(const std::string& vxk);
        void ClearContentKey();
        bool HasContentKey() const { return haveContentKey; }
        // "XXXX-XXXX-XXXX-XXXX", must match the fingerprint in App Settings;
        // "" without a key.
        std::string GetContentKeyFingerprint() const;

        // Session Management
        bool AuthenticateWithUsername(const std::string& username, const std::string& password);
        bool AuthenticateWithKey(const std::string& userKey);
        bool TryAutoLogin();  // NEW: Try auto-login using persistent token
        bool RefreshToken();  // Refresh token when it expires
        void EndSession();  // End current session (does NOT clear persistent token)
        void ClearAutoLoginToken();  // Clear persistent auto-login token
        bool IsSessionValid() const { return currentSession.isValid; }
        bool IsTokenExpired() const;
        Session GetCurrentSession() const { return currentSession; }
        
        // File Operations (NEW STRUCTURE - requires productId)
        // Vaultix always sends downloads AES-256-GCM encrypted with the key in
        // a (signed) response header. File and folder downloads fail if that
        // key is missing; unencrypted data is never returned or saved.
        // End-to-end encrypted apps: every download, folder and variables
        // request carries a fresh one-time X25519 key; the response must be
        // signed and is decrypted while it streams. The file's signature
        // must come from a team member the app owner approved (checked with
        // the signing key in the content key) and cover this app, name,
        // product (or general file of that name), size and keyed hash; the
        // content is then checked against the sealed size and SHA-256. Any
        // failure returns nothing: *ToMemory returns an empty vector,
        // DownloadFile/Folder write to "<outputPath>.vxpart" and only rename
        // it after the check. On success GetLastError() is "" (so an empty
        // file is not an error).
        std::vector<FileInfo> GetFileList(const std::string& productId);
        FileInfo GetFileInfo(const std::string& productId, const std::string& fileName);
        bool DownloadFile(const std::string& productId, const std::string& fileName, const std::string& outputPath);
        std::vector<uint8_t> DownloadFileToMemory(const std::string& productId, const std::string& fileName);
        bool StreamFile(const std::string& productId, const std::string& fileName,
                       std::function<void(const std::vector<uint8_t>&, size_t, size_t)> callback);
        // Signing time (Unix milliseconds) of the file or folder returned by
        // the last DownloadFile, DownloadFileToMemory, StreamFile,
        // DownloadFolder or DownloadFolderToMemory call, if it was a verified
        // end-to-end encrypted download; 0 otherwise (failure, legacy file).
        // Vaultix cannot fake content but could serve an older, genuinely
        // signed version: keep the newest value you have seen per file and
        // refuse an older one if that matters to your app.
        uint64_t GetLastSignedAt() const;
        // With a content key the server compares the keyed hash
        // (HMAC(kh, SHA-256 of the file)); files of apps without end-to-end
        // encryption are then checked once more with the plain SHA-256 -
        // except files this client already downloaded as verified end-to-end
        // encrypted files: for those a request for the plain hash returns false.
        bool IsValidFileHash(const std::string& productId, const std::string& fileName, const std::string& filePath);
        
        // Folder Operations
        std::vector<FolderInfo> GetFolderList(const std::string& productId);
        FolderInfo GetFolderInfo(const std::string& productId, const std::string& folderName);
        bool DownloadFolder(const std::string& productId, const std::string& folderName, const std::string& outputPath);
        std::vector<uint8_t> DownloadFolderToMemory(const std::string& productId, const std::string& folderName);

        // Product Variables: (name, value). End-to-end encrypted values are
        // opened with the content key and must carry a valid signature of an
        // approved team member; any failure returns an empty list.
        std::vector<std::pair<std::string, std::string>> GetProductVariables(const std::string& productId);
        
        struct ProductStatusInfo {
            bool hasStatus = false;
            std::string name;
            std::string color;
            std::string action;
        };

        struct ProductNewsInfo {
            bool hasNews = false;
            std::string headline;
            std::string content;
            std::string updatedAt;
        };

        bool GetProductStatus(const std::string& productId, ProductStatusInfo& statusInfo);
        bool GetProductNews(const std::string& productId, ProductNewsInfo& newsInfo);

        // Cosmetic profile of whoever this session is logged in as. The server
        // resolves the identity from the session token, so nothing is passed in.
        // Display strings only -- no key, email, HWID or ids.
        struct AccountInfo {
            std::string username;  // Display name in key mode, username in username/password mode
            std::string note;      // Free-text note the app owner set on this user
        };

        bool GetAccountInfo(AccountInfo& accountInfo);

    // Helper: Check if user has access to a product
    bool HasProductAccess(const std::string& productId) const;
    
    // Get all products user has access to
    std::vector<std::map<std::string, std::string>> GetUserProducts();
    
    // Get user's subscription details for a specific product
    SubscriptionInfo GetUserSubscriptionByProduct(const std::string& productId);
        
        // Decryption
        bool DecryptFile(const std::string& inputPath, 
                        const std::string& outputPath,
                        const std::string& key,
                        const std::string& iv);
        std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& encryptedData,
                                        const std::string& key,
                                        const std::string& iv);
        
        // Utility
        void SetDebugMode(bool debug) { debugMode = debug; }
        void SetSSLVerify(bool verify) { sslVerify = verify; }
        std::string GetLastError() const { return lastError; }

        // Security Configuration
        void EnableCertificatePinning(const std::vector<std::string>& certHashes) {
            certificatePinningEnabled = true;
            pinnedCertificates = certHashes;
        }
        void DisableCertificatePinning() { certificatePinningEnabled = false; }
        void SetMinTlsVersion(const std::string& version) { minTlsVersion = version; }
        void EnableRequestSigning(const std::string& signingKey) {
            requestSigningEnabled = true;
            requestSigningKey = signingKey;
        }
        void DisableRequestSigning() { requestSigningEnabled = false; }

        // Response verification (on by default).
        // Every request carries a fresh random X-Vaultix-Nonce. Vaultix signs
        // each response (Ed25519) over that nonce, the method, path and query
        // that were sent, the status code, a SHA-256 of the full body, the
        // file encryption headers and the Content-Type. The SDK checks that
        // signature with the Vaultix public key built into VaultixClient.cpp, so a
        // fake server (DNS redirect, locally trusted CA, proxy) cannot answer
        // "login OK", hand out files, or replay an old response. Any response
        // that fails the check makes the call fail; GetLastError() then
        // starts with "Server response could not be verified".
        // Turning this off is ONLY for local testing against your own test
        // server; never ship a build with SetRequireSignedResponses(false).
        void SetRequireSignedResponses(bool require) { requireSignedResponses = require; }
        bool GetRequireSignedResponses() const { return requireSignedResponses; }
        // Allowed difference between this computer's clock and the server's
        // signing time, in seconds (default 600 = +/-10 minutes). Values <= 0
        // restore the default. The per-request nonce already stops replays;
        // raise this if your users have badly wrong system clocks.
        void SetResponseClockSkewTolerance(long seconds) { responseClockSkewSeconds = seconds > 0 ? seconds : 600; }

        // Version label included in Safety events. The executable hash is authoritative.
        void SetSafetyClientVersion(const std::string& version) { safetyClientVersion = version.empty() ? "unknown" : version; }
        // Optional proactive heartbeat for otherwise-idle sessions. Protected
        // API calls also perform it automatically when the server requires one.
        bool SendSafetyHeartbeat() { return performSafetyHeartbeat(); }

        
    private:
        std::string lastError;

        // Network obfuscation helpers
        std::string ExtractJTIFromToken(const std::string& jwtToken);
        std::string DecryptHeaderValue(const std::string& encryptedValue, const std::string& sessionJTI);

        // Auto-Login helpers
        std::string GetPersistentTokenPath();
        std::string GetAppIdentifier(const std::string& apiKey);  // Get obfuscated app identifier
        bool SavePersistentToken(const std::string& token, const std::string& apiKey);
        std::string LoadPersistentToken(const std::string& apiKey);
        bool DeletePersistentToken(const std::string& apiKey);
        std::vector<uint8_t> GenerateGarbage(size_t minSize, size_t maxSize);  // Generate random garbage/padding
        std::string ObfuscateString(const std::string& input);  // Obfuscate string with garbage
        std::string DeobfuscateString(const std::string& obfuscated);  // Remove garbage and extract original

        // Curl callbacks
        static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
        static size_t StreamCallback(void* contents, size_t size, size_t nmemb, void* userp);
    };
}

#endif // VAULTIX_CLIENT_H