using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Vaultix.SDK
{
    /// <summary>
    /// Main client class for interacting with the Vaultix API.
    ///
    /// Every response is checked against Vaultix's Ed25519 response signature
    /// (on by default, see <see cref="SetRequireSignedResponses"/>). Apps with
    /// end-to-end encryption need the content key (<see cref="SetContentKey"/>)
    /// to download files, folders and encrypted variables.
    ///
    /// The client is not thread-safe: use one instance per thread, or lock.
    /// </summary>
    public class VaultixClient : IDisposable
    {
        /// <summary>Version of this SDK.</summary>
        public const string SdkVersion = "2.0.0";

        private const long DefaultClockSkewSeconds = 600;
        private const int StreamChunkBytes = 4096;

        private readonly string _baseUrl;
        private HttpClient? _httpClient;
        private string? _apiKey;
        private Session _currentSession;
        private bool _debugMode;
        private bool _sslVerify = true;
        private bool _certificatePinningEnabled;
        private List<string> _pinnedCertificates = new();
        private string _minTlsVersion = "1.2";
        private bool _requestSigningEnabled;
        private string? _requestSigningKey;
        private string _lastError = string.Empty;
        private readonly string _persistentTokenDirectory;

        private bool _requireSignedResponses = true;
        private long _responseClockSkewSeconds = DefaultClockSkewSeconds;
        private bool _lastResponseRejected;
        private readonly List<(string KeyId, byte[] PublicKey)> _testingResponseKeys = new();

        private Zk1.ContentKey? _contentKey;           // zk1 app keys, memory only, see SetContentKey()
        private long _lastSignedAt;                    // see GetLastSignedAt()
        // (productId, fileName) this client received as verified zk1 files;
        // IsValidFileHashAsync never sends their plain hash. Cleared by
        // ClearContentKey() and EndSession().
        private readonly HashSet<(string ProductId, string FileName)> _verifiedZk1Files = new();
        private bool _disposed;

        /// <summary>
        /// Initialize a new Vaultix client
        /// </summary>
        /// <param name="baseUrl">The base URL of the Vaultix API (default: https://vaultix.cc/api)</param>
        public VaultixClient(string baseUrl = "https://vaultix.cc/api")
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _currentSession = new Session();
            _persistentTokenDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "VaultixSDK");
        }

        // =====================================================================
        // Configuration
        // =====================================================================

        /// <summary>
        /// Set the application API key (prefixed with "ap_")
        /// </summary>
        /// <param name="key">Your application API key</param>
        public void SetApiKey(string key)
        {
            _apiKey = key;
        }

        /// <summary>
        /// Forget the application API key
        /// </summary>
        public void ClearApiKey()
        {
            _apiKey = null;
        }

        /// <summary>
        /// Enable or disable debug output (it never shows credentials, keys or request bodies)
        /// </summary>
        public bool DebugMode
        {
            get => _debugMode;
            set => _debugMode = value;
        }

        /// <summary>
        /// Enable or disable TLS certificate verification. Turning it off is for local testing only.
        /// </summary>
        public bool SslVerify
        {
            get => _sslVerify;
            set
            {
                _sslVerify = value;
                ResetHttpClient();
            }
        }

        /// <summary>
        /// Enable certificate pinning: the server's leaf certificate must carry one
        /// of these public keys, given as SHA-256 of the SubjectPublicKeyInfo (64
        /// hex characters, or "sha256/" + base64), in addition to the normal
        /// certificate validation.
        /// </summary>
        /// <param name="certHashes">SHA-256 hashes of trusted public keys</param>
        public void EnableCertificatePinning(List<string> certHashes)
        {
            _certificatePinningEnabled = true;
            _pinnedCertificates = new List<string>(certHashes ?? new List<string>());
            ResetHttpClient();
        }

        /// <summary>
        /// Disable certificate pinning
        /// </summary>
        public void DisableCertificatePinning()
        {
            _certificatePinningEnabled = false;
            ResetHttpClient();
        }

        /// <summary>
        /// Set minimum TLS version
        /// </summary>
        /// <param name="version">"1.2" or "1.3"</param>
        public void SetMinTlsVersion(string version)
        {
            _minTlsVersion = version;
            ResetHttpClient();
        }

        /// <summary>
        /// Enable request signing (X-Request-Timestamp and X-Request-Signature,
        /// HMAC-SHA256 over METHOD|ENDPOINT|BODY|TIMESTAMP)
        /// </summary>
        /// <param name="signingKey">The key used to sign requests</param>
        public void EnableRequestSigning(string signingKey)
        {
            _requestSigningEnabled = true;
            _requestSigningKey = signingKey;
        }

        /// <summary>
        /// Disable request signing
        /// </summary>
        public void DisableRequestSigning()
        {
            _requestSigningEnabled = false;
        }

        // =====================================================================
        // Response verification (on by default)
        // =====================================================================

        /// <summary>
        /// Every request carries a fresh random X-Vaultix-Nonce. Vaultix signs each
        /// response (Ed25519) over that nonce, the method, path and query that were
        /// sent, the status code, a SHA-256 of the full body, the file encryption
        /// headers and the Content-Type. The SDK checks that signature with the
        /// Vaultix public key built into the SDK, so a fake server (DNS redirect,
        /// locally trusted CA, proxy) cannot answer "login OK", hand out files, or
        /// replay an old response. Any response that fails the check makes the call
        /// fail; <see cref="GetLastError"/> then starts with "Server response could
        /// not be verified". End-to-end encrypted deliveries are always verified,
        /// also with this turned off.
        /// Turning this off is ONLY for local testing against your own test server;
        /// never ship a build with SetRequireSignedResponses(false).
        /// </summary>
        public void SetRequireSignedResponses(bool require) => _requireSignedResponses = require;

        /// <summary>Whether responses must carry a valid Vaultix signature (default true).</summary>
        public bool GetRequireSignedResponses() => _requireSignedResponses;

        /// <summary>Same as <see cref="SetRequireSignedResponses"/> / <see cref="GetRequireSignedResponses"/>.</summary>
        public bool RequireSignedResponses
        {
            get => _requireSignedResponses;
            set => _requireSignedResponses = value;
        }

        /// <summary>
        /// Allowed difference between this computer's clock and the server's
        /// signing time, in seconds (default 600 = +/-10 minutes). Values &lt;= 0
        /// restore the default. The per-request nonce already stops replays; raise
        /// this if your users have badly wrong system clocks.
        /// </summary>
        public void SetResponseClockSkewTolerance(long seconds) =>
            _responseClockSkewSeconds = seconds > 0 ? seconds : DefaultClockSkewSeconds;

        /// <summary>The current clock skew tolerance in seconds.</summary>
        public long ResponseClockSkewTolerance => _responseClockSkewSeconds;

        /// <summary>
        /// TESTING ONLY. Never call this in a build you ship.
        /// Trusts one extra Ed25519 key for response signatures, for a test backend
        /// that signs with its own throwaway key (the C# counterpart of the C++
        /// SDK's VAULTIX_TESTING_EXTRA_RESPONSE_KEY_ID / _HEX build flags). Whoever
        /// holds the matching private key can then answer as Vaultix. The built-in
        /// Vaultix keys stay trusted. The key id must be "vx-sig-" followed by the
        /// first 16 hex characters of SHA-256(public key). Returns false (and
        /// changes nothing) for an invalid key or key id.
        /// </summary>
        /// <param name="keyId">"vx-sig-..." key id the test server sends in X-Vaultix-Key-Id</param>
        /// <param name="publicKeyHex">raw 32-byte Ed25519 public key, 64 hex characters</param>
        public bool TrustResponseKeyForTestingOnly(string keyId, string publicKeyHex)
        {
            byte[] publicKey;
            try
            {
                publicKey = Convert.FromHexString(publicKeyHex ?? "");
            }
            catch (FormatException)
            {
                return false;
            }
            if (publicKey.Length != 32 || Zk1.WeakSigningKey(publicKey) ||
                keyId != ResponseSigning.KeyIdFor(publicKey))
            {
                return false;
            }
            _testingResponseKeys.RemoveAll(k => k.KeyId == keyId);
            _testingResponseKeys.Add((keyId, publicKey));
            Log("WARNING: an extra response key is trusted for testing (" + keyId + "); never ship this");
            return true;
        }

        // Tests only: forget the keys added with TrustResponseKeyForTestingOnly.
        internal void ClearTestingResponseKeys() => _testingResponseKeys.Clear();

        // =====================================================================
        // End-to-end encryption (content key)
        // =====================================================================

        /// <summary>
        /// Apps with end-to-end encryption need the content key ("vxk_...", 96
        /// characters, App Settings) to download files, folders and encrypted
        /// variables. It holds the key that opens the content and the app's signing
        /// key, which approves the team members whose signature every file and
        /// value must carry. The decoded key is kept in memory only and zeroed when
        /// replaced, cleared or when the client is disposed. Returns false (current
        /// key unchanged) if the key, its version or its checksum is invalid.
        /// </summary>
        public bool SetContentKey(string vxk)
        {
            Zk1.ContentKey? key = Zk1.ContentKeyFromSdkKey(vxk);
            if (key == null)
            {
                _lastError = "Invalid content key: use the vxk_ key from App Settings (96 characters)";
                return false;
            }
            ClearContentKey();
            _contentKey = key;
            return true;
        }

        /// <summary>Zero and forget the content key.</summary>
        public void ClearContentKey()
        {
            _contentKey?.Dispose();
            _contentKey = null;
            _verifiedZk1Files.Clear();
        }

        /// <summary>True when a content key is set.</summary>
        public bool HasContentKey => _contentKey != null;

        /// <summary>
        /// "XXXX-XXXX-XXXX-XXXX"; must match the fingerprint in App Settings.
        /// Empty without a key.
        /// </summary>
        public string GetContentKeyFingerprint()
        {
            if (_contentKey == null) return string.Empty;
            return Zk1.Fingerprint(Zk1.X25519Public(_contentKey.SdkSecret), _contentKey.SignPublic);
        }

        /// <summary>
        /// Signing time (Unix milliseconds) of the file or folder returned by the
        /// last DownloadFileAsync, DownloadFileToMemoryAsync, StreamFileAsync,
        /// DownloadFolderAsync or DownloadFolderToMemoryAsync call, if it was a
        /// verified end-to-end encrypted download; 0 otherwise (failure, legacy
        /// file). Vaultix cannot fake content but could serve an older, genuinely
        /// signed version: keep the newest value you have seen per file and refuse
        /// an older one if that matters to your app.
        /// </summary>
        public long GetLastSignedAt() => _lastSignedAt;

        // =====================================================================
        // Authentication
        // =====================================================================

        /// <summary>
        /// Authenticate with username and password
        /// </summary>
        /// <param name="username">User's username</param>
        /// <param name="password">User's password</param>
        /// <returns>True if authentication succeeded</returns>
        public async Task<bool> AuthenticateWithUsernameAsync(string username, string password)
        {
            string apiKey = ActiveApiKey();
            if (apiKey.Length == 0)
            {
                _lastError = "API key not set";
                return false;
            }
            try
            {
                string hwid = GetHwid();
                var body = new JObject { ["username"] = username, ["password"] = password, ["hwid"] = hwid };
                string? response = await PerformRequestAsync("/app_auth/login", "POST", body.ToString(Formatting.None),
                    apiKeyAuth: true).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    return false;
                }
                if (!CompleteLogin(response, hwid, apiKey, username, null, autoLogin: false)) return false;
                Log("Authenticated with username");
                return true;
            }
            catch (Exception ex)
            {
                _lastError = "Authentication failed: " + ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Authenticate with a license key
        /// </summary>
        /// <param name="userKey">User's license key</param>
        /// <returns>True if authentication succeeded</returns>
        public async Task<bool> AuthenticateWithKeyAsync(string userKey)
        {
            string apiKey = ActiveApiKey();
            if (apiKey.Length == 0)
            {
                _lastError = "API key not set";
                return false;
            }
            try
            {
                string hwid = GetHwid();
                var body = new JObject { ["key"] = userKey, ["hwid"] = hwid };
                string? response = await PerformRequestAsync("/app_auth/login_key", "POST", body.ToString(Formatting.None),
                    apiKeyAuth: true).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    return false;
                }
                if (!CompleteLogin(response, hwid, apiKey, null, userKey, autoLogin: false)) return false;
                Log("Authenticated with key");
                return true;
            }
            catch (Exception ex)
            {
                _lastError = "Key authentication failed: " + ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Try automatic login with the auto-login token Vaultix issued at the last
        /// login on this device (only for apps with auto-login enabled)
        /// </summary>
        /// <returns>True if auto-login succeeded</returns>
        public async Task<bool> TryAutoLoginAsync()
        {
            string apiKey = ActiveApiKey();
            if (apiKey.Length == 0)
            {
                _lastError = "API key not set";
                return false;
            }
            string? persistentToken = LoadPersistentToken(apiKey);
            if (string.IsNullOrEmpty(persistentToken))
            {
                _lastError = "No saved auto-login token for this app";
                return false;
            }
            try
            {
                string hwid = GetHwid();
                var body = new JObject { ["token"] = persistentToken, ["hwid"] = hwid };
                string? response = await PerformRequestAsync("/app_auth/autologin", "POST", body.ToString(Formatting.None),
                    apiKeyAuth: true).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    // An unverifiable response says nothing about the saved token; keep it.
                    if (!_lastResponseRejected) DeletePersistentToken(apiKey);
                    return false;
                }
                if (!CompleteLogin(response, hwid, apiKey, null, null, autoLogin: true))
                {
                    DeletePersistentToken(apiKey);
                    return false;
                }
                Log("Auto-login successful");
                return true;
            }
            catch (Exception ex)
            {
                _lastError = "Auto-login failed: " + ex.Message;
                DeletePersistentToken(apiKey);
                return false;
            }
        }

        /// <summary>
        /// Get a new session: signs in again with the license key of a key login.
        /// A username/password login needs the password again.
        /// </summary>
        /// <returns>True if refresh succeeded</returns>
        public async Task<bool> RefreshTokenAsync()
        {
            if (!string.IsNullOrEmpty(_currentSession.AppUser.Username))
            {
                _lastError = "Password re-entry required after token expiration";
                return false;
            }
            if (!string.IsNullOrEmpty(_currentSession.AppUser.Key))
            {
                return await AuthenticateWithKeyAsync(_currentSession.AppUser.Key!).ConfigureAwait(false);
            }
            _lastError = "No stored credentials for refresh";
            return false;
        }

        /// <summary>
        /// End the current session (logs out on the server; does NOT clear the auto-login token)
        /// </summary>
        public void EndSession()
        {
            Task.Run(EndSessionAsync).GetAwaiter().GetResult();
        }

        /// <summary>
        /// End the current session (logs out on the server; does NOT clear the auto-login token)
        /// </summary>
        public async Task EndSessionAsync()
        {
            if (_currentSession.IsValid)
            {
                try
                {
                    string? response = await PerformRequestAsync("/app_auth/logout", "POST", "").ConfigureAwait(false);
                    if (!string.IsNullOrEmpty(response) && ParseJson(response) is JObject json)
                    {
                        string message = Str(json, "message");
                        if (!message.Contains("successfully", StringComparison.Ordinal))
                        {
                            _lastError = message.Length == 0 ? "Failed to terminate session" : message;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _lastError = "Logout failed: " + ex.Message;
                }
            }
            // Clear session data regardless of logout success
            _currentSession = new Session();
            _verifiedZk1Files.Clear();
            Log("Session ended");
        }

        /// <summary>
        /// Revoke the auto-login token on the server and delete it from this device
        /// </summary>
        public void ClearAutoLoginToken()
        {
            Task.Run(ClearAutoLoginTokenAsync).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Revoke the auto-login token on the server and delete it from this device
        /// </summary>
        public async Task ClearAutoLoginTokenAsync()
        {
            string apiKey = ActiveApiKey();
            if (apiKey.Length == 0)
            {
                Log("No API key available for token lookup");
                return;
            }
            string? persistentToken = LoadPersistentToken(apiKey);
            if (!string.IsNullOrEmpty(persistentToken))
            {
                try
                {
                    var body = new JObject { ["token"] = persistentToken, ["hwid"] = GetHwid() };
                    await PerformRequestAsync("/app_auth/clear_autologin", "POST", body.ToString(Formatting.None),
                        apiKeyAuth: true).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // Still delete the local token
                    Log("Failed to notify the server: " + ex.Message);
                }
            }
            DeletePersistentToken(apiKey);
            Log("Auto-login token cleared");
        }

        // =====================================================================
        // Session State
        // =====================================================================

        /// <summary>
        /// Check if the current session is valid
        /// </summary>
        public bool IsSessionValid => _currentSession.IsValid;

        /// <summary>
        /// True without a session. With a session the server checks the token on
        /// every call (the C++ SDK behaves the same way).
        /// </summary>
        public Task<bool> IsTokenExpiredAsync()
        {
            return Task.FromResult(!_currentSession.IsValid || string.IsNullOrEmpty(_currentSession.TokenExpiry));
        }

        /// <summary>
        /// Get the current session information
        /// </summary>
        public Session GetCurrentSession() => _currentSession;

        /// <summary>
        /// Get the last error message ("" after a successful call)
        /// </summary>
        public string GetLastError() => _lastError;

        // =====================================================================
        // File Operations
        // =====================================================================

        /// <summary>
        /// Get a list of all files for a product
        /// </summary>
        public async Task<List<FileInfo>> GetFileListAsync(string productId)
        {
            var files = new List<FileInfo>();
            if (!await RequireSessionAsync().ConfigureAwait(false)) return files;
            try
            {
                string? response = await PerformRequestAsync("/files?productId=" + UrlEncode(productId), "GET", null,
                    ProductHeader(productId)).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    return files;
                }
                if (ParseJson(response) is JArray items)
                {
                    foreach (JObject item in items.OfType<JObject>()) files.Add(ParseFileInfo(item));
                }
                else
                {
                    _lastError = "Unexpected file list response";
                }
            }
            catch (Exception ex)
            {
                _lastError = "Exception during file list retrieval: " + ex.Message;
            }
            return files;
        }

        /// <summary>
        /// Get information about a specific file (null on failure)
        /// </summary>
        public async Task<FileInfo?> GetFileInfoAsync(string productId, string fileName)
        {
            if (!await RequireSessionAsync().ConfigureAwait(false)) return null;
            try
            {
                string? response = await PerformRequestAsync(
                    "/files/info/" + UrlEncode(fileName) + "?productId=" + UrlEncode(productId), "GET", null,
                    ProductHeader(productId)).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    return null;
                }
                if (ParseJson(response) is JObject json) return ParseFileInfo(json);
                _lastError = "Failed to parse JSON response";
            }
            catch (Exception ex)
            {
                _lastError = "Exception during file info retrieval: " + ex.Message;
            }
            return null;
        }

        /// <summary>
        /// Download a file to the specified path. The data is written to
        /// "&lt;outputPath&gt;.vxpart" and renamed to outputPath only after every
        /// check passed; on failure nothing is left behind.
        /// End-to-end encrypted files must carry a valid signature of a team member
        /// the app owner approved (checked with the signing key in the content key)
        /// covering this app, name, product (or general file of that name), size
        /// and keyed hash; the content is then checked against the sealed size and
        /// SHA-256.
        /// </summary>
        public async Task<bool> DownloadFileAsync(string productId, string fileName, string outputPath)
        {
            _lastSignedAt = 0;
            if (!await RequireSessionAsync().ConfigureAwait(false)) return false;
            try
            {
                CreateParentDirectory(outputPath);
                using var zk1 = new Zk1Download(Zk1Target.File, "file", fileName, productId, outputPath);
                Exchange? exchange = await RequestAsync(FileDownloadEndpoint(productId, fileName), "GET", null,
                    ProductHeader(productId), false, zk1).ConfigureAwait(false);
                if (zk1.IsDelivery) return zk1.Succeeded;
                byte[]? data = LegacyDownloadBody(exchange, "file", "Empty response when downloading file");
                if (data == null) return false;
                try
                {
                    return WriteVerifiedFile(outputPath, data);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(data);
                }
            }
            catch (Exception ex)
            {
                _lastError = "Exception during file download: " + ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Download a file into memory. Returns null on any failure
        /// (<see cref="GetLastError"/> says why); an empty file is an empty array.
        /// End-to-end encrypted files are verified and decrypted as described at
        /// <see cref="DownloadFileAsync"/>.
        /// </summary>
        public async Task<byte[]?> DownloadFileToMemoryAsync(string productId, string fileName)
        {
            _lastSignedAt = 0;
            if (!await RequireSessionAsync().ConfigureAwait(false)) return null;
            try
            {
                using var zk1 = new Zk1Download(Zk1Target.Memory, "file", fileName, productId, "");
                Exchange? exchange = await RequestAsync(FileDownloadEndpoint(productId, fileName), "GET", null,
                    ProductHeader(productId), false, zk1).ConfigureAwait(false);
                if (zk1.IsDelivery) return zk1.Succeeded ? zk1.TakeMemory() : null;
                return LegacyDownloadBody(exchange, "file", "Empty response when downloading file");
            }
            catch (Exception ex)
            {
                _lastError = "Exception during file download: " + ex.Message;
                return null;
            }
        }

        /// <summary>
        /// Download a file and hand it to the callback in 4 KiB chunks
        /// (chunk, bytes so far, total bytes). The file is downloaded and verified
        /// in full first, so the callback only ever sees verified data.
        /// </summary>
        public async Task<bool> StreamFileAsync(string productId, string fileName, Action<byte[], long, long>? progressCallback = null)
        {
            byte[]? data = await DownloadFileToMemoryAsync(productId, fileName).ConfigureAwait(false);
            if (data == null) return false;
            try
            {
                long total = data.Length;
                long processed = 0;
                while (processed < total)
                {
                    int size = (int)Math.Min(StreamChunkBytes, total - processed);
                    byte[] chunk = new byte[size];
                    Array.Copy(data, processed, chunk, 0, size);
                    processed += size;
                    progressCallback?.Invoke(chunk, processed, total);
                }
                return true;
            }
            catch (Exception ex)
            {
                _lastError = "Exception during file streaming: " + ex.Message;
                return false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(data);
            }
        }

        /// <summary>
        /// Check a local file against the file on the server. With a content key
        /// the server compares the keyed hash (HMAC(hashKey, SHA-256 of the file)),
        /// so Vaultix never learns the checksum of end-to-end encrypted files;
        /// files of apps without end-to-end encryption are then checked once more
        /// with the plain SHA-256, except files this client already downloaded as
        /// verified end-to-end encrypted files: for those a request for the plain
        /// hash returns false.
        /// </summary>
        public async Task<bool> IsValidFileHashAsync(string productId, string fileName, string filePath)
        {
            if (!await RequireSessionAsync().ConfigureAwait(false)) return false;
            try
            {
                byte[] digest;
                try
                {
                    using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    digest = await SHA256.HashDataAsync(stream).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    _lastError = "Failed to open file: " + filePath;
                    return false;
                }
                string fileHash = Convert.ToHexString(digest).ToLowerInvariant();
                Log("Calculated file hash");

                string plainRequest = new JObject
                {
                    ["productId"] = productId, ["fileName"] = fileName, ["hash"] = fileHash,
                }.ToString(Formatting.None);
                // End-to-end encryption: Vaultix stores only the keyed hash
                // HMAC(kh, SHA-256) of zk1 files (docs/E2EE_FORMAT.md section 5).
                // Files of apps without it answer "plain_hash_required": then once
                // more with the plain SHA-256, unless this client already received
                // the file as a verified zk1 delivery (a server asking for its
                // plain hash would learn what end-to-end encryption hides).
                bool keyed = _contentKey != null;
                string request = plainRequest;
                if (keyed)
                {
                    byte[] keyedHash = Zk1.HmacSha256(_contentKey!.HashKey, digest);
                    request = new JObject
                    {
                        ["productId"] = productId, ["fileName"] = fileName,
                        ["keyedHash"] = Convert.ToHexString(keyedHash).ToLowerInvariant(),
                    }.ToString(Formatting.None);
                }

                for (int attempt = 0; ; ++attempt)
                {
                    string? response = await PerformRequestAsync("/files/verify-hash", "POST", request,
                        ProductHeader(productId)).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(response))
                    {
                        if (_lastError.Length == 0) _lastError = "Empty response from server";
                        return false;
                    }
                    if (ParseJson(response) is not JObject json)
                    {
                        _lastError = "Failed to parse verification response";
                        return false;
                    }
                    bool isValid = Bool(json, "valid", false);
                    if (!isValid && keyed && attempt == 0 && Str(json, "code") == "plain_hash_required")
                    {
                        if (_verifiedZk1Files.Contains((productId, fileName)))
                        {
                            _lastError = "verify-hash: the server asked for the plain hash of an end-to-end encrypted file";
                            Log(_lastError);
                            return false;
                        }
                        Log("Not an end-to-end encrypted file: checking the plain hash");
                        request = plainRequest;
                        continue;
                    }
                    Log("Hash verification result: " + (isValid ? "VALID" : "INVALID"));
                    return isValid;
                }
            }
            catch (Exception ex)
            {
                _lastError = "Exception during hash verification: " + ex.Message;
                return false;
            }
        }

        // =====================================================================
        // Folder Operations
        // =====================================================================

        /// <summary>
        /// Get a list of all folders for a product
        /// </summary>
        public async Task<List<FolderInfo>> GetFolderListAsync(string productId)
        {
            var folders = new List<FolderInfo>();
            if (!await RequireSessionAsync().ConfigureAwait(false)) return folders;
            try
            {
                string? response = await PerformRequestAsync("/folders?productId=" + UrlEncode(productId), "GET", null,
                    ProductHeader(productId)).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    return folders;
                }
                if (ParseJson(response) is JArray items)
                {
                    foreach (JObject item in items.OfType<JObject>()) folders.Add(ParseFolderInfo(item));
                }
                else
                {
                    _lastError = "Unexpected folder list response";
                }
            }
            catch (Exception ex)
            {
                _lastError = "Exception getting folder list: " + ex.Message;
            }
            return folders;
        }

        /// <summary>
        /// Get information about a folder (null on failure)
        /// </summary>
        public async Task<FolderInfo?> GetFolderInfoAsync(string productId, string folderName)
        {
            if (!await RequireSessionAsync().ConfigureAwait(false)) return null;
            try
            {
                string? response = await PerformRequestAsync(
                    "/folders/info/" + UrlEncode(folderName) + "?productId=" + UrlEncode(productId), "GET", null,
                    ProductHeader(productId)).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    return null;
                }
                if (ParseJson(response) is JObject json) return ParseFolderInfo(json);
                _lastError = "Failed to parse JSON response";
            }
            catch (Exception ex)
            {
                _lastError = "Exception getting folder info: " + ex.Message;
            }
            return null;
        }

        /// <summary>
        /// Download a folder as a zip archive. Written to "&lt;outputPath&gt;.vxpart"
        /// and renamed only after every check passed (see <see cref="DownloadFileAsync"/>).
        /// </summary>
        public async Task<bool> DownloadFolderAsync(string productId, string folderName, string outputPath)
        {
            _lastSignedAt = 0;
            if (!await RequireSessionAsync().ConfigureAwait(false)) return false;
            try
            {
                if (!await FolderExistsAsync(productId, folderName).ConfigureAwait(false)) return false;
                CreateParentDirectory(outputPath);
                using var zk1 = new Zk1Download(Zk1Target.File, "folder", folderName, productId, outputPath);
                Exchange? exchange = await RequestAsync(FolderDownloadEndpoint(productId, folderName), "GET", null,
                    ProductHeader(productId), false, zk1).ConfigureAwait(false);
                if (zk1.IsDelivery) return zk1.Succeeded;
                byte[]? data = LegacyDownloadBody(exchange, "folder", "Empty response from server");
                if (data == null) return false;
                try
                {
                    return WriteVerifiedFile(outputPath, data);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(data);
                }
            }
            catch (Exception ex)
            {
                _lastError = "Exception during folder download: " + ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Download a folder (zip archive) into memory. Returns null on any failure.
        /// </summary>
        public async Task<byte[]?> DownloadFolderToMemoryAsync(string productId, string folderName)
        {
            _lastSignedAt = 0;
            if (!await RequireSessionAsync().ConfigureAwait(false)) return null;
            try
            {
                if (!await FolderExistsAsync(productId, folderName).ConfigureAwait(false)) return null;
                using var zk1 = new Zk1Download(Zk1Target.Memory, "folder", folderName, productId, "");
                Exchange? exchange = await RequestAsync(FolderDownloadEndpoint(productId, folderName), "GET", null,
                    ProductHeader(productId), false, zk1).ConfigureAwait(false);
                if (zk1.IsDelivery) return zk1.Succeeded ? zk1.TakeMemory() : null;
                return LegacyDownloadBody(exchange, "folder", "Empty response from server");
            }
            catch (Exception ex)
            {
                _lastError = "Exception during folder download: " + ex.Message;
                return null;
            }
        }

        // =====================================================================
        // Product Information
        // =====================================================================

        /// <summary>
        /// Get product variables (name, value). End-to-end encrypted values are
        /// opened with the content key and must carry a valid signature of an
        /// approved team member; any failure returns an empty dictionary.
        /// </summary>
        public async Task<Dictionary<string, string>> GetProductVariablesAsync(string productId)
        {
            var variables = new Dictionary<string, string>();
            if (!await RequireSessionAsync().ConfigureAwait(false)) return variables;
            try
            {
                string appId = _currentSession.AppId;
                if (string.IsNullOrEmpty(appId))
                {
                    _lastError = "Missing appId in session";
                    return variables;
                }
                using var zk1 = new Zk1Download(Zk1Target.Variables, "vars", "", productId, "");
                Exchange? exchange = await RequestAsync(
                    "/apps/" + UrlEncode(appId) + "/products/" + UrlEncode(productId) + "/variables", "GET", null,
                    null, false, zk1).ConfigureAwait(false);
                if (zk1.IsDelivery)
                {
                    if (zk1.Succeeded)
                    {
                        foreach (var entry in zk1.Variables) variables[entry.Key] = entry.Value;
                        Log($"GetProductVariables: {variables.Count} variables (values not shown)");
                    }
                    return variables;
                }
                if (exchange == null || exchange.Body.Length == 0) return variables;
                if (ParseJson(exchange.Text) is JArray items)
                {
                    foreach (JObject item in items.OfType<JObject>())
                    {
                        string name = Str(item, "name");
                        JToken? value = item["value"];
                        variables[name] = value == null || value.Type == JTokenType.Null ? ""
                            : value.Type == JTokenType.String ? value.Value<string>() ?? "" : value.ToString(Formatting.None);
                    }
                }
                else
                {
                    _lastError = "Unexpected variables response";
                }
            }
            catch (Exception ex)
            {
                variables.Clear();
                _lastError = "Exception during GetProductVariables: " + ex.Message;
            }
            return variables;
        }

        /// <summary>
        /// Get product status
        /// </summary>
        public async Task<ProductStatusInfo> GetProductStatusAsync(string productId)
        {
            var status = new ProductStatusInfo();
            try
            {
                string? response = await PerformRequestAsync("/api/products/" + UrlEncode(productId) + "/status", "GET")
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response when fetching product status";
                    return status;
                }
                if (ParseJson(response) is JObject json && json["status"] is JObject statusObject)
                {
                    status.HasStatus = true;
                    status.Name = Str(statusObject, "name");
                    status.Color = Str(statusObject, "color");
                    status.Action = Str(statusObject, "action");
                }
            }
            catch (Exception ex)
            {
                _lastError = "Failed to fetch product status: " + ex.Message;
            }
            return status;
        }

        /// <summary>
        /// Get product news
        /// </summary>
        public async Task<ProductNewsInfo> GetProductNewsAsync(string productId)
        {
            var news = new ProductNewsInfo();
            try
            {
                string? response = await PerformRequestAsync("/api/products/" + UrlEncode(productId) + "/news", "GET")
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response when fetching product news";
                    return news;
                }
                if (ParseJson(response) is JObject json && json["news"] is JObject newsObject)
                {
                    news.HasNews = true;
                    news.Headline = Str(newsObject, "headline");
                    news.Content = Str(newsObject, "content");
                    news.UpdatedAt = Str(newsObject, "updatedAt");
                }
            }
            catch (Exception ex)
            {
                _lastError = "Failed to fetch product news: " + ex.Message;
            }
            return news;
        }

        /// <summary>
        /// Cosmetic profile of whoever this session is logged in as (display
        /// strings only). Null on failure.
        /// </summary>
        public async Task<AccountInfo?> GetAccountInfoAsync()
        {
            if (!await RequireSessionAsync().ConfigureAwait(false)) return null;
            try
            {
                string? response = await PerformRequestAsync("/me", "GET").ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response when fetching account info";
                    return null;
                }
                if (ParseJson(response) is JObject json)
                {
                    return new AccountInfo { Username = Str(json, "username"), Note = Str(json, "note") };
                }
                _lastError = "Failed to parse account info";
            }
            catch (Exception ex)
            {
                _lastError = "Failed to fetch account info: " + ex.Message;
            }
            return null;
        }

        // =====================================================================
        // User & Subscription
        // =====================================================================

        /// <summary>
        /// Check if the signed-in user had a subscription to the product at login
        /// </summary>
        public bool HasProductAccess(string productId)
        {
            return _currentSession.IsValid && _currentSession.AppUser.Subscriptions.Contains(productId);
        }

        /// <summary>
        /// Get all products user has access to (id, name, description, appId,
        /// status, fileCount, subscriptionsCount)
        /// </summary>
        public async Task<List<Dictionary<string, string>>> GetUserProductsAsync()
        {
            var products = new List<Dictionary<string, string>>();
            if (!await RequireSessionAsync().ConfigureAwait(false)) return products;
            try
            {
                string? response = await PerformRequestAsync("/products", "GET").ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.Length == 0) _lastError = "Empty response from server";
                    return products;
                }
                if (ParseJson(response) is JArray items)
                {
                    foreach (JObject item in items.OfType<JObject>())
                    {
                        var product = new Dictionary<string, string>();
                        foreach (string field in new[] { "id", "name", "description", "appId", "status", "fileCount", "subscriptionsCount" })
                        {
                            product[field] = Str(item, field);
                        }
                        products.Add(product);
                    }
                }
            }
            catch (Exception ex)
            {
                _lastError = "Exception during product retrieval: " + ex.Message;
            }
            return products;
        }

        /// <summary>
        /// Get subscription details for a product
        /// </summary>
        public async Task<SubscriptionInfo> GetUserSubscriptionByProductAsync(string productId)
        {
            var subscription = new SubscriptionInfo();
            if (!await RequireSessionAsync().ConfigureAwait(false)) return subscription;
            try
            {
                string? response = await PerformRequestAsync("/products/" + UrlEncode(productId) + "/user-subscription", "GET")
                    .ConfigureAwait(false);
                if (string.IsNullOrEmpty(response))
                {
                    if (_lastError.StartsWith("HTTP Error 404", StringComparison.Ordinal))
                    {
                        _lastError = "No subscription found for this product";
                    }
                    else if (_lastError.Length == 0)
                    {
                        _lastError = "Empty response from server";
                    }
                    return subscription;
                }
                if (ParseJson(response) is JObject json)
                {
                    subscription.SubscriptionId = Str(json, "subscriptionId");
                    subscription.AppUserId = Str(json, "appUserId");
                    subscription.ProductId = Str(json, "productId");
                    subscription.Status = Str(json, "status");
                    subscription.ExpiresAt = StrOrNull(json, "expiresAt");
                    subscription.IsPaused = Bool(json, "isPaused", false);
                    subscription.PausedAt = StrOrNull(json, "pausedAt");
                    subscription.PausedUntil = StrOrNull(json, "pausedUntil");
                    subscription.Downloads = (int)Long(json, "downloads");
                    subscription.CreatedAt = Str(json, "createdAt");
                    subscription.UpdatedAt = Str(json, "updatedAt");
                }
                else
                {
                    _lastError = "Failed to parse subscription response";
                }
            }
            catch (Exception ex)
            {
                _lastError = "Exception during subscription retrieval: " + ex.Message;
            }
            return subscription;
        }

        // =====================================================================
        // Decryption (downloads of apps without end-to-end encryption)
        // =====================================================================

        /// <summary>
        /// Decrypt a file in the Vaultix download format of apps without end-to-end
        /// encryption (see <see cref="DecryptData"/>). The downloads functions do
        /// this already.
        /// </summary>
        public async Task<bool> DecryptFileAsync(string inputPath, string outputPath, string key, string iv)
        {
            try
            {
                if (!File.Exists(inputPath))
                {
                    _lastError = "Failed to open input file: " + inputPath;
                    return false;
                }
                byte[] encrypted = await File.ReadAllBytesAsync(inputPath).ConfigureAwait(false);
                byte[]? plain = DecryptVaultixData(encrypted, key);
                if (plain == null) return false;
                try
                {
                    CreateParentDirectory(outputPath);
                    await File.WriteAllBytesAsync(outputPath, plain).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
                return true;
            }
            catch (Exception ex)
            {
                _lastError = "Exception during file decryption: " + ex.Message;
                return false;
            }
        }

        /// <summary>
        /// Decrypt data in the Vaultix download format of apps without end-to-end
        /// encryption: SALT(16) || IV(12) || TAG(16) || CIPHERTEXT (or the older
        /// IV(12) || TAG(16) || CIPHERTEXT), AES-256-GCM with a key derived by
        /// PBKDF2-HMAC-SHA256 (100,000 iterations) from <paramref name="key"/>, the
        /// X-Encryption-Key value. The IV is embedded in the data, so
        /// <paramref name="iv"/> is ignored. Returns an empty array on failure.
        /// </summary>
        public byte[] DecryptData(byte[] encryptedData, string key, string iv)
        {
            return DecryptVaultixData(encryptedData, key) ?? Array.Empty<byte>();
        }

        // =====================================================================
        // Private: downloads
        // =====================================================================

        private static string FileDownloadEndpoint(string productId, string fileName) =>
            "/files/download/" + UrlEncode(fileName) + "?productId=" + UrlEncode(productId);

        private static string FolderDownloadEndpoint(string productId, string folderName) =>
            "/folders/download/" + UrlEncode(folderName) + "?productId=" + UrlEncode(productId);

        private static Dictionary<string, string> ProductHeader(string productId) =>
            new() { ["X-Product-ID"] = productId };

        private async Task<bool> FolderExistsAsync(string productId, string folderName)
        {
            FolderInfo? folder = await GetFolderInfoAsync(productId, folderName).ConfigureAwait(false);
            if (folder != null && folder.Id.Length > 0) return true;
            if (_lastError.Length == 0 || _lastError.StartsWith("HTTP Error 404", StringComparison.Ordinal))
            {
                _lastError = "Folder not found: " + folderName;
            }
            return false;
        }

        // The decrypted body of a download that did not come as a zk1 delivery.
        private byte[]? LegacyDownloadBody(Exchange? exchange, string what, string emptyMessage)
        {
            if (exchange == null || exchange.Body.Length == 0)
            {
                if (_lastError.Length == 0) _lastError = emptyMessage;
                return null;
            }
            // Vaultix always encrypts downloads. Never hand out a body that arrived
            // without an encryption key (the IV is embedded in the data).
            if (!exchange.Headers.TryGetValue("x-encryption-key", out string? key) || key.Length == 0)
            {
                _lastError = $"Missing encryption key in response headers; refusing unencrypted {what} data";
                return null;
            }
            byte[]? plain = DecryptVaultixData(exchange.Body, key);
            if (plain == null)
            {
                _lastError = $"Failed to decrypt {what}: " + _lastError;
                return null;
            }
            _lastError = "";
            return plain;
        }

        private bool WriteVerifiedFile(string outputPath, byte[] data)
        {
            string partPath = outputPath + ".vxpart";
            try
            {
                File.WriteAllBytes(partPath, data);
                File.Move(partPath, outputPath, true);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                TryDelete(partPath);
                _lastError = "Failed to save the file to " + outputPath;
                return false;
            }
        }

        private byte[]? DecryptVaultixData(byte[] encryptedData, string key)
        {
            byte[] salt;
            int offset;
            if (encryptedData.Length >= 44)
            {
                salt = encryptedData.AsSpan(0, 16).ToArray();
                offset = 16;
            }
            else if (encryptedData.Length >= 28)
            {
                // LEGACY_ENCRYPTION_SALT of the server (17 bytes)
                salt = Encoding.ASCII.GetBytes("vaultix_salt_2024");
                offset = 0;
            }
            else
            {
                _lastError = "Invalid encrypted data size for AES-GCM";
                return null;
            }
            ReadOnlySpan<byte> nonce = encryptedData.AsSpan(offset, 12);
            ReadOnlySpan<byte> tag = encryptedData.AsSpan(offset + 12, 16);
            ReadOnlySpan<byte> ciphertext = encryptedData.AsSpan(offset + 28);
            byte[] derived = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(key ?? ""), salt, 100000, HashAlgorithmName.SHA256, 32);
            byte[] plain = new byte[ciphertext.Length];
            try
            {
                using var gcm = new AesGcm(derived, 16);
                gcm.Decrypt(nonce, ciphertext, tag, plain);
                return plain;
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plain);
                _lastError = "Failed to finalize decryption (authentication failed)";
                return null;
            }
            catch (PlatformNotSupportedException)
            {
                _lastError = "AES-256-GCM is not supported on this platform";
                return null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derived);
            }
        }

        private enum Zk1Target { Memory, File, Variables }

        private enum Zk1State { Idle, Active, Done, Failed }

        // One download that may arrive as a zk1 delivery. RequestAsync() decides
        // when the headers are in: X-Encryption-Key "zk1d." -> check the
        // signature (mandatory, also with SetRequireSignedResponses(false)), then
        // decrypt while streaming; anything else stays on the legacy path.
        private sealed class Zk1Download : IDisposable
        {
            public readonly Zk1Target Target;
            public readonly string Kind;        // "file", "folder" or "vars"
            public readonly string Name;        // the name that was asked for (seal context)
            public readonly string ProductId;   // the product asked for: seal scope; vars: the delivery's object id
            public readonly string OutputPath;
            public Zk1State State = Zk1State.Idle;
            public string Error = "";
            public string StoreError = "";
            public bool Rejected;               // the signature check failed
            public readonly byte[] ClientSecret = new byte[32];
            public bool HaveClientKey;
            public Zk1.DeliveryOpener? Opener;
            public string? PartPath;            // "<outputPath>.vxpart" while the file is unverified
            public FileStream? Part;
            public byte[]? Memory;
            public int MemoryLength;
            public List<KeyValuePair<string, string>> Variables = new();

            public Zk1Download(Zk1Target target, string kind, string name, string productId, string outputPath)
            {
                Target = target;
                Kind = kind;
                Name = name ?? "";
                ProductId = productId ?? "";
                OutputPath = outputPath ?? "";
            }

            public bool IsDelivery => State is Zk1State.Active or Zk1State.Done or Zk1State.Failed;
            public bool Succeeded => State == Zk1State.Done;

            public static string Failure(string detail) => "End-to-end encrypted download failed: " + detail;

            public void Reset()
            {
                Discard();
                State = Zk1State.Idle;
                Error = "";
                StoreError = "";
                Rejected = false;
                CryptographicOperations.ZeroMemory(ClientSecret);
                HaveClientKey = false;
            }

            public bool Fail(string message)
            {
                if (State != Zk1State.Failed && Error.Length == 0) Error = message;
                State = Zk1State.Failed;
                Discard();
                return false;
            }

            // Drop every result and the partial file.
            public void Discard()
            {
                Opener?.Dispose();
                Opener = null;
                if (Memory != null) CryptographicOperations.ZeroMemory(Memory);
                Memory = null;
                MemoryLength = 0;
                Variables.Clear();
                if (Part != null)
                {
                    try { Part.Dispose(); } catch (IOException) { }
                    Part = null;
                }
                if (PartPath != null)
                {
                    TryDelete(PartPath);
                    PartPath = null;
                }
            }

            // A fresh X25519 key for this request; the value of X-Vaultix-Eph.
            public string PrepareRequest()
            {
                byte[] clientPublic = new byte[32];
                Zk1.X25519Generate(ClientSecret, clientPublic);
                HaveClientKey = true;
                return Zk1.B64uEncode(clientPublic);
            }

            // Decrypted content (not yet verified as a whole).
            public bool Store(ReadOnlySpan<byte> data)
            {
                try
                {
                    if (Target == Zk1Target.Memory)
                    {
                        if (Memory == null)
                        {
                            ulong size = Opener?.ContentSize ?? 0;
                            if (size > (ulong)Array.MaxLength)
                            {
                                StoreError = "the file is too large for memory";
                                return false;
                            }
                            // Exact size up front: no reallocation leaves plaintext copies behind.
                            Memory = new byte[(int)size];
                        }
                        if (data.Length > Memory.Length - MemoryLength)
                        {
                            StoreError = Failure("the file is larger than its sealed size");
                            return false;
                        }
                        data.CopyTo(Memory.AsSpan(MemoryLength));
                        MemoryLength += data.Length;
                        return true;
                    }
                    if (Target == Zk1Target.File && Part != null)
                    {
                        Part.Write(data);
                        return true;
                    }
                }
                catch (OutOfMemoryException)
                {
                    StoreError = "not enough memory for the file";
                }
                catch (IOException)
                {
                    StoreError = "Failed to write output file: " + PartPath;
                }
                return false;
            }

            public byte[] TakeMemory()
            {
                byte[] result = Memory ?? Array.Empty<byte>();
                Memory = null;
                MemoryLength = 0;
                return result;
            }

            public void Dispose()
            {
                Discard();
                CryptographicOperations.ZeroMemory(ClientSecret);
            }
        }

        // First byte of a delivery: the headers say "zk1d.".
        private bool Engage(Zk1Download zk1, int status, bool redirected, string method, string pathAndQuery,
                            Dictionary<string, string> lowerHeaders, string nonce)
        {
            zk1.State = Zk1State.Active;
            string reason = "";
            bool verified = false;
            if (redirected)
            {
                reason = "the request was redirected";
            }
            else if (nonce.Length == 0)
            {
                reason = "the request had no nonce";
            }
            else
            {
                verified = VerifyResponseSignatureFields(method, pathAndQuery, status, ResponseSigning.StreamBodyMarker,
                    lowerHeaders, nonce, out reason);
            }
            if (!verified)
            {
                zk1.Rejected = true;
                return zk1.Fail($"Server response could not be verified (HTTP {status}): {reason}");
            }
            if (status != 200) return zk1.Fail(Zk1Download.Failure("unexpected HTTP status " + status));
            if (zk1.Kind != "vars" && _contentKey == null) return zk1.Fail(Zk1.NeedContentKey);
            if (!AesGcm.IsSupported) return zk1.Fail(Zk1Download.Failure("AES-256-GCM is not supported on this platform"));
            // The app id is part of every signed message (from the signed login response).
            if (string.IsNullOrEmpty(_currentSession.AppId)) return zk1.Fail(Zk1Download.Failure("no app id in the session"));
            if (!zk1.HaveClientKey) return zk1.Fail(Zk1Download.Failure("no request key"));
            zk1.Opener = new Zk1.DeliveryOpener(zk1.ClientSecret, zk1.Kind);
            CryptographicOperations.ZeroMemory(zk1.ClientSecret);
            zk1.HaveClientKey = false;
            if (zk1.Kind != "vars")
            {
                zk1.Opener.SetFileContext(_contentKey!.Clone(), _currentSession.AppId, zk1.Name, zk1.ProductId, zk1.Store);
            }
            if (!zk1.Opener.Begin(lowerHeaders["x-encryption-key"])) return zk1.Fail(Zk1Download.Failure(zk1.Opener.Error));
            if (zk1.Kind == "vars" && zk1.Opener.ObjectId != zk1.ProductId)
            {
                return zk1.Fail(Zk1Download.Failure("the variables delivery is for another product"));
            }
            if (zk1.Target == Zk1Target.File)
            {
                zk1.PartPath = zk1.OutputPath + ".vxpart";
                try
                {
                    zk1.Part = new FileStream(zk1.PartPath, FileMode.Create, FileAccess.Write, FileShare.None);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
                {
                    return zk1.Fail("Failed to open output file: " + zk1.PartPath);
                }
            }
            return true;
        }

        // End of the body: the whole delivery must authenticate.
        private bool FinishDelivery(Zk1Download zk1)
        {
            if (zk1.State != Zk1State.Active) return zk1.State == Zk1State.Done;
            Zk1.DeliveryOpener opener = zk1.Opener!;
            if (!opener.Finish())
            {
                return zk1.Fail(zk1.StoreError.Length > 0 ? zk1.StoreError : Zk1Download.Failure(opener.Error));
            }
            if (zk1.Target == Zk1Target.File)
            {
                try
                {
                    zk1.Part!.Flush(true);
                    zk1.Part.Dispose();
                    zk1.Part = null;
                }
                catch (IOException)
                {
                    return zk1.Fail("Failed to write output file: " + zk1.PartPath);
                }
                try
                {
                    File.Move(zk1.PartPath!, zk1.OutputPath, true);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    return zk1.Fail("Failed to save the file to " + zk1.OutputPath);
                }
                zk1.PartPath = null;
            }
            else if (zk1.Target == Zk1Target.Variables)
            {
                if (!Zk1.OpenVariables(opener.VarsPayload, _contentKey, _currentSession.AppId, zk1.ProductId,
                        out List<KeyValuePair<string, string>> variables, out string reason))
                {
                    return zk1.Fail(reason == Zk1.NeedContentKey ? reason : Zk1Download.Failure(reason));
                }
                zk1.Variables = variables;
            }
            if (zk1.Kind != "vars") _lastSignedAt = (long)opener.SignedAt;
            if (zk1.Kind == "file")
            {
                // verified and fully decrypted: IsValidFileHashAsync never sends its plain hash
                _verifiedZk1Files.Add((zk1.ProductId, zk1.Name));
            }
            opener.Dispose();
            zk1.Opener = null;
            zk1.State = Zk1State.Done;
            return true;
        }

        // =====================================================================
        // Private: HTTP
        // =====================================================================

        private sealed class Exchange
        {
            public int Status;
            public byte[] Body = Array.Empty<byte>();
            public Dictionary<string, string> Headers = new(StringComparer.Ordinal);   // lower-case names
            public string Text => Encoding.UTF8.GetString(Body);
        }

        private string ActiveApiKey() =>
            !string.IsNullOrEmpty(_apiKey) ? _apiKey! : _currentSession.AppApiKey ?? "";

        private async Task<bool> RequireSessionAsync()
        {
            if (!_currentSession.IsValid)
            {
                _lastError = "No valid session";
                return false;
            }
            if (await IsTokenExpiredAsync().ConfigureAwait(false) && !await RefreshTokenAsync().ConfigureAwait(false))
            {
                _lastError = "Token expired and refresh failed";
                return false;
            }
            return true;
        }

        // Body text of a successful, verified response; null on any failure
        // (GetLastError() says why).
        private async Task<string?> PerformRequestAsync(string endpoint, string method, string? body = null,
                                                        IReadOnlyDictionary<string, string>? headers = null,
                                                        bool apiKeyAuth = false)
        {
            Exchange? exchange = await RequestAsync(endpoint, method, body, headers, apiKeyAuth, null).ConfigureAwait(false);
            return exchange?.Text;
        }

        private async Task<Exchange?> RequestAsync(string endpoint, string method, string? body,
                                                   IReadOnlyDictionary<string, string>? headers, bool apiKeyAuth,
                                                   Zk1Download? zk1)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(VaultixClient));
            _lastResponseRejected = false;
            _lastError = "";
            zk1?.Reset();

            string sentMethod = method == "POST" || method == "PUT" || method == "DELETE" ? method : "GET";
            if (!Uri.TryCreate(_baseUrl + endpoint, UriKind.Absolute, out Uri? requestUri))
            {
                _lastError = "Invalid URL";
                return null;
            }
            using var request = new HttpRequestMessage(new HttpMethod(sentMethod), requestUri)
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
            };
            request.Headers.TryAddWithoutValidation("User-Agent", "VaultixSDK-CSharp/" + SdkVersion);

            // Fresh nonce per request: Vaultix signs the response over it, so a
            // response can only ever be valid for this one request. zk1
            // deliveries are always verified, so downloads always send one.
            string nonce = "";
            if (_requireSignedResponses || zk1 != null)
            {
                nonce = ResponseSigning.GenerateNonce();
                request.Headers.TryAddWithoutValidation("X-Vaultix-Nonce", nonce);
            }
            // End-to-end encryption: a fresh one-time X25519 key per request.
            if (zk1 != null) request.Headers.TryAddWithoutValidation("X-Vaultix-Eph", zk1.PrepareRequest());

            string payload = body ?? "";
            if (_requestSigningEnabled && !string.IsNullOrEmpty(_requestSigningKey))
            {
                string timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
                byte[] mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(_requestSigningKey),
                    Encoding.UTF8.GetBytes(method + "|" + endpoint + "|" + payload + "|" + timestamp));
                request.Headers.TryAddWithoutValidation("X-Request-Timestamp", timestamp);
                request.Headers.TryAddWithoutValidation("X-Request-Signature", Convert.ToHexString(mac).ToLowerInvariant());
            }

            string apiKey = ActiveApiKey();
            if (!apiKeyAuth && _currentSession.IsValid && !string.IsNullOrEmpty(_currentSession.SessionToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _currentSession.SessionToken);
            }
            else if (apiKey.Length > 0)
            {
                request.Headers.TryAddWithoutValidation("X-API-Key", apiKey);
            }
            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers.Remove(header.Key);
                    request.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }
            if (sentMethod == "POST" || sentMethod == "PUT")
            {
                var content = new ByteArrayContent(Encoding.UTF8.GetBytes(payload));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                request.Content = content;
            }

            Log($"{sentMethod} {requestUri.GetLeftPart(UriPartial.Path)}" + (payload.Length > 0 ? $" ({payload.Length} bytes, not shown)" : ""));

            HttpResponseMessage response;
            try
            {
                response = await Http.SendAsync(request,
                    zk1 != null ? HttpCompletionOption.ResponseHeadersRead : HttpCompletionOption.ResponseContentRead)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (IsNetworkError(ex))
            {
                _lastError = "Network error: " + DescribeNetworkError(ex);
                Log(_lastError);
                return null;
            }

            using (response)
            {
                int status = (int)response.StatusCode;
                Dictionary<string, string> lowerHeaders = CollectHeaders(response);
                Uri effectiveUri = response.RequestMessage?.RequestUri ?? requestUri;
                bool redirected = !string.Equals(effectiveUri.AbsoluteUri, requestUri.AbsoluteUri, StringComparison.Ordinal);
                string pathAndQuery = ResponseSigning.PathAndQuery(effectiveUri);
                Log($"Response: HTTP {status}");

                // zk1 delivery: check the signature, then decrypt while it streams.
                if (zk1 != null && lowerHeaders.TryGetValue("x-encryption-key", out string? encryptionKey) &&
                    encryptionKey.StartsWith(Zk1.DeliveryHeaderPrefix, StringComparison.Ordinal))
                {
                    if (Engage(zk1, status, redirected, sentMethod, pathAndQuery, lowerHeaders, nonce))
                    {
                        byte[] buffer = new byte[81920];
                        try
                        {
                            using Stream stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                            int read;
                            while (zk1.State == Zk1State.Active &&
                                   (read = await stream.ReadAsync(buffer.AsMemory()).ConfigureAwait(false)) > 0)
                            {
                                if (!zk1.Opener!.Update(buffer.AsSpan(0, read)))
                                {
                                    zk1.Fail(zk1.StoreError.Length > 0 ? zk1.StoreError : Zk1Download.Failure(zk1.Opener.Error));
                                }
                            }
                            if (zk1.State == Zk1State.Active) FinishDelivery(zk1);
                        }
                        catch (Exception ex) when (IsNetworkError(ex))
                        {
                            zk1.Fail("Network error: " + DescribeNetworkError(ex));
                        }
                    }
                    _lastResponseRejected = zk1.Rejected;
                    _lastError = zk1.Succeeded ? "" : zk1.Error;
                    Log(zk1.Succeeded ? $"End-to-end encrypted {zk1.Kind} delivery verified and decrypted" : _lastError);
                    return null;
                }

                byte[] bodyBytes;
                try
                {
                    bodyBytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (IsNetworkError(ex))
                {
                    _lastError = "Network error: " + DescribeNetworkError(ex);
                    return null;
                }

                // Verify that the response really comes from Vaultix and answers
                // exactly this request, before anything in it is used (status
                // codes and error bodies included).
                if (_requireSignedResponses)
                {
                    string reason = "the request was redirected";
                    bool verified = !redirected && VerifyResponseSignatureFields(sentMethod, pathAndQuery, status,
                        ResponseSigning.Sha256Hex(bodyBytes), lowerHeaders, nonce, out reason);
                    if (!verified)
                    {
                        _lastError = $"Server response could not be verified (HTTP {status}): {reason}";
                        _lastResponseRejected = true;
                        Log(_lastError);
                        return null;
                    }
                    Log("Response signature verified");
                }

                if (status >= 400)
                {
                    string text = Encoding.UTF8.GetString(bodyBytes);
                    _lastError = $"HTTP Error {status}: {text}";
                    if (lowerHeaders.TryGetValue("x-debug-info", out string? debugInfo)) _lastError += $" [Debug: {debugInfo}]";
                    if (zk1 != null && status == 409 && ParseJson(text) is JObject error &&
                        Str(error, "code") == "e2ee_sdk_update_required")
                    {
                        _lastError = _contentKey == null
                            ? Zk1.NeedContentKey + " (HTTP 409 e2ee_sdk_update_required)"
                            : Zk1Download.Failure("the server did not receive the one-time request key X-Vaultix-Eph " +
                                                  "(HTTP 409 e2ee_sdk_update_required); a proxy may have removed it");
                    }
                    Log(_lastError.Length > 200 ? _lastError.Substring(0, 200) : _lastError);
                    return null;
                }
                return new Exchange { Status = status, Body = bodyBytes, Headers = lowerHeaders };
            }
        }

        // Response headers with lower-case names, raw values with surrounding
        // spaces/tabs removed; when a header occurs more than once the last value counts.
        private static Dictionary<string, string> CollectHeaders(HttpResponseMessage response)
        {
            var headers = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var header in response.Headers.NonValidated) headers[header.Key.ToLowerInvariant()] = LastValue(header.Value);
            foreach (var header in response.Content.Headers.NonValidated) headers[header.Key.ToLowerInvariant()] = LastValue(header.Value);
            return headers;
        }

        private static string LastValue(HeaderStringValues values)
        {
            string last = "";
            foreach (string value in values) last = value;
            return last.Trim(' ', '\t');
        }

        // vaultix-resp-v1 check of one response (bodyHashField is the body's
        // SHA-256 hex, or "zk1-stream" for zk1 deliveries).
        internal bool VerifyResponseSignatureFields(string method, string pathAndQuery, int statusCode, string bodyHashField,
                                                    IReadOnlyDictionary<string, string> lowerHeaders, string nonce,
                                                    out string failureReason)
        {
            string Header(string name) => lowerHeaders.TryGetValue(name, out string? value) ? value : "";
            string signature = Header("x-vaultix-signature");
            string keyId = Header("x-vaultix-key-id");
            string signedAt = Header("x-vaultix-signed-at");
            if (signature.Length == 0 || keyId.Length == 0 || signedAt.Length == 0)
            {
                failureReason = "the response is not signed";
                return false;
            }
            byte[]? publicKey = TrustedPublicKey(keyId);
            if (publicKey == null)
            {
                failureReason = "unknown signing key '" + ResponseSigning.Printable(keyId) + "'";
                return false;
            }
            if (signedAt.Length > 12 || !signedAt.All(char.IsAsciiDigit))
            {
                failureReason = "invalid signing time";
                return false;
            }
            string? canonical = ResponseSigning.Canonical(keyId, nonce, signedAt, method, pathAndQuery,
                statusCode.ToString(System.Globalization.CultureInfo.InvariantCulture), bodyHashField,
                Header("x-encryption-key"), Header("x-encryption-iv"), Header("content-type"));
            if (canonical == null || !ResponseSigning.VerifyEd25519(publicKey, canonical, signature))
            {
                failureReason = "invalid signature (the response was altered, replayed, or does not come from Vaultix)";
                return false;
            }
            long skew = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - long.Parse(signedAt, System.Globalization.CultureInfo.InvariantCulture));
            if (skew > _responseClockSkewSeconds)
            {
                failureReason = $"the signature time differs from this computer's clock by {skew} seconds (check the system date and time)";
                return false;
            }
            failureReason = "";
            return true;
        }

        private byte[]? TrustedPublicKey(string keyId)
        {
            foreach (var key in ResponseSigning.TrustedResponseKeys)
            {
                if (key.KeyId == keyId) return Convert.FromHexString(key.PublicKeyHex);
            }
            foreach (var key in _testingResponseKeys)
            {
                if (key.KeyId == keyId) return key.PublicKey;
            }
            return null;
        }

        private static bool IsNetworkError(Exception ex) =>
            ex is HttpRequestException or IOException or OperationCanceledException or AuthenticationException;

        private static string DescribeNetworkError(Exception ex) =>
            ex is OperationCanceledException ? "the request timed out" : ex.Message;

        private HttpClient Http
        {
            get
            {
                if (_httpClient == null)
                {
                    SslProtocols protocols = _minTlsVersion == "1.3" ? SslProtocols.Tls13
                        : _minTlsVersion == "1.2" ? SslProtocols.Tls12 | SslProtocols.Tls13
                        : SslProtocols.None;
                    var handler = new SocketsHttpHandler
                    {
                        AllowAutoRedirect = true,
                        AutomaticDecompression = DecompressionMethods.None,
                        UseCookies = false,
                        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                        SslOptions = new SslClientAuthenticationOptions
                        {
                            EnabledSslProtocols = protocols,
                            RemoteCertificateValidationCallback = ValidateServerCertificate,
                        },
                    };
                    _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
                }
                return _httpClient;
            }
        }

        private void ResetHttpClient()
        {
            _httpClient?.Dispose();
            _httpClient = null;
        }

        private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            if (_sslVerify && errors != SslPolicyErrors.None) return false;
            if (!_certificatePinningEnabled || _pinnedCertificates.Count == 0) return true;
            if (certificate == null) return false;
            using var leaf = new X509Certificate2(certificate);
            byte[] spkiHash = SHA256.HashData(leaf.PublicKey.ExportSubjectPublicKeyInfo());
            string hex = Convert.ToHexString(spkiHash);
            string base64 = "sha256/" + Convert.ToBase64String(spkiHash);
            foreach (string pin in _pinnedCertificates)
            {
                if (string.Equals(pin, hex, StringComparison.OrdinalIgnoreCase) || string.Equals(pin, base64, StringComparison.Ordinal))
                {
                    Log("Certificate pin matched");
                    return true;
                }
            }
            Log("Certificate pinning failed - no matching certificate found");
            return false;
        }

        // =====================================================================
        // Private: session, JSON and storage helpers
        // =====================================================================

        private bool CompleteLogin(string response, string hwid, string apiKey, string? username, string? key, bool autoLogin)
        {
            if (ParseJson(response) is not JObject json)
            {
                _lastError = autoLogin ? "Failed to parse auto-login response" : "Failed to parse authentication response";
                return false;
            }
            string accessToken = Str(json, "access_token");
            if (accessToken.Length == 0)
            {
                _lastError = "No access token received";
                return false;
            }
            if (Bool(json, "safetyEnabled", false))
            {
                _lastError = "This app requires Safety (approved builds), which only the Vaultix C++ SDK supports";
                return false;
            }
            var session = new Session
            {
                IsValid = true,
                SessionToken = accessToken,
                SessionId = Str(json, "sessionId"),
                AppId = Str(json, "appId"),
                TokenExpiry = Str(json, "expiresAt"),
                Hwid = hwid,
                AppApiKey = apiKey,
            };
            session.AppUser = new AppUser
            {
                Id = Str(json, "appUserId"),
                AppId = session.AppId,
                Username = username,
                Key = key,
            };
            if (json["subscriptions"] is JArray subscriptions)
            {
                foreach (JToken subscription in subscriptions)
                {
                    if (subscription.Type == JTokenType.String) session.AppUser.Subscriptions.Add(subscription.Value<string>()!);
                }
            }
            _currentSession = session;

            string persistentToken = Str(json, "persistentToken");
            if (persistentToken.Length > 0)
            {
                SavePersistentToken(persistentToken, apiKey);
                Log("Auto-login token saved");
            }
            return true;
        }

        private static FileInfo ParseFileInfo(JObject item) => new FileInfo
        {
            Id = Str(item, "id"),
            Name = Str(item, "name"),
            AppId = Str(item, "appId"),
            Size = Long(item, "size"),
            Encrypted = Bool(item, "encrypted", true),
            EncryptionKey = StrOrNull(item, "encryptionKey"),
            EncryptionIV = StrOrNull(item, "encryptionIV"),
            Enc = StrOrNull(item, "enc"),
            Downloads = (int)Long(item, "downloads"),
            UploadedAt = Str(item, "uploadedAt"),
        };

        private static FolderInfo ParseFolderInfo(JObject item) => new FolderInfo
        {
            Id = Str(item, "id"),
            Name = Str(item, "name"),
            AppId = Str(item, "appId"),
            TotalSize = ParseSize(item["totalSize"]),
            FileCount = (int)Long(item, "fileCount"),
            Downloads = (int)Long(item, "downloads"),
            UploadedAt = Str(item, "uploadedAt"),
        };

        // A byte count, or a formatted size such as "25.5 MB" (what the server sends for folders).
        private static long ParseSize(JToken? token)
        {
            if (token == null || token.Type == JTokenType.Null) return 0;
            if (token.Type == JTokenType.Integer) return token.Value<long>();
            string text = token.ToString().Trim();
            string[] parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0 || !double.TryParse(parts[0], System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out double number))
            {
                return 0;
            }
            string unit = parts.Length > 1 ? parts[1].ToUpperInvariant() : "B";
            double factor = unit switch
            {
                "KB" => 1024d,
                "MB" => 1024d * 1024,
                "GB" => 1024d * 1024 * 1024,
                "TB" => 1024d * 1024 * 1024 * 1024,
                _ => 1d,
            };
            return (long)(number * factor);
        }

        internal static JToken? ParseJson(string text)
        {
            try
            {
                using var reader = new JsonTextReader(new StringReader(text))
                {
                    DateParseHandling = DateParseHandling.None,
                    FloatParseHandling = FloatParseHandling.Decimal,
                    MaxDepth = 64,
                };
                JToken token = JToken.ReadFrom(reader);
                while (reader.Read())
                {
                    if (reader.TokenType != JsonToken.Comment) return null;
                }
                return token;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static string Str(JObject item, string name)
        {
            JToken? token = item[name];
            if (token == null || token.Type == JTokenType.Null) return "";
            return token.Type == JTokenType.String ? token.Value<string>() ?? "" : token.ToString(Formatting.None);
        }

        private static string? StrOrNull(JObject item, string name)
        {
            JToken? token = item[name];
            return token == null || token.Type == JTokenType.Null ? null : Str(item, name);
        }

        private static long Long(JObject item, string name)
        {
            JToken? token = item[name];
            if (token == null) return 0;
            if (token.Type == JTokenType.Integer) return token.Value<long>();
            if (token.Type == JTokenType.Float) return (long)token.Value<double>();
            return long.TryParse(token.ToString(), out long value) ? value : 0;
        }

        private static bool Bool(JObject item, string name, bool fallback)
        {
            JToken? token = item[name];
            if (token == null || token.Type == JTokenType.Null) return fallback;
            if (token.Type == JTokenType.Boolean) return token.Value<bool>();
            return token.Type == JTokenType.String ? token.Value<string>() == "true" : fallback;
        }

        // Like the C++ urlEncode: unreserved characters stay, every other UTF-8 byte is %XX.
        private static string UrlEncode(string value)
        {
            var encoded = new StringBuilder();
            foreach (byte b in Encoding.UTF8.GetBytes(value ?? ""))
            {
                char c = (char)b;
                if (b < 0x80 && (char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == '~'))
                {
                    encoded.Append(c);
                }
                else
                {
                    encoded.Append('%').Append("0123456789ABCDEF"[b >> 4]).Append("0123456789ABCDEF"[b & 0x0F]);
                }
            }
            return encoded.ToString();
        }

        private static void CreateParentDirectory(string path)
        {
            string? directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory)) Directory.CreateDirectory(directory);
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // nothing more to do
            }
        }

        private static string GetHwid()
        {
            // A hardware ID from the machine and user name
            var machineInfo = $"{Environment.MachineName}-{Environment.UserName}";
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(machineInfo)));
        }

        // Auto-login tokens: one file per app (named after a hash of the app API
        // key) in the user's application data folder. Obfuscated, not encrypted.
        private string PersistentTokenPath(string apiKey)
        {
            string id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(apiKey))).Substring(0, 16).ToLowerInvariant();
            return Path.Combine(_persistentTokenDirectory, "autologin_" + id + ".dat");
        }

        private void SavePersistentToken(string token, string apiKey)
        {
            if (token.Length == 0 || apiKey.Length == 0) return;
            try
            {
                if (!Directory.Exists(_persistentTokenDirectory))
                {
                    Directory.CreateDirectory(_persistentTokenDirectory);
                    if (!OperatingSystem.IsWindows())
                    {
                        File.SetUnixFileMode(_persistentTokenDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                    }
                }
                string path = PersistentTokenPath(apiKey);
                File.WriteAllText(path, Obfuscate(token));
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log("Failed to save the auto-login token");
            }
        }

        private string? LoadPersistentToken(string apiKey)
        {
            try
            {
                string path = PersistentTokenPath(apiKey);
                return File.Exists(path) ? Deobfuscate(File.ReadAllText(path)) : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        private void DeletePersistentToken(string apiKey) => TryDelete(PersistentTokenPath(apiKey));

        private static string Obfuscate(string input)
        {
            string Garbage() => Zk1.B64uEncode(RandomNumberGenerator.GetBytes(RandomNumberGenerator.GetInt32(8, 40)));
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(Garbage() + "|" + input + "|" + Garbage()));
        }

        private static string? Deobfuscate(string obfuscated)
        {
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(obfuscated.Trim()));
                int first = decoded.IndexOf('|');
                int last = decoded.LastIndexOf('|');
                return first >= 0 && last > first ? decoded.Substring(first + 1, last - first - 1) : null;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        private void Log(string message)
        {
            if (_debugMode)
            {
                Console.WriteLine($"[VaultixSDK] {message}");
            }
        }

        /// <summary>
        /// Zero the content key and release the HTTP connections
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            ClearContentKey();
            _testingResponseKeys.Clear();
            _httpClient?.Dispose();
            _httpClient = null;
            GC.SuppressFinalize(this);
        }
    }
}
