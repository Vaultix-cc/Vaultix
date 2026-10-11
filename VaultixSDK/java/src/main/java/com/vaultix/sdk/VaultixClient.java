package com.vaultix.sdk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Client for the Vaultix API: sign-in with a license key or username and
 * password, end-to-end encrypted file, folder and variable delivery, product
 * status and news.
 *
 * <p><b>Signed responses.</b> Every request carries a fresh random
 * {@code X-Vaultix-Nonce}. Vaultix signs each response (Ed25519) over that
 * nonce, the method, path and query that were sent, the status code, a SHA-256
 * of the full body, the file encryption headers and the Content-Type. The SDK
 * checks that signature with the Vaultix public key built into this SDK, so a
 * fake server (DNS redirect, locally trusted CA, proxy) cannot answer "login
 * OK", hand out files, or replay an old response. A response that fails the
 * check makes the call fail; {@link #getLastError()} then starts with
 * "Server response could not be verified".
 *
 * <p><b>End-to-end encryption.</b> Apps with end-to-end encryption need the
 * content key ({@code vxk_...}, App Settings), see {@link #setContentKey}.
 * Every download and variables request then carries a fresh one-time X25519
 * key; the response is decrypted while it streams, the uploader's signature
 * is checked against the app signing key in the content key, and the content
 * is checked against its sealed size and SHA-256. Any failure returns nothing.
 *
 * <p>A {@code VaultixClient} is not thread-safe: use one per thread or
 * synchronize calls yourself.
 */
public class VaultixClient implements AutoCloseable {

    private static final String DEFAULT_BASE_URL = "https://vaultix.cc/api";
    private static final String USER_AGENT = "VaultixSDK-Java/2.0.0";
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 600;
    private static final int TIMEOUT_SECONDS = 30;
    private static final int READ_BUFFER_BYTES = 64 * 1024;
    private static final int STREAM_CHUNK_BYTES = 4096;
    private static final byte[] EMPTY = new byte[0];
    private static final byte[] LEGACY_SALT = "vaultix_salt_2024".getBytes(StandardCharsets.US_ASCII);
    private static final String SAFETY_UNSUPPORTED =
            "This app requires approved-build checks (Safety), which only the C++ SDK supports";

    private String baseUrl;
    private String apiKey;
    private Session currentSession;
    private boolean debugMode;
    private boolean sslVerify = true;
    private boolean certificatePinningEnabled;
    private List<String> pinnedCertificates = new ArrayList<>();
    private String minTlsVersion = "1.2";
    private boolean requestSigningEnabled;
    private String requestSigningKey;
    private String lastError = "";
    private final Path tokenDirectory;
    private HttpClient httpClient;
    private boolean httpClientStale = true;
    private final SecureRandom random = new SecureRandom();

    private boolean requireSignedResponses = true;
    private long responseClockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
    private boolean lastResponseRejected;
    private String testingResponseKeyId;
    private byte[] testingResponsePublicKey;

    private Zk1.ContentKey contentKey;  // memory only, see setContentKey()
    private long lastSignedAt;           // see getLastSignedAt()
    // (productId, fileName) this client received as verified zk1 files;
    // isValidFileHash never sends their plain hash. Cleared by
    // clearContentKey() and endSession().
    private final Set<String> verifiedZk1Files = new HashSet<>();

    /** Receives a downloaded file in chunks, see {@link #streamFile}. */
    @FunctionalInterface
    public interface StreamCallback {
        void onChunk(byte[] chunk, long received, long total);
    }

    /**
     * Initialize a new Vaultix client.
     *
     * @param baseUrl the API base URL, normally {@code https://vaultix.cc/api}
     */
    public VaultixClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.currentSession = new Session();
        this.tokenDirectory = Paths.get(System.getProperty("user.home"), ".vaultix");
    }

    public VaultixClient() {
        this(DEFAULT_BASE_URL);
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    /** The app API key ({@code ap_...}); only needed to sign in. */
    public void setApiKey(String key) {
        this.apiKey = key;
    }

    public void clearApiKey() {
        this.apiKey = null;
    }

    public boolean isDebugMode() { return debugMode; }

    /** Debug output never shows credentials, keys, tokens or request bodies. */
    public void setDebugMode(boolean debugMode) { this.debugMode = debugMode; }

    public boolean isSslVerify() { return sslVerify; }

    /** Turning TLS certificate checks off is for local testing only. */
    public void setSslVerify(boolean sslVerify) {
        this.sslVerify = sslVerify;
        httpClientStale = true;
    }

    /**
     * Requires the server certificate's public key to match one of these
     * SHA-256 hashes (hex, of the DER SubjectPublicKeyInfo), in addition to
     * the normal certificate checks.
     */
    public void enableCertificatePinning(List<String> certHashes) {
        this.certificatePinningEnabled = true;
        this.pinnedCertificates = certHashes == null ? new ArrayList<>() : new ArrayList<>(certHashes);
        httpClientStale = true;
    }

    public void disableCertificatePinning() {
        this.certificatePinningEnabled = false;
        httpClientStale = true;
    }

    /** "1.2" (default) or "1.3". */
    public void setMinTlsVersion(String version) {
        this.minTlsVersion = version;
        httpClientStale = true;
    }

    /** Adds X-Request-Timestamp and X-Request-Signature (HMAC-SHA256) to every request. */
    public void enableRequestSigning(String signingKey) {
        this.requestSigningEnabled = true;
        this.requestSigningKey = signingKey;
    }

    public void disableRequestSigning() {
        this.requestSigningEnabled = false;
    }

    /**
     * Response verification is on by default (see the class description).
     * Turning it off is ONLY for local testing against your own test server;
     * never ship a build with {@code setRequireSignedResponses(false)}.
     * End-to-end encrypted deliveries are always verified.
     */
    public void setRequireSignedResponses(boolean require) {
        this.requireSignedResponses = require;
    }

    public boolean getRequireSignedResponses() {
        return requireSignedResponses;
    }

    /**
     * Allowed difference between this computer's clock and the server's
     * signing time, in seconds (default 600 = +/-10 minutes). Values &lt;= 0
     * restore the default. The per-request nonce already stops replays; raise
     * this if your users have badly wrong system clocks.
     */
    public void setResponseClockSkewTolerance(long seconds) {
        this.responseClockSkewSeconds = seconds > 0 ? seconds : DEFAULT_CLOCK_SKEW_SECONDS;
    }

    /**
     * TESTING ONLY. Trusts one extra response-signing key in addition to the
     * Vaultix keys built into this SDK, for tests against a Vaultix test
     * backend that signs with its own throwaway key (the Java counterpart of
     * the C++ build flags VAULTIX_TESTING_EXTRA_RESPONSE_KEY_ID / _HEX).
     *
     * <p><b>Never call this in a build you ship.</b> Whoever holds the private
     * key of a trusted key can answer as Vaultix: fake logins, files and
     * variables of apps without end-to-end encryption.
     *
     * @param keyId        "vx-sig-" + first 16 hex characters of SHA-256(public key)
     * @param publicKeyHex the raw 32-byte Ed25519 public key as 64 hex characters
     * @return false (nothing changed) if the key id does not belong to the key;
     *         both null removes the extra key
     */
    public boolean setTestingExtraResponseKey(String keyId, String publicKeyHex) {
        if (keyId == null && publicKeyHex == null) {
            testingResponseKeyId = null;
            Zk1.wipe(testingResponsePublicKey);
            testingResponsePublicKey = null;
            return true;
        }
        byte[] publicKey = Zk1.fromHex32(publicKeyHex == null ? null : publicKeyHex.trim());
        if (publicKey == null || keyId == null || !ResponseSigning.keyIdFor(publicKey).equals(keyId.trim())) {
            lastError = "Invalid testing response key: the key id must be vx-sig- plus the first 16 hex "
                    + "characters of SHA-256(public key)";
            return false;
        }
        testingResponseKeyId = keyId.trim();
        testingResponsePublicKey = publicKey;
        return true;
    }

    // =========================================================================
    // End-to-end encryption
    // =========================================================================

    /**
     * Apps with end-to-end encryption need the content key ({@code vxk_...},
     * 96 characters, App Settings) to download files, folders and encrypted
     * variables. It holds the key that opens the content and the app's signing
     * key, which approves the team members whose signature every file and
     * value must carry. It is kept in memory only and its bytes are wiped when
     * it is replaced or cleared (the String you pass in cannot be wiped).
     *
     * @return false (current key unchanged) if the key, its version or its
     *         checksum is invalid
     */
    public boolean setContentKey(String vxk) {
        Zk1.ContentKey key = Zk1.ContentKey.fromSdkKey(vxk);
        if (key == null) {
            lastError = "Invalid content key: use the vxk_ key from App Settings (96 characters)";
            return false;
        }
        clearContentKey();
        contentKey = key;
        return true;
    }

    /** Wipes the content key. */
    public void clearContentKey() {
        if (contentKey != null) contentKey.wipe();
        contentKey = null;
        verifiedZk1Files.clear();
    }

    public boolean hasContentKey() {
        return contentKey != null;
    }

    /** "XXXX-XXXX-XXXX-XXXX", must match the fingerprint in App Settings; "" without a key. */
    public String getContentKeyFingerprint() {
        return contentKey == null ? "" : contentKey.fingerprint();
    }

    /**
     * Signing time (Unix milliseconds) of the file or folder returned by the
     * last download call (downloadFile, downloadFileToMemory, streamFile,
     * downloadFolder, downloadFolderToMemory), if it was a verified end-to-end
     * encrypted download; 0 otherwise (failure, legacy file). Vaultix cannot
     * fake content but could serve an older, genuinely signed version: keep
     * the newest value you have seen per file and refuse an older one if that
     * matters to your app.
     */
    public long getLastSignedAt() {
        return lastSignedAt;
    }

    // =========================================================================
    // Authentication
    // =========================================================================

    public boolean authenticateWithUsername(String username, String password) {
        lastError = "";
        String key = activeApiKey();
        if (key.isEmpty()) {
            lastError = "API key not set";
            return false;
        }
        try {
            String hwid = getHwid();
            JsonObject body = new JsonObject();
            body.addProperty("username", nz(username));
            body.addProperty("password", nz(password));
            body.addProperty("hwid", hwid);
            byte[] response = performRequest("/app_auth/login", "POST", body.toString(), apiKeyHeader(key), null, null);
            if (response.length == 0) {
                if (lastError.isEmpty()) lastError = "Empty response from server";
                return false;
            }
            return applyLoginResponse(response, key, hwid, username, null, false);
        } catch (RuntimeException e) {
            lastError = "Authentication failed: " + e.getMessage();
            return false;
        }
    }

    public boolean authenticateWithKey(String userKey) {
        lastError = "";
        String key = activeApiKey();
        if (key.isEmpty()) {
            lastError = "API key not set";
            return false;
        }
        try {
            String hwid = getHwid();
            JsonObject body = new JsonObject();
            body.addProperty("key", nz(userKey));
            body.addProperty("hwid", hwid);
            byte[] response = performRequest("/app_auth/login_key", "POST", body.toString(), apiKeyHeader(key), null, null);
            if (response.length == 0) {
                if (lastError.isEmpty()) lastError = "Empty response from server";
                return false;
            }
            return applyLoginResponse(response, key, hwid, null, userKey, false);
        } catch (RuntimeException e) {
            lastError = "Key authentication failed: " + e.getMessage();
            return false;
        }
    }

    /** Signs in with the persistent token a previous login on this machine saved (if the app allows auto-login). */
    public boolean tryAutoLogin() {
        lastError = "";
        String key = activeApiKey();
        if (key.isEmpty()) {
            lastError = "API key not set";
            return false;
        }
        String savedToken = loadPersistentToken(key);
        if (savedToken == null || savedToken.isEmpty()) {
            lastError = "No saved token found";
            return false;
        }
        try {
            String hwid = getHwid();
            JsonObject body = new JsonObject();
            body.addProperty("token", savedToken);
            body.addProperty("hwid", hwid);
            byte[] response = performRequest("/app_auth/autologin", "POST", body.toString(), apiKeyHeader(key), null, null);
            if (response.length == 0) {
                if (lastError.isEmpty()) lastError = "Empty response from server";
                // An unverifiable response says nothing about the saved token; keep it.
                if (!lastResponseRejected) deletePersistentToken(key);
                return false;
            }
            if (!applyLoginResponse(response, key, hwid, null, null, true)) {
                deletePersistentToken(key);
                return false;
            }
            return true;
        } catch (RuntimeException e) {
            lastError = "Auto-login failed: " + e.getMessage();
            deletePersistentToken(key);
            return false;
        }
    }

    /**
     * Signs in again: with the stored license key in key mode; username and
     * password sessions need the password again.
     */
    public boolean refreshToken() {
        String username = currentSession.getAppUser().getUsername();
        String key = currentSession.getAppUser().getKey();
        if (username != null && !username.isEmpty()) {
            lastError = "Password re-entry required after token expiration";
            return false;
        } else if (key != null && !key.isEmpty()) {
            return authenticateWithKey(key);
        }
        lastError = "No stored credentials for refresh";
        return false;
    }

    /** Ends the current session on the server (does NOT clear the auto-login token). */
    public void endSession() {
        if (currentSession.isValid()) {
            byte[] response = performRequest("/app_auth/logout", "POST", "", null, null, null);
            if (response.length > 0) {
                JsonObject json = parseObject(response);
                if (json != null) {
                    String message = str(json, "message");
                    if (!message.contains("successfully")) {
                        lastError = message.isEmpty() ? "Failed to terminate session" : message;
                    }
                }
            }
        }
        currentSession = new Session();
        verifiedZk1Files.clear();
        log("Session ended");
    }

    /** Revokes the auto-login token on the server and deletes it from this machine. */
    public void clearAutoLoginToken() {
        String key = activeApiKey();
        if (key.isEmpty()) {
            log("No API key available for token lookup");
            return;
        }
        String token = loadPersistentToken(key);
        if (token != null && !token.isEmpty()) {
            JsonObject body = new JsonObject();
            body.addProperty("token", token);
            body.addProperty("hwid", getHwid());
            Map<String, String> headers = apiKeyHeader(key);
            headers.put("Content-Type", "application/json");
            performRequest("/app_auth/clear_autologin", "POST", body.toString(), headers, null, null);
        }
        deletePersistentToken(key);
        log("Auto-login token cleared");
    }

    private boolean applyLoginResponse(byte[] response, String apiKeyUsed, String hwid, String username,
                                       String userKey, boolean autoLogin) {
        JsonObject json = parseObject(response);
        if (json == null) {
            lastError = autoLogin ? "Failed to parse auto-login response" : "Failed to parse authentication response";
            return false;
        }
        String accessToken = str(json, "access_token");
        if (accessToken.isEmpty()) {
            lastError = "No access token received";
            return false;
        }
        if (bool(json, "safetyEnabled", false)) {
            lastError = SAFETY_UNSUPPORTED;
            return false;
        }
        Session session = new Session();
        session.setValid(true);
        session.setSessionToken(accessToken);
        session.setSessionId(str(json, "sessionId"));
        session.setAppId(str(json, "appId"));
        session.setTokenExpiry(str(json, "expiresAt"));
        session.setHwid(hwid);
        AppUser user = new AppUser();
        user.setId(str(json, "appUserId"));
        user.setAppId(session.getAppId());
        user.setUsername(username);
        user.setKey(userKey);
        List<String> subscriptions = new ArrayList<>();
        JsonElement subs = json.get("subscriptions");
        if (subs != null && subs.isJsonArray()) {
            for (JsonElement sub : subs.getAsJsonArray()) {
                if (sub.isJsonPrimitive()) subscriptions.add(sub.getAsString());
            }
        }
        user.setSubscriptions(subscriptions);
        session.setAppUser(user);
        session.setAppApiKey(apiKeyUsed);
        currentSession = session;
        clearApiKey();  // kept in the session for clearAutoLoginToken()

        String persistentToken = str(json, "persistentToken");
        if (!persistentToken.isEmpty()) {
            savePersistentToken(persistentToken, apiKeyUsed);
            log("Persistent auth token saved for auto-login");
        }
        log(autoLogin ? "Auto-login successful" : "Authenticated successfully");
        return true;
    }

    // =========================================================================
    // Session State
    // =========================================================================

    public boolean isSessionValid() {
        return currentSession.isValid();
    }

    public boolean isTokenExpired() {
        return !currentSession.isValid() || currentSession.getTokenExpiry() == null
                || currentSession.getTokenExpiry().isEmpty();
    }

    public Session getCurrentSession() {
        return currentSession;
    }

    /** What went wrong in the last call; "" after a successful download. */
    public String getLastError() {
        return lastError;
    }

    // =========================================================================
    // File Operations
    // =========================================================================

    /**
     * GET /files?productId= (the endpoint the C++ SDK calls; parsed when the
     * server answers with a list).
     */
    public List<FileInfo> getFileList(String productId) {
        List<FileInfo> files = new ArrayList<>();
        lastError = "";
        if (!requireSession()) return files;
        byte[] response = performRequest("/files?productId=" + urlEncode(productId), "GET", "",
                productHeader(productId), null, null);
        if (response.length == 0) return files;
        JsonElement parsed = parseJson(response);
        if (parsed == null || !parsed.isJsonArray()) {
            lastError = "Unexpected file list response";
            return files;
        }
        for (JsonElement element : parsed.getAsJsonArray()) {
            if (element.isJsonObject()) files.add(fileInfoFrom(element.getAsJsonObject()));
        }
        return files;
    }

    /** File metadata, or null on failure. */
    public FileInfo getFileInfo(String productId, String fileName) {
        lastError = "";
        if (!requireSession()) return null;
        byte[] response = performRequest(assetEndpoint("files", "info", fileName, productId), "GET", "",
                productHeader(productId), null, null);
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response from server";
            return null;
        }
        JsonObject json = parseObject(response);
        if (json == null) {
            lastError = "Failed to parse JSON response";
            return null;
        }
        return fileInfoFrom(json);
    }

    /**
     * Downloads a file to disk. End-to-end encrypted files are written to
     * {@code <outputPath>.vxpart} and renamed only after every check passed.
     * Missing parent directories are created.
     */
    public boolean downloadFile(String productId, String fileName, String outputPath) {
        lastSignedAt = 0;
        lastError = "";
        if (!requireSession()) return false;
        if (!prepareOutput(outputPath)) return false;
        Map<String, String> responseHeaders = new HashMap<>();
        Zk1Download zk1 = new Zk1Download(Target.FILE, "file", fileName, productId, outputPath);
        byte[] response = performRequest(assetEndpoint("files", "download", fileName, productId), "GET", "",
                productHeader(productId), responseHeaders, zk1);
        if (zk1.isDelivery()) {
            if (zk1.succeeded()) log("Downloaded file " + fileName + " to " + outputPath);
            return zk1.succeeded();
        }
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response when downloading file";
            return false;
        }
        String encryptionKey = responseHeaders.getOrDefault("x-encryption-key", "");
        if (encryptionKey.isEmpty()) {
            lastError = "Missing encryption key in response headers";
            return false;
        }
        byte[] plain = decryptLegacy(response, encryptionKey);
        if (plain == null) {
            lastError = "Failed to decrypt file: " + lastError;
            return false;
        }
        try {
            Files.write(Paths.get(outputPath), plain);
        } catch (IOException e) {
            lastError = "Failed to open output file: " + outputPath;
            return false;
        } finally {
            Zk1.wipe(plain);
        }
        log("Downloaded file " + fileName + " to " + outputPath);
        return true;
    }

    /**
     * Downloads a file into memory. Returns an empty array on any failure; on
     * success {@link #getLastError()} is "" (so an empty file is not an error).
     */
    public byte[] downloadFileToMemory(String productId, String fileName) {
        lastSignedAt = 0;
        lastError = "";
        if (!requireSession()) return EMPTY;
        Map<String, String> responseHeaders = new HashMap<>();
        Zk1Download zk1 = new Zk1Download(Target.MEMORY, "file", fileName, productId, null);
        byte[] response = performRequest(assetEndpoint("files", "download", fileName, productId), "GET", "",
                productHeader(productId), responseHeaders, zk1);
        if (zk1.isDelivery()) {
            return zk1.succeeded() ? zk1.takeMemory() : EMPTY;
        }
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response when downloading file";
            return EMPTY;
        }
        String encryptionKey = responseHeaders.getOrDefault("x-encryption-key", "");
        if (encryptionKey.isEmpty()) {
            // Vaultix always encrypts downloads. Never hand out a body that
            // arrived without encryption headers.
            lastError = "Missing encryption key in response headers; refusing unencrypted file data";
            return EMPTY;
        }
        byte[] plain = decryptLegacy(response, encryptionKey);
        if (plain == null) {
            lastError = "Failed to decrypt file: " + lastError;
            return EMPTY;
        }
        return plain;
    }

    /**
     * Downloads the whole file (verified like {@link #downloadFileToMemory}),
     * then hands it to the callback in 4 KB chunks. Nothing is passed to the
     * callback before the download verified.
     */
    public boolean streamFile(String productId, String fileName, StreamCallback callback) {
        byte[] data = downloadFileToMemory(productId, fileName);
        if (!lastError.isEmpty()) return false;
        try {
            long total = data.length;
            int processed = 0;
            while (processed < data.length) {
                int size = Math.min(STREAM_CHUNK_BYTES, data.length - processed);
                byte[] chunk = Arrays.copyOfRange(data, processed, processed + size);
                processed += size;
                callback.onChunk(chunk, processed, total);
            }
            return true;
        } catch (RuntimeException e) {
            lastError = "Exception during file streaming: " + e.getMessage();
            return false;
        } finally {
            Zk1.wipe(data);
        }
    }

    /**
     * Checks a local file against the server's hash. With a content key the
     * server compares the keyed hash (HMAC(kh, SHA-256 of the file)); files of
     * apps without end-to-end encryption are then checked once more with the
     * plain SHA-256, except files this client already downloaded as verified
     * end-to-end encrypted files: for those a request for the plain hash
     * returns false.
     */
    public boolean isValidFileHash(String productId, String fileName, String filePath) {
        lastError = "";
        if (!requireSession()) return false;
        byte[] digest;
        try (InputStream in = Files.newInputStream(Paths.get(filePath))) {
            MessageDigest sha = Zk1.newSha256();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) sha.update(buffer, 0, n);
            digest = sha.digest();
        } catch (IOException | RuntimeException e) {
            lastError = "Failed to open file: " + filePath;
            return false;
        }
        JsonObject plainRequest = new JsonObject();
        plainRequest.addProperty("productId", nz(productId));
        plainRequest.addProperty("fileName", nz(fileName));
        plainRequest.addProperty("hash", Zk1.hex(digest));
        // End-to-end encryption: Vaultix stores only the keyed hash HMAC(kh, SHA-256)
        // of zk1 files. Files of apps without it answer "plain_hash_required":
        // then once more with the plain SHA-256, unless this client already
        // received the file as a verified zk1 delivery (a server asking for its
        // plain hash would learn what end-to-end encryption hides).
        boolean keyed = hasContentKey();
        String requestBody = plainRequest.toString();
        if (keyed) {
            JsonObject keyedRequest = new JsonObject();
            keyedRequest.addProperty("productId", nz(productId));
            keyedRequest.addProperty("fileName", nz(fileName));
            keyedRequest.addProperty("keyedHash", Zk1.hex(Zk1.keyedHash(contentKey.hashKey, digest)));
            requestBody = keyedRequest.toString();
        }
        for (int attempt = 0; ; attempt++) {
            byte[] response = performRequest("/files/verify-hash", "POST", requestBody, productHeader(productId), null, null);
            if (response.length == 0) {
                if (lastError.isEmpty()) lastError = "Empty response from server";
                return false;
            }
            JsonObject json = parseObject(response);
            if (json == null) {
                lastError = "Failed to parse verification response";
                return false;
            }
            boolean valid = bool(json, "valid", false);
            if (!valid && keyed && attempt == 0 && "plain_hash_required".equals(str(json, "code"))) {
                if (verifiedZk1Files.contains(fileKey(productId, fileName))) {
                    lastError = "verify-hash: the server asked for the plain hash of an end-to-end encrypted file";
                    return false;
                }
                log("Not an end-to-end encrypted file: checking the plain hash");
                requestBody = plainRequest.toString();
                continue;
            }
            log("Hash verification result: " + (valid ? "VALID" : "INVALID"));
            return valid;
        }
    }

    // =========================================================================
    // Folder Operations
    // =========================================================================

    /**
     * GET /folders?productId= (the endpoint the C++ SDK calls; parsed when the
     * server answers with a list).
     */
    public List<FolderInfo> getFolderList(String productId) {
        List<FolderInfo> folders = new ArrayList<>();
        lastError = "";
        if (!currentSession.isValid()) {
            lastError = "No valid session";
            return folders;
        }
        byte[] response = performRequest("/folders?productId=" + urlEncode(productId), "GET", "", null, null, null);
        if (response.length == 0) return folders;
        JsonElement parsed = parseJson(response);
        if (parsed == null || !parsed.isJsonArray()) {
            lastError = "Unexpected folder list response";
            return folders;
        }
        for (JsonElement element : parsed.getAsJsonArray()) {
            if (element.isJsonObject()) folders.add(folderInfoFrom(element.getAsJsonObject()));
        }
        return folders;
    }

    /** Folder metadata, or null on failure. */
    public FolderInfo getFolderInfo(String productId, String folderName) {
        lastError = "";
        if (!currentSession.isValid()) {
            lastError = "No valid session";
            return null;
        }
        byte[] response = performRequest(assetEndpoint("folders", "info", folderName, productId), "GET", "",
                null, null, null);
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response from server";
            return null;
        }
        JsonObject json = parseObject(response);
        if (json == null) {
            lastError = "Failed to parse JSON response";
            return null;
        }
        return folderInfoFrom(json);
    }

    /**
     * Downloads a folder as a ZIP archive to disk. End-to-end encrypted
     * folders are written to {@code <outputPath>.vxpart} and renamed only after
     * every check passed. Missing parent directories are created.
     */
    public boolean downloadFolder(String productId, String folderName, String outputPath) {
        lastSignedAt = 0;
        lastError = "";
        if (!currentSession.isValid()) {
            lastError = "No valid session";
            return false;
        }
        if (!folderExists(productId, folderName)) return false;
        if (!prepareOutput(outputPath)) return false;
        Map<String, String> responseHeaders = new HashMap<>();
        Zk1Download zk1 = new Zk1Download(Target.FILE, "folder", folderName, productId, outputPath);
        byte[] response = performRequest(assetEndpoint("folders", "download", folderName, productId), "GET", "",
                productHeader(productId), responseHeaders, zk1);
        if (zk1.isDelivery()) {
            if (zk1.succeeded()) log("Saved decrypted folder to " + outputPath);
            return zk1.succeeded();
        }
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response from server";
            return false;
        }
        String encryptionKey = responseHeaders.getOrDefault("x-encryption-key", "");
        if (encryptionKey.isEmpty()) {
            lastError = "Missing encryption key in response headers; refusing unencrypted folder data";
            return false;
        }
        byte[] plain = decryptLegacy(response, encryptionKey);
        if (plain == null) {
            lastError = "Failed to decrypt folder: " + lastError;
            return false;
        }
        try {
            Files.write(Paths.get(outputPath), plain);
        } catch (IOException e) {
            lastError = "Failed to open output file: " + outputPath;
            return false;
        } finally {
            Zk1.wipe(plain);
        }
        log("Saved decrypted folder to " + outputPath);
        return true;
    }

    /**
     * Downloads a folder as a ZIP archive into memory. Returns an empty array
     * on any failure; on success {@link #getLastError()} is "".
     */
    public byte[] downloadFolderToMemory(String productId, String folderName) {
        lastSignedAt = 0;
        lastError = "";
        if (!currentSession.isValid()) {
            lastError = "No valid session";
            return EMPTY;
        }
        if (!folderExists(productId, folderName)) return EMPTY;
        Map<String, String> responseHeaders = new HashMap<>();
        Zk1Download zk1 = new Zk1Download(Target.MEMORY, "folder", folderName, productId, null);
        byte[] response = performRequest(assetEndpoint("folders", "download", folderName, productId), "GET", "",
                productHeader(productId), responseHeaders, zk1);
        if (zk1.isDelivery()) {
            return zk1.succeeded() ? zk1.takeMemory() : EMPTY;
        }
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response from server";
            return EMPTY;
        }
        String encryptionKey = responseHeaders.getOrDefault("x-encryption-key", "");
        if (encryptionKey.isEmpty()) {
            lastError = "Missing encryption key in response headers; refusing unencrypted folder data";
            return EMPTY;
        }
        byte[] plain = decryptLegacy(response, encryptionKey);
        if (plain == null) {
            lastError = "Failed to decrypt folder: " + lastError;
            return EMPTY;
        }
        return plain;
    }

    // Like the C++ SDK: look the folder up first.
    private boolean folderExists(String productId, String folderName) {
        FolderInfo folder = getFolderInfo(productId, folderName);
        if (folder != null && !folder.getId().isEmpty()) {
            lastError = "";
            return true;
        }
        if (!lastResponseRejected) {
            lastError = "Folder not found: " + folderName + (lastError.isEmpty() ? "" : " (" + lastError + ")");
        }
        return false;
    }

    // =========================================================================
    // Product Information
    // =========================================================================

    /**
     * Product variables (name to value, in server order). End-to-end encrypted
     * values are opened with the content key and must carry a valid signature
     * of an approved team member; any failure returns an empty map.
     */
    public Map<String, String> getProductVariables(String productId) {
        Map<String, String> variables = new LinkedHashMap<>();
        lastError = "";
        if (!requireSession()) return variables;
        String appId = currentSession.getAppId();
        if (appId == null || appId.isEmpty()) {
            lastError = "Missing appId in session";
            return variables;
        }
        String endpoint = "/apps/" + urlEncode(appId) + "/products/" + urlEncode(productId) + "/variables";
        Zk1Download zk1 = new Zk1Download(Target.VARIABLES, "vars", "", productId, null);
        byte[] response = performRequest(endpoint, "GET", "", null, null, zk1);
        if (zk1.isDelivery()) {
            if (zk1.succeeded()) {
                for (Map.Entry<String, String> entry : zk1.variables) variables.put(entry.getKey(), entry.getValue());
                log("GetProductVariables: " + variables.size() + " variables (values not shown)");
            }
            return variables;
        }
        if (response.length == 0) return variables;
        JsonElement parsed = parseJson(response);
        if (parsed == null || !parsed.isJsonArray()) {
            lastError = "Failed to parse variables response";
            return variables;
        }
        for (JsonElement element : parsed.getAsJsonArray()) {
            if (!element.isJsonObject()) continue;
            JsonObject item = element.getAsJsonObject();
            String name = str(item, "name");
            if (!name.isEmpty()) variables.put(name, str(item, "value"));
        }
        return variables;
    }

    public ProductStatusInfo getProductStatus(String productId) {
        ProductStatusInfo status = new ProductStatusInfo();
        lastError = "";
        byte[] response = performRequest("/api/products/" + urlEncode(productId) + "/status", "GET", "", null, null, null);
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response when fetching product status";
            return status;
        }
        JsonObject json = parseObject(response);
        if (json == null) {
            lastError = "Failed to parse product status";
            return status;
        }
        JsonElement statusElement = json.get("status");
        if (statusElement != null && statusElement.isJsonObject()) {
            JsonObject object = statusElement.getAsJsonObject();
            status.setHasStatus(true);
            status.setName(str(object, "name"));
            status.setColor(str(object, "color"));
            status.setAction(str(object, "action"));
        }
        return status;
    }

    public ProductNewsInfo getProductNews(String productId) {
        ProductNewsInfo news = new ProductNewsInfo();
        lastError = "";
        byte[] response = performRequest("/api/products/" + urlEncode(productId) + "/news", "GET", "", null, null, null);
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response when fetching product news";
            return news;
        }
        JsonObject json = parseObject(response);
        if (json == null) {
            lastError = "Failed to parse product news";
            return news;
        }
        JsonElement newsElement = json.get("news");
        if (newsElement != null && newsElement.isJsonObject()) {
            JsonObject object = newsElement.getAsJsonObject();
            news.setHasNews(true);
            news.setHeadline(str(object, "headline"));
            news.setContent(str(object, "content"));
            news.setUpdatedAt(str(object, "updatedAt"));
        }
        return news;
    }

    /**
     * Cosmetic profile of whoever this session is logged in as; null on
     * failure. The server resolves the identity from the session token.
     */
    public AccountInfo getAccountInfo() {
        lastError = "";
        if (!requireSession()) return null;
        byte[] response = performRequest("/me", "GET", "", null, null, null);
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response when fetching account info";
            return null;
        }
        JsonObject json = parseObject(response);
        if (json == null) {
            lastError = "Failed to parse account info";
            return null;
        }
        AccountInfo info = new AccountInfo();
        info.setUsername(str(json, "username"));
        info.setNote(str(json, "note"));
        return info;
    }

    // =========================================================================
    // User & Subscription
    // =========================================================================

    /** True if the login response listed a subscription to this product. */
    public boolean hasProductAccess(String productId) {
        return currentSession.isValid() && currentSession.getAppUser().getSubscriptions().contains(productId);
    }

    public List<Map<String, String>> getUserProducts() {
        List<Map<String, String>> products = new ArrayList<>();
        lastError = "";
        if (!requireSession()) return products;
        byte[] response = performRequest("/products", "GET", "", null, null, null);
        if (response.length == 0) {
            if (lastError.isEmpty()) lastError = "Empty response from server";
            return products;
        }
        JsonElement parsed = parseJson(response);
        if (parsed == null || !parsed.isJsonArray()) {
            lastError = "Unexpected products response";
            return products;
        }
        for (JsonElement element : parsed.getAsJsonArray()) {
            if (!element.isJsonObject()) continue;
            JsonObject item = element.getAsJsonObject();
            Map<String, String> product = new HashMap<>();
            for (String field : new String[] {"id", "name", "description", "appId", "status", "fileCount",
                                              "subscriptionsCount"}) {
                product.put(field, str(item, field));
            }
            products.add(product);
        }
        return products;
    }

    public SubscriptionInfo getUserSubscriptionByProduct(String productId) {
        SubscriptionInfo subscription = new SubscriptionInfo();
        lastError = "";
        if (!requireSession()) return subscription;
        byte[] response = performRequest("/products/" + urlEncode(productId) + "/user-subscription", "GET", "",
                null, null, null);
        if (response.length == 0) {
            if (lastError.contains("HTTP Error 404")) {
                lastError = "No subscription found for this product";
            } else if (lastError.isEmpty()) {
                lastError = "Empty response from server";
            }
            return subscription;
        }
        JsonObject json = parseObject(response);
        if (json == null) {
            lastError = "Failed to parse subscription response";
            return subscription;
        }
        subscription.setSubscriptionId(str(json, "subscriptionId"));
        subscription.setAppUserId(str(json, "appUserId"));
        subscription.setProductId(str(json, "productId"));
        subscription.setStatus(str(json, "status"));
        subscription.setExpiresAt(strOrNull(json, "expiresAt"));
        subscription.setPaused(bool(json, "isPaused", false));
        subscription.setPausedAt(strOrNull(json, "pausedAt"));
        subscription.setPausedUntil(strOrNull(json, "pausedUntil"));
        subscription.setDownloads((int) number(json, "downloads"));
        subscription.setCreatedAt(str(json, "createdAt"));
        subscription.setUpdatedAt(str(json, "updatedAt"));
        return subscription;
    }

    // =========================================================================
    // HTTP
    // =========================================================================

    /**
     * One request. Returns the body, or an empty array on any failure (then
     * {@link #lastError} says why). With zk1 set, the request carries a fresh
     * X-Vaultix-Eph key and a zk1 delivery is decrypted while it streams (the
     * result is then in zk1 and the return value is empty).
     */
    private byte[] performRequest(String endpoint, String method, String postData, Map<String, String> headers,
                                  Map<String, String> responseHeaders, Zk1Download zk1) {
        lastResponseRejected = false;
        if (zk1 != null) zk1.reset();
        if (responseHeaders != null) responseHeaders.clear();
        String sentMethod = ("POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method)) ? method : "GET";
        String body = postData == null ? "" : postData;

        URI uri;
        HttpRequest.Builder request;
        try {
            uri = new URI(baseUrl + endpoint);
            request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(TIMEOUT_SECONDS));
        } catch (URISyntaxException | IllegalArgumentException e) {
            lastError = "Invalid request URL: " + e.getMessage();
            return EMPTY;
        }
        Map<String, String> sent = new LinkedHashMap<>();
        sent.put("Content-Type", "application/json");
        sent.put("User-Agent", USER_AGENT);

        // Fresh nonce per request: Vaultix signs the response over it, so a
        // response can only ever be valid for this one request. zk1 deliveries
        // are always verified, so downloads always send one.
        String nonce = "";
        if (requireSignedResponses || zk1 != null) {
            nonce = generateNonce();
            sent.put("X-Vaultix-Nonce", nonce);
        }
        // End-to-end encryption: a fresh one-time X25519 key per request.
        if (zk1 != null) {
            String ephemeral = zk1.prepareRequest();
            if (ephemeral == null) {
                lastError = zk1.error;
                return EMPTY;
            }
            sent.put("X-Vaultix-Eph", ephemeral);
        }
        if (requestSigningEnabled && requestSigningKey != null && !requestSigningKey.isEmpty()) {
            String timestamp = Long.toString(System.currentTimeMillis());
            String toSign = method + "|" + endpoint + "|" + body + "|" + timestamp;
            sent.put("X-Request-Timestamp", timestamp);
            sent.put("X-Request-Signature", Zk1.hex(Zk1.hmacSha256(Zk1.utf8(requestSigningKey), Zk1.utf8(toSign))));
        }
        if (currentSession.isValid() && currentSession.getSessionToken() != null
                && !currentSession.getSessionToken().isEmpty()) {
            sent.put("Authorization", "Bearer " + currentSession.getSessionToken());
        } else if (apiKey != null && !apiKey.isEmpty()) {
            sent.put("X-API-Key", apiKey);
        }
        if (headers != null) sent.putAll(headers);
        try {
            for (Map.Entry<String, String> header : sent.entrySet()) request.setHeader(header.getKey(), header.getValue());
        } catch (IllegalArgumentException e) {
            lastError = "Invalid request header: " + e.getMessage();
            if (zk1 != null) zk1.fail(lastError);
            return EMPTY;
        }
        if ("POST".equals(sentMethod) || "PUT".equals(sentMethod)) {
            request.method(sentMethod, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else if ("DELETE".equals(sentMethod)) {
            request.DELETE();
        } else {
            request.GET();
        }
        if (debugMode) {
            log(sentMethod + " " + uri);
            if (!body.isEmpty()) log("Data: " + body.length() + " characters (not shown)");
            for (Map.Entry<String, String> header : sent.entrySet()) log("Header: " + redactHeader(header.getKey(), header.getValue()));
        }

        HttpResponse<InputStream> response;
        try {
            response = http().send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            lastError = "Request interrupted";
            return EMPTY;
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            lastError = "Network error: " + describe(e);
            log(lastError);
            return EMPTY;
        }
        int status = response.statusCode();
        Map<String, String> lower = lastHeaderValues(response.headers());
        if (responseHeaders != null) responseHeaders.putAll(lower);
        String pathAndQuery = pathAndQuery(uri);
        log("Response code: " + status);

        // zk1 delivery: the signature is checked from the headers and the body
        // decrypted while it streams.
        if (zk1 != null && lower.getOrDefault("x-encryption-key", "").startsWith("zk1d.")) {
            readDelivery(response, zk1, status, lower, nonce, sentMethod, pathAndQuery);
            lastResponseRejected = zk1.rejected;
            if (zk1.succeeded()) {
                lastError = "";
                log("End-to-end encrypted " + zk1.kind + " delivery verified and decrypted");
            } else {
                lastError = zk1.error;
                if (responseHeaders != null) responseHeaders.clear();
                log(lastError);
            }
            return EMPTY;
        }

        byte[] data;
        try (InputStream in = response.body()) {
            data = in.readAllBytes();
        } catch (IOException e) {
            lastError = "Network error: " + describe(e);
            log(lastError);
            return EMPTY;
        }
        log("Response size: " + data.length + " bytes");

        // Redirects are not followed; like the C++ SDK, a redirected request fails.
        if (status >= 300 && status < 400) {
            lastResponseRejected = requireSignedResponses;
            lastError = requireSignedResponses
                    ? "Server response could not be verified (HTTP " + status + "): the request was redirected"
                    : "HTTP Error " + status + ": redirects are not followed";
            log(lastError);
            if (responseHeaders != null) responseHeaders.clear();
            return EMPTY;
        }

        // Verify that the response really comes from Vaultix and answers
        // exactly this request, before anything in it is used (status codes and
        // error bodies included).
        if (requireSignedResponses) {
            String reason = verifyResponseSignature(sentMethod, pathAndQuery, status, Zk1.hex(Zk1.sha256(data)), lower, nonce);
            if (reason != null) {
                lastError = "Server response could not be verified (HTTP " + status + "): " + reason;
                lastResponseRejected = true;
                log(lastError);
                if (responseHeaders != null) responseHeaders.clear();
                Zk1.wipe(data);
                return EMPTY;
            }
            log("Response signature verified");
        }

        if (status >= 400) {
            String text = new String(data, StandardCharsets.UTF_8);
            if (status == 409 && text.contains("e2ee_sdk_update_required")) {
                lastError = "HTTP Error 409: this app uses end-to-end encryption and the request carried no "
                        + "one-time key (e2ee_sdk_update_required); download with a content key set (setContentKey)";
            } else {
                lastError = "HTTP Error " + status + ": " + text;
                String debugInfo = lower.get("x-debug-info");
                if (debugInfo != null && !debugInfo.isEmpty()) lastError += " [Debug: " + debugInfo + "]";
            }
            log(lastError);
            return EMPTY;
        }
        return data;
    }

    private void readDelivery(HttpResponse<InputStream> response, Zk1Download zk1, int status,
                              Map<String, String> lower, String nonce, String method, String pathAndQuery) {
        try (InputStream in = response.body()) {
            if (!zk1.engage(status, lower, nonce, method, pathAndQuery)) return;
            byte[] buffer = new byte[READ_BUFFER_BYTES];
            try {
                int n;
                while ((n = in.read(buffer)) != -1) {
                    if (n > 0 && !zk1.update(buffer, n)) return;
                }
            } catch (IOException e) {
                zk1.fail("Network error: " + describe(e));
                return;
            }
            zk1.finish();
        } catch (IOException ignored) {
            // closing the body
        } catch (RuntimeException e) {
            zk1.fail(Zk1Download.failure(describe(e)));
        }
    }

    /** null if the signature is valid, else the reason. */
    private String verifyResponseSignature(String method, String pathAndQuery, int status, String bodyHashField,
                                           Map<String, String> lower, String nonce) {
        String signature = lower.getOrDefault("x-vaultix-signature", "");
        String keyId = lower.getOrDefault("x-vaultix-key-id", "");
        String signedAt = lower.getOrDefault("x-vaultix-signed-at", "");
        if (signature.isEmpty() || keyId.isEmpty() || signedAt.isEmpty()) return "the response is not signed";
        byte[] publicKey = trustedResponseKey(keyId);
        if (publicKey == null) return "unknown signing key '" + ResponseSigning.printable(keyId) + "'";
        if (signedAt.length() > 12 || !signedAt.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return "invalid signing time";
        }
        byte[] canonical = ResponseSigning.canonical(keyId, nonce, signedAt, method, pathAndQuery,
                Integer.toString(status), bodyHashField, lower.getOrDefault("x-encryption-key", ""),
                lower.getOrDefault("x-encryption-iv", ""), lower.getOrDefault("content-type", ""));
        byte[] signatureBytes = Zk1.b64uDecode(signature, 64);
        if (canonical == null || signatureBytes == null || signatureBytes.length != 64
                || !Zk1.ed25519Verify(publicKey, canonical, signatureBytes)) {
            return "invalid signature (the response was altered, replayed, or does not come from Vaultix)";
        }
        long skew = Math.abs(System.currentTimeMillis() / 1000 - Long.parseLong(signedAt));
        if (skew > responseClockSkewSeconds) {
            return "the signature time differs from this computer's clock by " + skew
                    + " seconds (check the system date and time)";
        }
        return null;
    }

    private byte[] trustedResponseKey(String keyId) {
        byte[] builtIn = ResponseSigning.trustedPublicKey(keyId);
        if (builtIn != null) return builtIn;
        if (testingResponseKeyId != null && testingResponseKeyId.equals(keyId)) return testingResponsePublicKey.clone();
        return null;
    }

    private HttpClient http() throws GeneralSecurityException {
        if (httpClient == null || httpClientStale) {
            httpClient = buildHttpClient();
            httpClientStale = false;
        }
        return httpClient;
    }

    private HttpClient buildHttpClient() throws GeneralSecurityException {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .followRedirects(HttpClient.Redirect.NEVER);
        if (baseUrl.regionMatches(true, 0, "https://", 0, 8)) {
            builder.version(HttpClient.Version.HTTP_2);
            TrustManager trust = null;
            if (!sslVerify) {
                trust = new TrustAllManager();
            } else if (certificatePinningEnabled && !pinnedCertificates.isEmpty()) {
                trust = new PinningTrustManager(defaultTrustManager(), pinnedCertificates);
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trust == null ? null : new TrustManager[] {trust}, null);
            SSLParameters parameters = context.getDefaultSSLParameters();
            parameters.setProtocols("1.3".equals(minTlsVersion) ? new String[] {"TLSv1.3"}
                                                                 : new String[] {"TLSv1.3", "TLSv1.2"});
            builder.sslContext(context).sslParameters(parameters);
        } else {
            builder.version(HttpClient.Version.HTTP_1_1);
        }
        return builder.build();
    }

    private static X509ExtendedTrustManager defaultTrustManager() throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509ExtendedTrustManager) return (X509ExtendedTrustManager) manager;
        }
        throw new GeneralSecurityException("no default X509 trust manager");
    }

    /** Normal certificate checks plus a pin on the leaf certificate's public key. */
    private static final class PinningTrustManager extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager delegate;
        private final List<String> pins;

        PinningTrustManager(X509ExtendedTrustManager delegate, List<String> pins) {
            this.delegate = delegate;
            this.pins = new ArrayList<>(pins);
        }

        private void checkPin(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("no server certificate");
            String hash = Zk1.hex(Zk1.sha256(chain[0].getPublicKey().getEncoded()));
            for (String pin : pins) {
                if (pin != null && pin.trim().equalsIgnoreCase(hash)) return;
            }
            throw new CertificateException("Certificate pinning failed - no matching certificate found");
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            delegate.checkServerTrusted(chain, authType, socket);
            checkPin(chain);
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            delegate.checkServerTrusted(chain, authType, engine);
            checkPin(chain);
        }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkServerTrusted(chain, authType);
            checkPin(chain);
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            throw new CertificateException("client certificates are not accepted");
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            throw new CertificateException("client certificates are not accepted");
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("client certificates are not accepted");
        }

        @Override public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }

    /** setSslVerify(false): no certificate or host name checks (local testing only). */
    private static final class TrustAllManager extends X509ExtendedTrustManager {
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            throw new CertificateException("client certificates are not accepted");
        }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            throw new CertificateException("client certificates are not accepted");
        }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("client certificates are not accepted");
        }
        @Override public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    // =========================================================================
    // End-to-end encrypted download (one request)
    // =========================================================================

    private enum Target { MEMORY, FILE, VARIABLES }

    private enum State { IDLE, ACTIVE, DONE, FAILED }

    /**
     * A download that may come back as a zk1 delivery. performRequest() decides
     * at the response headers: X-Encryption-Key "zk1d." means check the
     * signature (mandatory, also with setRequireSignedResponses(false)), then
     * decrypt while streaming; anything else stays on the legacy path.
     */
    private final class Zk1Download {
        final Target target;
        final String kind;        // "file", "folder" or "vars"
        final String name;        // the name that was asked for (seal context)
        final String productId;   // the product asked for: seal scope; vars: the delivery's object id
        final String outputPath;
        Path partPath;            // "<outputPath>.vxpart" while the file is unverified
        OutputStream part;
        byte[] memory;
        int memoryLength;
        List<Map.Entry<String, String>> variables = new ArrayList<>();
        State state = State.IDLE;
        String error = "";
        String storeError = "";
        boolean rejected;         // the signature check failed
        byte[] clientSecret;
        Zk1.DeliveryOpener opener;

        Zk1Download(Target target, String kind, String name, String productId, String outputPath) {
            this.target = target;
            this.kind = kind;
            this.name = nz(name);
            this.productId = nz(productId);
            this.outputPath = outputPath;
        }

        static String failure(String detail) {
            return "End-to-end encrypted download failed: " + detail;
        }

        // Drop every result and the partial file.
        void discard() {
            if (opener != null) opener.close();
            opener = null;
            Zk1.wipe(memory);
            memory = null;
            memoryLength = 0;
            variables = new ArrayList<>();
            if (part != null) {
                try {
                    part.close();
                } catch (IOException ignored) {
                    // deleted below
                }
                part = null;
            }
            if (partPath != null) {
                try {
                    Files.deleteIfExists(partPath);
                } catch (IOException ignored) {
                    // nothing else to do
                }
                partPath = null;
            }
        }

        void reset() {
            discard();
            state = State.IDLE;
            error = "";
            storeError = "";
            rejected = false;
            Zk1.wipe(clientSecret);
            clientSecret = null;
        }

        boolean fail(String message) {
            if (state != State.FAILED && error.isEmpty()) error = message;
            state = State.FAILED;
            discard();
            return false;
        }

        // A fresh X25519 key for this request; the value of X-Vaultix-Eph.
        String prepareRequest() {
            byte[][] pair = Zk1.x25519Generate(random);
            if (pair == null) {
                fail("Could not create a one-time request key");
                return null;
            }
            clientSecret = pair[0];
            return Zk1.b64uEncode(pair[1]);
        }

        boolean isDelivery() {
            return state != State.IDLE;
        }

        boolean succeeded() {
            return state == State.DONE;
        }

        byte[] takeMemory() {
            byte[] out = memory == null ? new byte[0] : memory;
            memory = null;
            return out;
        }

        // The headers of a delivery are in.
        boolean engage(int status, Map<String, String> lower, String nonce, String method, String pathAndQuery) {
            state = State.ACTIVE;
            String reason = nonce.isEmpty() ? "the request had no nonce"
                    : verifyResponseSignature(method, pathAndQuery, status, ResponseSigning.STREAM_BODY_MARKER, lower, nonce);
            if (reason != null) {
                rejected = true;
                return fail("Server response could not be verified (HTTP " + status + "): " + reason);
            }
            if (status != 200) return fail(failure("unexpected HTTP status " + status));
            if (!"vars".equals(kind) && contentKey == null) return fail(Zk1.NEED_CONTENT_KEY);
            // The app id is part of every signed message (from the signed login response).
            String appId = currentSession.getAppId();
            if (appId == null || appId.isEmpty()) return fail(failure("no app id in the session"));
            if (clientSecret == null) return fail(failure("no request key"));
            opener = new Zk1.DeliveryOpener(clientSecret, kind);
            Zk1.wipe(clientSecret);
            clientSecret = null;
            if (!"vars".equals(kind)) opener.setFileContext(contentKey, appId, name, productId, this::store);
            if (!opener.begin(lower.get("x-encryption-key"))) return fail(failure(opener.error()));
            if ("vars".equals(kind) && !opener.objectId().equals(productId)) {
                return fail(failure("the variables delivery is for another product"));
            }
            if (target == Target.FILE) {
                partPath = Paths.get(outputPath + ".vxpart");
                try {
                    part = Files.newOutputStream(partPath);
                } catch (IOException | RuntimeException e) {
                    return fail("Failed to open output file: " + partPath);
                }
            }
            return true;
        }

        // Decrypted content (not yet verified as a whole).
        boolean store(byte[] data, int offset, int length) {
            if (target == Target.MEMORY) {
                if (memory == null) {
                    long size = opener.contentSize();
                    if (size > Integer.MAX_VALUE - 8) {
                        storeError = "the file is too large for memory";
                        return false;
                    }
                    try {
                        // Exact size up front: no reallocation leaves plaintext copies behind.
                        memory = new byte[(int) size];
                    } catch (OutOfMemoryError e) {
                        storeError = "not enough memory for the file";
                        return false;
                    }
                }
                if (length > memory.length - memoryLength) {
                    storeError = failure("the file is larger than its sealed size");
                    return false;
                }
                System.arraycopy(data, offset, memory, memoryLength, length);
                memoryLength += length;
                return true;
            }
            if (target == Target.FILE && part != null) {
                try {
                    part.write(data, offset, length);
                    return true;
                } catch (IOException e) {
                    storeError = "Failed to write output file: " + partPath;
                    return false;
                }
            }
            return false;
        }

        boolean update(byte[] data, int length) {
            if (state != State.ACTIVE) return false;
            if (!opener.update(data, 0, length)) {
                return fail(storeError.isEmpty() ? failure(opener.error()) : storeError);
            }
            return true;
        }

        // End of the body: the whole delivery must authenticate.
        boolean finish() {
            if (state != State.ACTIVE) return state == State.DONE;
            if (!opener.finish()) return fail(storeError.isEmpty() ? failure(opener.error()) : storeError);
            if (target == Target.FILE) {
                try {
                    part.close();
                } catch (IOException e) {
                    part = null;
                    return fail("Failed to write output file: " + partPath);
                }
                part = null;
                try {
                    moveReplacing(partPath, Paths.get(outputPath));
                } catch (IOException | RuntimeException e) {
                    return fail("Failed to save the file to " + outputPath);
                }
                partPath = null;
            } else if (target == Target.VARIABLES) {
                byte[] payload = opener.varsPayload();
                try {
                    variables = Zk1.openVariables(payload, contentKey, currentSession.getAppId(), productId);
                } catch (Zk1.Zk1Exception e) {
                    return fail(Zk1.NEED_CONTENT_KEY.equals(e.getMessage()) ? e.getMessage() : failure(e.getMessage()));
                } finally {
                    Zk1.wipe(payload);
                }
            }
            if (!"vars".equals(kind)) lastSignedAt = opener.signedAt();
            // verified and fully decrypted: isValidFileHash never sends its plain hash
            if ("file".equals(kind)) verifiedZk1Files.add(fileKey(productId, name));
            opener.close();
            opener = null;
            state = State.DONE;
            return true;
        }
    }

    private static void moveReplacing(Path from, Path to) throws IOException {
        try {
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    // =========================================================================
    // Legacy downloads (apps without end-to-end encryption)
    // =========================================================================

    /**
     * SALT(16) || IV(12) || TAG(16) || CIPHERTEXT, or the old IV || TAG ||
     * CIPHERTEXT with a fixed salt; AES-256-GCM under PBKDF2-HMAC-SHA256(header
     * key, salt, 100000). Null (and lastError) on failure.
     */
    private byte[] decryptLegacy(byte[] data, String key) {
        byte[] salt;
        int ivAt;
        int tagAt;
        int cipherAt;
        if (data.length >= 44) {
            salt = Arrays.copyOfRange(data, 0, 16);
            ivAt = 16;
            tagAt = 28;
            cipherAt = 44;
        } else if (data.length >= 28) {
            salt = LEGACY_SALT;
            ivAt = 0;
            tagAt = 12;
            cipherAt = 28;
        } else {
            lastError = "Invalid encrypted data size for AES-GCM";
            return null;
        }
        byte[] derived = Zk1.pbkdf2Sha256(key.getBytes(StandardCharsets.ISO_8859_1), salt, 100000, 32);
        byte[] input = new byte[data.length - cipherAt + 16];
        System.arraycopy(data, cipherAt, input, 0, data.length - cipherAt);
        System.arraycopy(data, tagAt, input, data.length - cipherAt, 16);
        try {
            return Zk1.aesGcmDecrypt(derived, Arrays.copyOfRange(data, ivAt, ivAt + 12), null, input, 0, input.length);
        } catch (GeneralSecurityException e) {
            lastError = "Failed to finalize decryption (authentication failed)";
            return null;
        } finally {
            Zk1.wipe(derived);
        }
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    private boolean requireSession() {
        if (!currentSession.isValid()) {
            lastError = "No valid session";
            return false;
        }
        if (isTokenExpired() && !refreshToken()) {
            lastError = "Token expired and refresh failed";
            return false;
        }
        return true;
    }

    private boolean prepareOutput(String outputPath) {
        if (outputPath == null || outputPath.isEmpty()) {
            lastError = "No output path";
            return false;
        }
        try {
            Path parent = Paths.get(outputPath).toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            return true;
        } catch (IOException | RuntimeException e) {
            lastError = "Failed to create the output directory for " + outputPath;
            return false;
        }
    }

    private String activeApiKey() {
        if (apiKey != null && !apiKey.isEmpty()) return apiKey;
        String stored = currentSession.getAppApiKey();
        return stored == null ? "" : stored;
    }

    private static Map<String, String> apiKeyHeader(String key) {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-API-Key", key);
        return headers;
    }

    // An empty value is not sent (curl drops empty headers in the C++ SDK too).
    private static Map<String, String> productHeader(String productId) {
        return productId == null || productId.isEmpty() ? Collections.emptyMap()
                : Collections.singletonMap("X-Product-ID", productId);
    }

    private static String assetEndpoint(String collection, String action, String name, String productId) {
        return "/" + collection + "/" + action + "/" + urlEncode(name) + "?productId=" + urlEncode(productId);
    }

    private static String fileKey(String productId, String fileName) {
        return nz(productId) + "\0" + nz(fileName);
    }

    private static String nz(String value) {
        return value == null ? "" : value;
    }

    /** Like the C++ SDK: unreserved characters stay, every other UTF-8 byte becomes %XX. */
    static String urlEncode(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : nz(value).getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                out.append((char) c);
            } else {
                out.append('%').append("0123456789ABCDEF".charAt(c >> 4)).append("0123456789ABCDEF".charAt(c & 0xF));
            }
        }
        return out.toString();
    }

    /** Path and query exactly as the JDK client puts them on the request line. */
    static String pathAndQuery(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        String query = uri.getRawQuery();
        return query == null || query.isEmpty() ? path : path + "?" + query;
    }

    /** Lower-case header names; the last value counts; surrounding spaces and tabs removed. */
    private static Map<String, String> lastHeaderValues(HttpHeaders headers) {
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : headers.map().entrySet()) {
            List<String> values = entry.getValue();
            if (values.isEmpty()) continue;
            out.put(entry.getKey().toLowerCase(Locale.ROOT), trimSpaces(values.get(values.size() - 1)));
        }
        return out;
    }

    private static String trimSpaces(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) start++;
        while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) end--;
        return value.substring(start, end);
    }

    // 24 random bytes as 48 hex characters.
    private String generateNonce() {
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Zk1.hex(bytes);
    }

    private static String describe(Throwable e) {
        String message = e.getMessage();
        return e.getClass().getSimpleName() + (message == null || message.isEmpty() ? "" : ": " + message);
    }

    // Debug output never shows credentials, keys or request bodies.
    private static String redactHeader(String name, String value) {
        String lower = name.toLowerCase(Locale.ROOT);
        switch (lower) {
            case "content-type": case "user-agent": case "x-product-id": case "x-vaultix-nonce":
            case "x-vaultix-eph": case "x-request-timestamp": case "content-length":
                return name + ": " + value;
            default:
                return name + ": [redacted]";
        }
    }

    private FileInfo fileInfoFrom(JsonObject json) {
        FileInfo file = new FileInfo();
        file.setId(str(json, "id"));
        file.setName(str(json, "name"));
        file.setAppId(str(json, "appId"));
        file.setSize(size(json.get("size")));
        file.setEncrypted(bool(json, "encrypted", true));
        file.setEncryptionKey(strOrNull(json, "encryptionKey"));
        file.setEncryptionIv(strOrNull(json, "encryptionIV"));
        file.setDownloads((int) number(json, "downloads"));
        file.setUploadedAt(str(json, "uploadedAt"));
        return file;
    }

    private FolderInfo folderInfoFrom(JsonObject json) {
        FolderInfo folder = new FolderInfo();
        folder.setId(str(json, "id"));
        folder.setName(str(json, "name"));
        folder.setAppId(str(json, "appId"));
        folder.setTotalSize(size(json.get("totalSize")));
        folder.setFileCount((int) number(json, "fileCount"));
        folder.setDownloads((int) number(json, "downloads"));
        folder.setUploadedAt(str(json, "uploadedAt"));
        return folder;
    }

    /** A byte count, or a size text such as "25.5 MB" (approximate); 0 if unknown. */
    private static long size(JsonElement element) {
        if (element == null || element.isJsonNull() || !element.isJsonPrimitive()) return 0;
        if (element.getAsJsonPrimitive().isNumber()) return element.getAsLong();
        String text = element.getAsString().trim();
        String[] parts = text.split("\\s+");
        try {
            double value = Double.parseDouble(parts[0]);
            String unit = parts.length > 1 ? parts[1].toUpperCase(Locale.ROOT) : "B";
            double factor;
            switch (unit) {
                case "KB": factor = 1024.0; break;
                case "MB": factor = 1024.0 * 1024; break;
                case "GB": factor = 1024.0 * 1024 * 1024; break;
                case "TB": factor = 1024.0 * 1024 * 1024 * 1024; break;
                default: factor = 1.0; break;
            }
            return (long) (value * factor);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static JsonElement parseJson(byte[] data) {
        try {
            return JsonParser.parseString(new String(data, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static JsonObject parseObject(byte[] data) {
        JsonElement element = parseJson(data);
        return element != null && element.isJsonObject() ? element.getAsJsonObject() : null;
    }

    private static String str(JsonObject json, String key) {
        JsonElement value = json.get(key);
        if (value == null || value.isJsonNull()) return "";
        return value.isJsonPrimitive() ? value.getAsString() : value.toString();
    }

    private static String strOrNull(JsonObject json, String key) {
        JsonElement value = json.get(key);
        if (value == null || value.isJsonNull()) return null;
        return value.isJsonPrimitive() ? value.getAsString() : value.toString();
    }

    private static long number(JsonObject json, String key) {
        JsonElement value = json.get(key);
        if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) return 0;
        try {
            return value.getAsLong();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    private static boolean bool(JsonObject json, String key, boolean defaultValue) {
        JsonElement value = json.get(key);
        if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) return defaultValue;
        if (value.getAsJsonPrimitive().isBoolean()) return value.getAsBoolean();
        String text = value.getAsString();
        return "true".equals(text) || "1".equals(text);
    }

    private void log(String message) {
        if (debugMode) System.out.println("[VaultixSDK] " + message);
    }

    // =========================================================================
    // HWID and auto-login token
    // =========================================================================

    private String getHwid() {
        String machine = System.getenv("COMPUTERNAME");
        if (machine == null || machine.isEmpty()) machine = System.getenv("HOSTNAME");
        if (machine == null || machine.isEmpty()) {
            try {
                Path hostname = Paths.get("/etc/hostname");
                if (Files.isReadable(hostname)) machine = new String(Files.readAllBytes(hostname), StandardCharsets.UTF_8).trim();
            } catch (IOException | RuntimeException e) {
                machine = null;
            }
        }
        if (machine == null || machine.isEmpty()) {
            try {
                machine = InetAddress.getLocalHost().getHostName();
            } catch (IOException | RuntimeException e) {
                machine = null;
            }
        }
        if (machine == null || machine.isEmpty()) return UUID.randomUUID().toString();
        String machineInfo = System.getProperty("user.name") + "-" + machine;
        return Zk1.hex(Zk1.sha256(machineInfo.getBytes(StandardCharsets.UTF_8)));
    }

    private Path tokenPath(String key) {
        String id = Zk1.hex(Zk1.sha256(Zk1.utf8("vaultix-autologin:" + key))).substring(0, 16);
        return tokenDirectory.resolve("autologin-" + id + ".dat");
    }

    private void savePersistentToken(String token, String key) {
        if (token == null || token.isEmpty() || key == null || key.isEmpty()) return;
        try {
            Files.createDirectories(tokenDirectory);
            Path path = tokenPath(key);
            Files.write(path, obfuscate(token).getBytes(StandardCharsets.US_ASCII));
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            }
        } catch (IOException | RuntimeException e) {
            log("Failed to save the auto-login token");
        }
    }

    private String loadPersistentToken(String key) {
        try {
            Path path = tokenPath(key);
            if (Files.exists(path)) return deobfuscate(new String(Files.readAllBytes(path), StandardCharsets.US_ASCII));
        } catch (IOException | RuntimeException e) {
            log("Failed to read the auto-login token");
        }
        return null;
    }

    private boolean deletePersistentToken(String key) {
        try {
            return Files.deleteIfExists(tokenPath(key));
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    // Obfuscation only (not encryption): garbage|token|garbage, base64.
    private String obfuscate(String input) {
        StringBuilder garbage = new StringBuilder();
        int garbageLength = random.nextInt(41) + 10;  // 10-50
        while (garbage.length() < garbageLength) {
            char c = (char) (random.nextInt(94) + 33);  // ASCII 33-126
            if (c != '|') garbage.append(c);
        }
        String combined = garbage + "|" + input + "|" + garbage;
        return Base64.getEncoder().encodeToString(combined.getBytes(StandardCharsets.UTF_8));
    }

    private static String deobfuscate(String obfuscated) {
        try {
            String decoded = new String(Base64.getDecoder().decode(obfuscated.trim()), StandardCharsets.UTF_8);
            String[] parts = decoded.split("\\|");
            if (parts.length >= 2) return parts[1];
        } catch (RuntimeException e) {
            // not a token file of this SDK
        }
        return null;
    }

    /** Ends the HTTP client and wipes the content key and API key. */
    @Override
    public void close() throws Exception {
        httpClient = null;
        clearContentKey();
        clearApiKey();
    }
}
