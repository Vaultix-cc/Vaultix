package com.vaultix.sdk;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Map;

import static com.vaultix.sdk.TestSupport.pattern;
import static com.vaultix.sdk.TestSupport.sha256Hex;
import static com.vaultix.sdk.TestSupport.unhex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The client against a local mock of the SDK endpoints that serves the
 * zk1.json content and signs responses with the public golden test key
 * (trusted through the testing hook). Covers the failure paths a real
 * backend does not produce.
 */
class MockServerTest {

    private static final String API_KEY = "ap_mock";
    private static final String LEGACY_KEY = "enc_key_mock";

    private static HttpServer server;
    private static String base;
    private static JsonObject v;
    private static byte[] signingSeed;
    private static String keyId;
    private static String publicKeyHex;
    private static byte[] folderCipher;
    private static byte[] legacyPlain;
    private static byte[] legacyBody;
    private static volatile String mode = "ok";
    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path temp;

    @BeforeAll
    static void start() throws Exception {
        v = TestSupport.zk1Vectors();
        JsonObject golden = TestSupport.responseGolden();
        signingSeed = unhex(golden.get("seed_hex").getAsString());
        keyId = golden.get("key_id").getAsString();
        publicKeyHex = golden.get("public_key_hex").getAsString();
        JsonObject folder = file(1);
        folderCipher = TestSupport.streamEncrypt(unhex(folder.get("fileKey").getAsString()),
                pattern(folder.get("plainLength").getAsInt(), folder.get("seed").getAsInt()), "VXZ1");
        legacyPlain = pattern(5000, 42);
        byte[] salt = pattern(16, 1);
        byte[] iv = pattern(12, 2);
        byte[] derived = Zk1.pbkdf2Sha256(LEGACY_KEY.getBytes(StandardCharsets.US_ASCII), salt, 100000, 32);
        byte[] sealed = TestSupport.aesGcmEncrypt(derived, iv, new byte[0], legacyPlain);  // ciphertext || tag
        int cipherLength = sealed.length - 16;
        legacyBody = new byte[16 + 12 + 16 + cipherLength];
        System.arraycopy(salt, 0, legacyBody, 0, 16);
        System.arraycopy(iv, 0, legacyBody, 16, 12);
        System.arraycopy(sealed, cipherLength, legacyBody, 28, 16);
        System.arraycopy(sealed, 0, legacyBody, 44, cipherLength);

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/", MockServerTest::handle);
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort() + "/api";
    }

    @AfterAll
    static void stop() {
        if (server != null) server.stop(0);
    }

    @BeforeEach
    void resetMode() {
        mode = "ok";
    }

    private static JsonObject file(int index) {
        return v.getAsJsonArray("files").get(index).getAsJsonObject();
    }

    private static String appKey(int index) {
        return v.getAsJsonArray("appKeys").get(index).getAsJsonObject().get("sdkKey").getAsString();
    }

    // ------------------------------------------------------------------
    // Mock server
    // ------------------------------------------------------------------

    private static void handle(HttpExchange exchange) throws IOException {
        try {
            route(exchange);
        } catch (Exception e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
        } finally {
            exchange.close();
        }
    }

    private static void route(HttpExchange ex) throws Exception {
        String path = ex.getRequestURI().getRawPath();
        byte[] requestBody = ex.getRequestBody().readAllBytes();
        String bearer = ex.getRequestHeaders().getFirst("Authorization");
        boolean session = "Bearer mock-token".equals(bearer);
        if (path.equals("/api/app_auth/login_key")) {
            if (!API_KEY.equals(ex.getRequestHeaders().getFirst("X-API-Key"))) {
                json(ex, 401, "{\"detail\":\"Invalid API key\"}");
                return;
            }
            json(ex, 200, "{\"access_token\":\"mock-token\",\"token_type\":\"bearer\",\"appId\":\"app-1\","
                    + "\"appUserId\":\"u-1\",\"subscriptions\":[\"prod-1234\"],\"expiresAt\":\"2030-01-01T00:00:00\","
                    + "\"sessionId\":\"s-1\"}");
            return;
        }
        if (!session) {
            json(ex, 401, "{\"detail\":\"Not authenticated\"}");
            return;
        }
        String eph = ex.getRequestHeaders().getFirst("X-Vaultix-Eph");
        switch (path) {
            case "/api/app_auth/logout":
                json(ex, 200, "{\"message\":\"Logged out successfully\"}");
                return;
            case "/api/files/download/loader.exe": {
                JsonObject f = file(0);
                byte[] payload = Zk1.concat(TestSupport.fileDeliveryPrefix(unhex(f.get("sealed").getAsString()),
                        unhex(f.get("signature").getAsString())), unhex(f.get("cipher").getAsString()));
                delivery(ex, eph, "file", "6f1c2a8e-file", payload);
                return;
            }
            case "/api/folders/info/assets":
                json(ex, 200, "{\"id\":\"folder-1\",\"appId\":\"app-1\",\"productId\":\"\",\"name\":\"assets\","
                        + "\"totalSize\":\"1.0 MB\",\"fileCount\":2,\"encrypted\":true,\"key\":\"\",\"iv\":\"\","
                        + "\"enc\":\"zk1\",\"downloads\":0,\"uploadedAt\":\"2026-10-01T00:00:00\"}");
                return;
            case "/api/folders/download/assets": {
                JsonObject f = file(1);
                byte[] payload = Zk1.concat(TestSupport.fileDeliveryPrefix(unhex(f.get("sealed").getAsString()),
                        unhex(f.get("signature").getAsString())), folderCipher);
                delivery(ex, eph, "folder", "folder-1", payload);
                return;
            }
            case "/api/apps/app-1/products/prod-1234/variables": {
                byte[] payload = unhex(v.getAsJsonArray("delivery").get(1).getAsJsonObject().get("payload").getAsString());
                delivery(ex, eph, "vars", "wrongproduct".equals(mode) ? "prod-other" : "prod-1234", payload);
                return;
            }
            case "/api/files/download/moved.bin":
                ex.getResponseHeaders().set("Location", "/api/files/download/legacy.bin?productId=prod-1234");
                respond(ex, 302, new byte[0], null, null, null, false);
                return;
            case "/api/files/download/legacy.bin":
                respond(ex, 200, legacyBody.clone(), "application/octet-stream", LEGACY_KEY, "mock-iv", false);
                return;
            case "/api/files/verify-hash": {
                JsonObject body = JsonParser.parseString(new String(requestBody, StandardCharsets.UTF_8)).getAsJsonObject();
                String name = body.get("fileName").getAsString();
                String keyed = body.has("keyedHash") ? body.get("keyedHash").getAsString() : null;
                String plain = body.has("hash") ? body.get("hash").getAsString() : null;
                String answer;
                if (name.equals("loader.exe") && !"askplain".equals(mode)) {
                    answer = keyed == null ? "{\"valid\":false,\"code\":\"keyed_hash_required\"}"
                            : "{\"valid\":" + keyed.equals(file(0).get("keyedHash").getAsString()) + "}";
                } else if (keyed != null) {
                    answer = "{\"valid\":false,\"code\":\"plain_hash_required\"}";
                } else {
                    answer = "{\"valid\":" + sha256Hex(name.equals("legacy.bin") ? legacyPlain : pattern(1000, 100)).equals(plain) + "}";
                }
                json(ex, 200, answer);
                return;
            }
            default:
                json(ex, 404, "{\"detail\":\"Not Found\"}");
        }
    }

    private static void delivery(HttpExchange ex, String eph, String kind, String objectId, byte[] payload) throws Exception {
        if (eph == null) {
            json(ex, 409, "{\"detail\":\"Update the SDK\",\"code\":\"e2ee_sdk_update_required\"}");
            return;
        }
        byte[] serverSecret = new byte[32];
        RANDOM.nextBytes(serverSecret);
        Object[] built = TestSupport.delivery(Zk1.b64uDecode(eph, 32), serverSecret, kind, objectId, payload);
        byte[] body = (byte[]) built[1];
        if ("corrupt".equals(mode)) body[body.length - 5] ^= 1;
        respond(ex, 200, body, "application/octet-stream", (String) built[0], null, true);
    }

    private static void json(HttpExchange ex, int status, String text) throws Exception {
        respond(ex, status, text.getBytes(StandardCharsets.UTF_8), "application/json", null, null, false);
    }

    private static void respond(HttpExchange ex, int status, byte[] body, String contentType, String encKey,
                                String encIv, boolean stream) throws Exception {
        Headers headers = ex.getResponseHeaders();
        if (contentType != null) headers.set("Content-Type", contentType);
        if (encKey != null) headers.set("X-Encryption-Key", encKey);
        if (encIv != null) headers.set("X-Encryption-IV", encIv);
        String nonce = ex.getRequestHeaders().getFirst("X-Vaultix-Nonce");
        if (nonce != null && !"unsigned".equals(mode)) {
            long signedAt = System.currentTimeMillis() / 1000 - ("oldtime".equals(mode) ? 3600 : 0);
            String query = ex.getRequestURI().getRawQuery();
            String target = ex.getRequestURI().getRawPath() + (query == null || query.isEmpty() ? "" : "?" + query);
            String signedNonce = "replay".equals(mode) ? "0123456789abcdef0123456789abcdef" : nonce;
            byte[] canonical = ResponseSigning.canonical(keyId, signedNonce, Long.toString(signedAt), ex.getRequestMethod(),
                    target, Integer.toString(status), stream ? "zk1-stream" : sha256Hex(body),
                    encKey == null ? "" : encKey, encIv == null ? "" : encIv, contentType == null ? "" : contentType);
            byte[] signature = TestSupport.ed25519Sign(signingSeed, canonical);
            if ("badsig".equals(mode)) signature[10] ^= 1;
            headers.set("X-Vaultix-Signature", Zk1.b64uEncode(signature));
            headers.set("X-Vaultix-Key-Id", keyId);
            headers.set("X-Vaultix-Signed-At", Long.toString(signedAt));
        }
        ex.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) ex.getResponseBody().write(body);
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    private VaultixClient signedIn(boolean withContentKey) {
        VaultixClient client = new VaultixClient(base);
        assertTrue(client.setTestingExtraResponseKey(keyId, publicKeyHex));
        client.setApiKey(API_KEY);
        if (withContentKey) assertTrue(client.setContentKey(appKey(0)));
        assertTrue(client.authenticateWithKey("MOCK-KEY"), client.getLastError());
        assertEquals("app-1", client.getCurrentSession().getAppId());
        assertTrue(client.hasProductAccess("prod-1234"));
        return client;
    }

    @Test
    void endToEndEncryptedDownloadsVariablesAndHashes() throws Exception {
        try (VaultixClient client = signedIn(true)) {
            byte[] data = client.downloadFileToMemory("prod-1234", "loader.exe");
            assertEquals("", client.getLastError());
            assertArrayEquals(pattern(1000, 100), data);
            assertEquals(file(0).get("signedAt").getAsLong(), client.getLastSignedAt());

            Path out = temp.resolve("sub/loader.exe");
            assertTrue(client.downloadFile("prod-1234", "loader.exe", out.toString()), client.getLastError());
            assertArrayEquals(pattern(1000, 100), Files.readAllBytes(out));
            assertFalse(Files.exists(temp.resolve("sub/loader.exe.vxpart")));

            ByteArrayOutputStream streamed = new ByteArrayOutputStream();
            long[] last = {0, 0};
            assertTrue(client.streamFile("prod-1234", "loader.exe", (chunk, received, total) -> {
                streamed.write(chunk, 0, chunk.length);
                last[0] = received;
                last[1] = total;
            }));
            assertArrayEquals(pattern(1000, 100), streamed.toByteArray());
            assertEquals(1000, last[0]);
            assertEquals(1000, last[1]);

            // folder (general scope, two chunks), asked for with a product id
            JsonObject folder = file(1);
            byte[] zip = client.downloadFolderToMemory("prod-1234", "assets");
            assertEquals("", client.getLastError());
            assertEquals(folder.get("plainSha256").getAsString(), sha256Hex(zip));
            assertEquals(folder.get("signedAt").getAsLong(), client.getLastSignedAt());
            Path zipOut = temp.resolve("assets.zip");
            assertTrue(client.downloadFolder("prod-1234", "assets", zipOut.toString()), client.getLastError());
            assertEquals(folder.get("plainSha256").getAsString(), sha256Hex(Files.readAllBytes(zipOut)));
            assertFalse(Files.exists(temp.resolve("assets.zip.vxpart")));

            Map<String, String> variables = client.getProductVariables("prod-1234");
            assertEquals("", client.getLastError());
            assertEquals("https://example.com/v1?x=ä", variables.get("apiUrl"));
            assertEquals("plain", variables.get("legacy"));

            assertTrue(client.isValidFileHash("prod-1234", "loader.exe", out.toString()), client.getLastError());
            Files.write(out, new byte[] {1}, java.nio.file.StandardOpenOption.APPEND);
            assertFalse(client.isValidFileHash("prod-1234", "loader.exe", out.toString()));

            // legacy files still work with a content key set; their hash falls back to the plain SHA-256
            byte[] legacy = client.downloadFileToMemory("prod-1234", "legacy.bin");
            assertArrayEquals(legacyPlain, legacy);
            assertEquals(0, client.getLastSignedAt());
            Path legacyOut = temp.resolve("legacy.bin");
            assertTrue(client.downloadFile("prod-1234", "legacy.bin", legacyOut.toString()));
            assertTrue(client.isValidFileHash("prod-1234", "legacy.bin", legacyOut.toString()), client.getLastError());

            // a server asking for the plain hash of a verified zk1 file is refused
            mode = "askplain";
            assertFalse(client.isValidFileHash("prod-1234", "loader.exe", legacyOut.toString()));
            assertTrue(client.getLastError().contains("plain hash of an end-to-end encrypted file"), client.getLastError());
            client.endSession();
            assertFalse(client.isSessionValid());
        }
    }

    @Test
    void corruptedDeliveriesLeaveNothingBehind() throws Exception {
        try (VaultixClient client = signedIn(true)) {
            mode = "corrupt";
            assertEquals(0, client.downloadFileToMemory("prod-1234", "loader.exe").length);
            assertTrue(client.getLastError().startsWith("End-to-end encrypted download failed: "), client.getLastError());
            assertEquals(0, client.getLastSignedAt());

            Path out = temp.resolve("loader.exe");
            assertFalse(client.downloadFile("prod-1234", "loader.exe", out.toString()));
            assertFalse(Files.exists(out));
            assertFalse(Files.exists(temp.resolve("loader.exe.vxpart")));

            // a two-chunk delivery that fails at its last chunk
            Path zip = temp.resolve("assets.zip");
            Files.write(zip, new byte[] {7});  // an older copy stays untouched
            assertFalse(client.downloadFolder("prod-1234", "assets", zip.toString()));
            assertArrayEquals(new byte[] {7}, Files.readAllBytes(zip));
            assertFalse(Files.exists(temp.resolve("assets.zip.vxpart")));

            assertTrue(client.getProductVariables("prod-1234").isEmpty());
            assertFalse(client.getLastError().isEmpty());
            mode = "wrongproduct";
            assertTrue(client.getProductVariables("prod-1234").isEmpty());
            assertTrue(client.getLastError().contains("another product"), client.getLastError());
        }
    }

    @Test
    void contentKeyIsRequiredAndMustMatch() throws Exception {
        try (VaultixClient client = signedIn(false)) {
            assertEquals(0, client.downloadFileToMemory("prod-1234", "loader.exe").length);
            assertEquals(Zk1.NEED_CONTENT_KEY, client.getLastError());
            Path out = temp.resolve("x.exe");
            assertFalse(client.downloadFile("prod-1234", "loader.exe", out.toString()));
            assertFalse(Files.exists(out));
            assertTrue(client.getProductVariables("prod-1234").isEmpty());
            assertEquals(Zk1.NEED_CONTENT_KEY, client.getLastError());
            // legacy content needs no key
            assertArrayEquals(legacyPlain, client.downloadFileToMemory("prod-1234", "legacy.bin"));

            assertTrue(client.setContentKey(appKey(1)));  // another app's key
            assertEquals(0, client.downloadFileToMemory("prod-1234", "loader.exe").length);
            assertTrue(client.getLastError().contains("cannot open the sealed file key"), client.getLastError());
        }
    }

    @Test
    void responsesThatCannotBeVerifiedAreRefused() throws Exception {
        // without the testing hook the mock's key is unknown: login refused
        try (VaultixClient untrusted = new VaultixClient(base)) {
            untrusted.setApiKey(API_KEY);
            assertFalse(untrusted.authenticateWithKey("MOCK-KEY"));
            assertTrue(untrusted.getLastError().startsWith("Server response could not be verified (HTTP 200): unknown signing key"),
                    untrusted.getLastError());
            assertFalse(untrusted.isSessionValid());
        }
        try (VaultixClient client = signedIn(true)) {
            mode = "badsig";
            assertEquals(0, client.downloadFileToMemory("prod-1234", "legacy.bin").length);
            assertTrue(client.getLastError().contains("invalid signature"), client.getLastError());
            assertEquals(0, client.downloadFileToMemory("prod-1234", "loader.exe").length);
            assertTrue(client.getLastError().startsWith("Server response could not be verified (HTTP 200): invalid signature"),
                    client.getLastError());

            mode = "ok";
            assertEquals(0, client.downloadFileToMemory("prod-1234", "moved.bin").length);
            assertTrue(client.getLastError().endsWith("the request was redirected"), client.getLastError());

            mode = "replay";
            assertTrue(client.getProductVariables("prod-1234").isEmpty());
            assertTrue(client.getLastError().contains("invalid signature"), client.getLastError());

            mode = "oldtime";
            assertEquals(0, client.downloadFileToMemory("prod-1234", "legacy.bin").length);
            assertTrue(client.getLastError().contains("differs from this computer's clock"), client.getLastError());
            client.setResponseClockSkewTolerance(7200);
            assertArrayEquals(legacyPlain, client.downloadFileToMemory("prod-1234", "legacy.bin"));
            client.setResponseClockSkewTolerance(0);  // back to the default

            mode = "unsigned";
            assertEquals(0, client.downloadFileToMemory("prod-1234", "legacy.bin").length);
            assertTrue(client.getLastError().endsWith("the response is not signed"), client.getLastError());
            // with checks off, unsigned legacy responses pass, but deliveries are always verified
            client.setRequireSignedResponses(false);
            assertArrayEquals(legacyPlain, client.downloadFileToMemory("prod-1234", "legacy.bin"));
            assertEquals(0, client.downloadFileToMemory("prod-1234", "loader.exe").length);
            assertTrue(client.getLastError().endsWith("the response is not signed"), client.getLastError());
            mode = "badsig";
            assertEquals(0, client.downloadFileToMemory("prod-1234", "loader.exe").length);
            assertTrue(client.getLastError().contains("invalid signature"), client.getLastError());
            mode = "ok";
            assertNotNull(client.downloadFileToMemory("prod-1234", "loader.exe"));
            assertEquals("", client.getLastError());
        }
    }
}
