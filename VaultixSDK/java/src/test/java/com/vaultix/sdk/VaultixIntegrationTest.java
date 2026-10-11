package com.vaultix.sdk;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.vaultix.sdk.TestSupport.sha256Hex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Against a running Vaultix test backend described by a fixture file
 * (-Dvaultix.fixture=PATH or VAULTIX_SDK_FIXTURE). Skipped without one.
 * Read-only: log in, download, verify hashes, log out.
 */
@EnabledIf("fixturePresent")
class VaultixIntegrationTest {

    private static JsonObject fixture;
    private static String baseUrl;
    private static String testKeyId;
    private static String testKeyHex;
    private static JsonObject e2ee;
    private static JsonObject legacy;

    @TempDir
    Path temp;

    static boolean fixturePresent() {
        Path path = TestSupport.fixturePath();
        return path != null && Files.isRegularFile(path);
    }

    @BeforeAll
    static void loadFixture() throws IOException {
        Path path = TestSupport.fixturePath();
        fixture = JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8)).getAsJsonObject();
        baseUrl = fixture.get("baseUrl").getAsString();
        testKeyId = fixture.getAsJsonObject("testResponseKey").get("keyId").getAsString();
        testKeyHex = fixture.getAsJsonObject("testResponseKey").get("publicKeyHex").getAsString();
        e2ee = fixture.getAsJsonObject("e2ee");
        legacy = fixture.getAsJsonObject("legacy");
        System.out.println("integration backend " + baseUrl + " (test response key " + testKeyId + ")");
    }

    private static String s(JsonObject o, String key) {
        return o.get(key).getAsString();
    }

    private static VaultixClient client(JsonObject app, boolean trustTestKey) {
        VaultixClient client = new VaultixClient(baseUrl);
        if (trustTestKey) assertTrue(client.setTestingExtraResponseKey(testKeyId, testKeyHex));
        client.setApiKey(s(app, "apiKey"));
        return client;
    }

    private static Map<String, byte[]> unzip(byte[] zip) throws IOException {
        Map<String, byte[]> entries = new HashMap<>();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                if (!entry.isDirectory()) entries.put(entry.getName(), in.readAllBytes());
            }
        }
        return entries;
    }

    private static void checkToolsZip(byte[] zip) throws IOException {
        Map<String, byte[]> entries = unzip(zip);
        System.out.println("      folder zip entries: " + entries.keySet());
        assertTrue(entries.containsKey("bin/app.exe"), entries.keySet().toString());
        assertEquals(3000, entries.get("bin/app.exe").length);
        assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), entries.get("readme.txt"));
    }

    @Test
    void endToEndEncryptedApp() throws Exception {
        String product = s(e2ee, "productId");
        String fileName = s(e2ee.getAsJsonObject("file"), "name");
        String expected = s(e2ee.getAsJsonObject("file"), "sha256");
        try (VaultixClient client = client(e2ee, true)) {
            assertTrue(client.setContentKey(s(e2ee, "contentKey")));
            System.out.println("      content key fingerprint " + client.getContentKeyFingerprint());
            assertTrue(client.authenticateWithKey(s(e2ee, "licenseKey")), client.getLastError());

            byte[] data = client.downloadFileToMemory(product, fileName);
            assertEquals("", client.getLastError());
            assertEquals(expected, sha256Hex(data), "zk1 file SHA-256");
            System.out.println("      zk1 file: " + data.length + " bytes, sha256 match, signed at " + client.getLastSignedAt());

            byte[] again = client.downloadFileToMemory(product, fileName);
            assertEquals(expected, sha256Hex(again), "second download (new one-time key)");
            assertTrue(client.getLastSignedAt() > 0, "getLastSignedAt");

            Path out = temp.resolve("downloads/" + fileName);
            assertTrue(client.downloadFile(product, fileName, out.toString()), client.getLastError());
            assertEquals(expected, sha256Hex(Files.readAllBytes(out)));
            assertFalse(Files.exists(Path.of(out + ".vxpart")), "no .vxpart left");
            try (var listing = Files.list(out.getParent())) {
                assertEquals(1, listing.count());
            }

            ByteArrayOutputStream streamed = new ByteArrayOutputStream();
            assertTrue(client.streamFile(product, fileName, (chunk, received, total) -> streamed.write(chunk, 0, chunk.length)));
            assertEquals(expected, sha256Hex(streamed.toByteArray()));

            String folderName = s(e2ee.getAsJsonObject("folder"), "name");
            byte[] zip = client.downloadFolderToMemory(product, folderName);
            assertEquals("", client.getLastError());
            checkToolsZip(zip);
            assertTrue(client.getLastSignedAt() > 0);
            Path zipOut = temp.resolve("Tools.zip");
            assertTrue(client.downloadFolder(product, folderName, zipOut.toString()), client.getLastError());
            checkToolsZip(Files.readAllBytes(zipOut));
            assertFalse(Files.exists(Path.of(zipOut + ".vxpart")));

            Map<String, String> variables = client.getProductVariables(product);
            assertEquals("", client.getLastError());
            JsonObject variable = e2ee.getAsJsonObject("variable");
            assertEquals(s(variable, "value"), variables.get(s(variable, "name")));
            System.out.println("      variables: " + variables.keySet());

            assertTrue(client.isValidFileHash(product, fileName, out.toString()), client.getLastError());
            Files.write(out, new byte[] {'x'}, StandardOpenOption.APPEND);
            assertFalse(client.isValidFileHash(product, fileName, out.toString()));

            FileInfo info = client.getFileInfo(product, fileName);
            assertTrue(info != null && info.getName().equals(fileName), client.getLastError());
            List<FileInfo> list = client.getFileList(product);
            System.out.println("      getFileList: " + list.size() + " entries; lastError='" + client.getLastError() + "'");
            client.endSession();
        }
    }

    @Test
    void otherReadOnlyCalls() throws Exception {
        String product = s(e2ee, "productId");
        try (VaultixClient client = client(e2ee, true)) {
            assertTrue(client.authenticateWithKey(s(e2ee, "licenseKey")), client.getLastError());
            assertTrue(client.hasProductAccess(product));

            List<Map<String, String>> products = client.getUserProducts();
            assertEquals("", client.getLastError());
            assertTrue(products.stream().anyMatch(p -> product.equals(p.get("id"))), products.toString());

            SubscriptionInfo subscription = client.getUserSubscriptionByProduct(product);
            assertEquals("", client.getLastError());
            assertEquals(product, subscription.getProductId());

            ProductStatusInfo status = client.getProductStatus(product);
            assertEquals("", client.getLastError());
            ProductNewsInfo news = client.getProductNews(product);
            assertEquals("", client.getLastError());
            AccountInfo account = client.getAccountInfo();
            assertTrue(account != null, client.getLastError());

            FolderInfo folder = client.getFolderInfo(product, s(e2ee.getAsJsonObject("folder"), "name"));
            assertTrue(folder != null && !folder.getId().isEmpty(), client.getLastError());
            List<FolderInfo> folders = client.getFolderList(product);
            System.out.println("      products " + products.size() + ", subscription " + subscription.getStatus()
                    + ", status " + status.hasStatus() + ", news " + news.hasNews() + ", folder info "
                    + folder.getName() + ", getFolderList: " + folders.size() + " entries; lastError='"
                    + client.getLastError() + "'");

            // auto-login, if the app hands out persistent tokens
            try (VaultixClient again = client(e2ee, true)) {
                if (again.tryAutoLogin()) {
                    System.out.println("      tryAutoLogin: ok");
                    assertTrue(again.isSessionValid());
                    again.clearAutoLoginToken();
                    again.endSession();
                } else {
                    System.out.println("      tryAutoLogin: " + again.getLastError());
                    assertFalse(again.getLastError().startsWith("Server response could not be verified"), again.getLastError());
                }
            }
            client.endSession();
        }
    }

    @Test
    void withoutOrWithTheWrongContentKeyNothingIsReturned() throws Exception {
        String product = s(e2ee, "productId");
        String fileName = s(e2ee.getAsJsonObject("file"), "name");
        try (VaultixClient client = client(e2ee, true)) {
            assertTrue(client.authenticateWithKey(s(e2ee, "licenseKey")), client.getLastError());
            byte[] none = client.downloadFileToMemory(product, fileName);
            assertEquals(0, none.length);
            assertTrue(client.getLastError().contains("setContentKey"), client.getLastError());
            System.out.println("      without content key: " + client.getLastError());
            Path out = temp.resolve("none.bin");
            assertFalse(client.downloadFile(product, fileName, out.toString()));
            assertFalse(Files.exists(out));
            assertFalse(Files.exists(Path.of(out + ".vxpart")));

            assertTrue(client.setContentKey(s(e2ee, "wrongContentKey")));
            byte[] wrong = client.downloadFileToMemory(product, fileName);
            assertEquals(0, wrong.length);
            assertFalse(client.getLastError().isEmpty());
            System.out.println("      with the wrong content key: " + client.getLastError());
            assertTrue(client.getProductVariables(product).isEmpty());
            assertFalse(client.getLastError().isEmpty());
            client.endSession();
        }
    }

    @Test
    void legacyAppStillWorks() throws Exception {
        String product = s(legacy, "productId");
        JsonObject file = legacy.getAsJsonObject("file");
        try (VaultixClient client = client(legacy, true)) {
            assertTrue(client.authenticateWithKey(s(legacy, "licenseKey")), client.getLastError());
            byte[] data = client.downloadFileToMemory(product, s(file, "name"));
            assertEquals("", client.getLastError());
            assertEquals(file.get("size").getAsInt(), data.length);
            assertEquals(s(file, "sha256"), sha256Hex(data));
            assertEquals(0, client.getLastSignedAt());
            Path out = temp.resolve(s(file, "name"));
            assertTrue(client.downloadFile(product, s(file, "name"), out.toString()), client.getLastError());
            assertEquals(s(file, "sha256"), sha256Hex(Files.readAllBytes(out)));
            assertTrue(client.isValidFileHash(product, s(file, "name"), out.toString()), client.getLastError());
            System.out.println("      legacy file: " + data.length + " bytes, sha256 match");
            client.endSession();
        }
    }

    @Test
    void withoutTheTestingHookEveryResponseIsRefused() throws Exception {
        String unknown = "unknown signing key '" + testKeyId + "'";
        try (VaultixClient client = client(e2ee, false)) {
            assertFalse(client.authenticateWithKey(s(e2ee, "licenseKey")));
            assertTrue(client.getLastError().startsWith("Server response could not be verified"), client.getLastError());
            assertTrue(client.getLastError().contains(unknown), client.getLastError());
            assertFalse(client.isSessionValid());
            System.out.println("      no testing hook, login: " + client.getLastError());
        }
        try (VaultixClient client = client(legacy, false)) {
            assertFalse(client.authenticateWithKey(s(legacy, "licenseKey")));
            assertTrue(client.getLastError().contains(unknown), client.getLastError());

            // Sign in with checks off (testing only), then turn them back on: every call is refused.
            client.setRequireSignedResponses(false);
            client.setApiKey(s(legacy, "apiKey"));
            assertTrue(client.authenticateWithKey(s(legacy, "licenseKey")), client.getLastError());
            client.setRequireSignedResponses(true);
            String product = s(legacy, "productId");
            String fileName = s(legacy.getAsJsonObject("file"), "name");
            assertEquals(0, client.downloadFileToMemory(product, fileName).length);
            assertTrue(client.getLastError().contains(unknown), client.getLastError());
            assertEquals(null, client.getFileInfo(product, fileName));
            assertTrue(client.getLastError().contains(unknown), client.getLastError());
            assertTrue(client.getProductVariables(product).isEmpty());
            assertTrue(client.getLastError().contains(unknown), client.getLastError());
            Path local = temp.resolve("local.bin");
            Files.write(local, new byte[] {1, 2, 3});
            assertFalse(client.isValidFileHash(product, fileName, local.toString()));
            assertTrue(client.getLastError().contains(unknown), client.getLastError());
            client.endSession();
        }
        // zk1 deliveries are verified even with setRequireSignedResponses(false).
        try (VaultixClient client = client(e2ee, false)) {
            client.setRequireSignedResponses(false);
            assertTrue(client.setContentKey(s(e2ee, "contentKey")));
            assertTrue(client.authenticateWithKey(s(e2ee, "licenseKey")), client.getLastError());
            byte[] data = client.downloadFileToMemory(s(e2ee, "productId"), s(e2ee.getAsJsonObject("file"), "name"));
            assertEquals(0, data.length);
            assertTrue(client.getLastError().startsWith("Server response could not be verified (HTTP 200): " + unknown),
                    client.getLastError());
            assertTrue(client.getProductVariables(s(e2ee, "productId")).isEmpty());
            assertTrue(client.getLastError().contains(unknown), client.getLastError());
            System.out.println("      no testing hook, zk1 download with checks off: " + client.getLastError());
            client.endSession();
        }
    }
}
