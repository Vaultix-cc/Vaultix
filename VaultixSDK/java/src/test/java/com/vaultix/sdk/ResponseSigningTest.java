package com.vaultix.sdk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import static com.vaultix.sdk.TestSupport.unhex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** vaultix-resp-v1 against backend/tests/response_signing_golden.json, plus client configuration without a network. */
class ResponseSigningTest {

    @Test
    void goldenVectorsVerify() throws Exception {
        JsonObject golden = TestSupport.responseGolden();
        byte[] publicKey = unhex(golden.get("public_key_hex").getAsString());
        String keyId = golden.get("key_id").getAsString();
        assertEquals(keyId, ResponseSigning.keyIdFor(publicKey));
        for (JsonElement e : golden.getAsJsonArray("vectors")) {
            JsonObject g = e.getAsJsonObject();
            byte[] body = unhex(g.get("body_hex").getAsString());
            assertEquals(g.get("body_sha256").getAsString(), TestSupport.sha256Hex(body));
            byte[] canonical = ResponseSigning.canonical(keyId, g.get("nonce").getAsString(),
                    Long.toString(g.get("signed_at").getAsLong()), g.get("method").getAsString(),
                    g.get("path_and_query").getAsString(), Integer.toString(g.get("status").getAsInt()),
                    TestSupport.sha256Hex(body), g.get("encryption_key").getAsString(),
                    g.get("encryption_iv").getAsString(), g.get("content_type").getAsString());
            assertArrayEquals(g.get("canonical").getAsString().getBytes(StandardCharsets.UTF_8), canonical);
            byte[] signature = Zk1.b64uDecode(g.get("signature").getAsString(), 64);
            assertTrue(Zk1.ed25519Verify(publicKey, canonical, signature));
            byte[] altered = canonical.clone();
            altered[altered.length - 1] ^= 1;
            assertFalse(Zk1.ed25519Verify(publicKey, altered, signature));
        }
        assertNull(ResponseSigning.canonical(keyId, "nonce\n", "1", "GET", "/", "200", "x", "", "", ""));
    }

    @Test
    void builtInKeysMatchTheirIds() {
        assertTrue(ResponseSigning.TRUSTED_RESPONSE_KEYS.length > 0);
        for (String[] key : ResponseSigning.TRUSTED_RESPONSE_KEYS) {
            byte[] publicKey = Zk1.fromHex32(key[1]);
            assertEquals(key[0], ResponseSigning.keyIdFor(publicKey));
            assertFalse(Zk1.isWeakEd25519PublicKey(publicKey));
        }
        assertEquals("vx-sig-22545e6918734982", ResponseSigning.TRUSTED_RESPONSE_KEYS[0][0]);
        assertNull(ResponseSigning.trustedPublicKey("vx-sig-0000000000000000"));
        assertEquals("abc???", ResponseSigning.printable("abc<>\n"));
    }

    @Test
    void requestTargets() {
        assertEquals("Tools%20Valuables.json", VaultixClient.urlEncode("Tools Valuables.json"));
        assertEquals("%C3%BC-_.~a", VaultixClient.urlEncode("ü-_.~a"));
        assertEquals("/api/files/download/a%20b?productId=p-1",
                VaultixClient.pathAndQuery(URI.create("http://127.0.0.1:5098/api/files/download/a%20b?productId=p-1")));
        assertEquals("/api/me", VaultixClient.pathAndQuery(URI.create("https://vaultix.cc/api/me")));
    }

    @Test
    void contentKeyAndTestingKeyConfiguration() throws Exception {
        JsonObject vectors = TestSupport.zk1Vectors();
        JsonObject app = vectors.getAsJsonArray("appKeys").get(0).getAsJsonObject();
        JsonObject other = vectors.getAsJsonArray("appKeys").get(1).getAsJsonObject();
        try (VaultixClient client = new VaultixClient("http://127.0.0.1:9/api")) {
            assertFalse(client.hasContentKey());
            assertEquals("", client.getContentKeyFingerprint());
            assertTrue(client.setContentKey(app.get("sdkKey").getAsString()));
            assertEquals(app.get("fingerprint").getAsString(), client.getContentKeyFingerprint());
            // an invalid key returns false and keeps the old key
            assertFalse(client.setContentKey("vxk_invalid"));
            assertTrue(client.getLastError().startsWith("Invalid content key"));
            assertEquals(app.get("fingerprint").getAsString(), client.getContentKeyFingerprint());
            assertTrue(client.setContentKey(other.get("sdkKey").getAsString()));
            assertEquals(other.get("fingerprint").getAsString(), client.getContentKeyFingerprint());
            client.clearContentKey();
            assertFalse(client.hasContentKey());

            JsonObject golden = TestSupport.responseGolden();
            assertFalse(client.setTestingExtraResponseKey("vx-sig-0000000000000000", golden.get("public_key_hex").getAsString()));
            assertFalse(client.setTestingExtraResponseKey(golden.get("key_id").getAsString(), "zz"));
            assertTrue(client.setTestingExtraResponseKey(golden.get("key_id").getAsString(), golden.get("public_key_hex").getAsString()));
            assertTrue(client.setTestingExtraResponseKey(null, null));

            assertTrue(client.getRequireSignedResponses());
            // no session: nothing is sent
            assertEquals(0, client.downloadFileToMemory("p", "f").length);
            assertEquals("No valid session", client.getLastError());
            assertFalse(client.downloadFile("p", "f", "/tmp/x"));
            assertEquals(0, client.downloadFolderToMemory("p", "f").length);
            assertTrue(client.getProductVariables("p").isEmpty());
            assertEquals(0, client.getLastSignedAt());
        }
    }
}
