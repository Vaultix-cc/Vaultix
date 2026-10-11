package com.vaultix.sdk;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.vaultix.sdk.TestSupport.hex;
import static com.vaultix.sdk.TestSupport.pattern;
import static com.vaultix.sdk.TestSupport.sha256Hex;
import static com.vaultix.sdk.TestSupport.unhex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The SDK side of crypto_vectors/zk1.json, byte for byte, plus failure cases. */
class Zk1VectorsTest {

    private static JsonObject v;
    private static String appId;

    @BeforeAll
    static void load() throws Exception {
        v = TestSupport.zk1Vectors();
        appId = v.get("appId").getAsString();
        System.out.println("zk1 vectors from " + TestSupport.vectorsSource() + " (format "
                + v.get("format").getAsString() + " v" + v.get("version").getAsInt() + ")");
    }

    private static JsonObject kat(String name, int index) {
        return v.getAsJsonObject("kat").getAsJsonArray(name).get(index).getAsJsonObject();
    }

    private static JsonArray list(String name) {
        return v.getAsJsonArray(name);
    }

    private static JsonObject item(String name, int index) {
        return list(name).get(index).getAsJsonObject();
    }

    private static String s(JsonObject o, String key) {
        return o.get(key).getAsString();
    }

    private static byte[] h(JsonObject o, String key) {
        return unhex(s(o, key));
    }

    private static Zk1.ContentKey appKey(int index) {
        return Zk1.ContentKey.fromSdkKey(s(item("appKeys", index), "sdkKey"));
    }

    // ------------------------------------------------------------------
    // Primitives
    // ------------------------------------------------------------------

    @Test
    void hkdfRfc5869TestCase1() {
        byte[] okm = Zk1.hkdfSha256(unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                unhex("000102030405060708090a0b0c"), unhex("f0f1f2f3f4f5f6f7f8f9"), 42);
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", hex(okm));
        for (JsonElement e : v.getAsJsonObject("kat").getAsJsonArray("hkdf")) {
            JsonObject k = e.getAsJsonObject();
            assertEquals(s(k, "okm"), hex(Zk1.hkdfSha256(h(k, "ikm"), h(k, "salt"), h(k, "info"), k.get("length").getAsInt())));
        }
    }

    @Test
    void x25519Rfc7748() {
        // RFC 7748 section 5.2, first vector
        assertEquals("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                hex(Zk1.x25519Shared(unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                        unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))));
        for (JsonElement e : v.getAsJsonObject("kat").getAsJsonArray("x25519")) {
            JsonObject k = e.getAsJsonObject();
            assertEquals(s(k, "out"), hex(Zk1.x25519Shared(h(k, "scalar"), h(k, "u"))));
        }
        for (JsonElement e : v.getAsJsonObject("kat").getAsJsonArray("x25519_public")) {
            JsonObject k = e.getAsJsonObject();
            assertEquals(s(k, "public"), hex(Zk1.x25519Public(h(k, "scalar"))));
        }
        // Low-order peer keys give an all-zero secret: refused.
        byte[] scalar = h(kat("x25519", 0), "scalar");
        assertNull(Zk1.x25519Shared(scalar, new byte[32]));
        byte[] one = new byte[32];
        one[0] = 1;
        assertNull(Zk1.x25519Shared(scalar, one));
        assertNull(Zk1.x25519Shared(scalar, new byte[31]));
    }

    @Test
    void ed25519Rfc8032AndWeakKeys() {
        JsonObject k = kat("ed25519", 0);
        byte[] publicKey = h(k, "public");
        byte[] signature = h(k, "signature");
        byte[] message = h(k, "message");
        assertTrue(Zk1.ed25519Verify(publicKey, message, signature));
        byte[] bad = signature.clone();
        bad[0] ^= 1;
        assertFalse(Zk1.ed25519Verify(publicKey, message, bad));
        assertFalse(Zk1.ed25519Verify(publicKey, new byte[] {1}, signature));
        // Small-order and non-canonical keys are refused before verification.
        byte[] identity = new byte[32];
        identity[0] = 1;
        assertTrue(Zk1.isWeakEd25519PublicKey(identity));
        byte[] trivialSignature = new byte[64];
        trivialSignature[0] = 1;  // R = identity, S = 0
        assertFalse(Zk1.ed25519Verify(identity, new byte[] {42}, trivialSignature));
        byte[] p = unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assertTrue(Zk1.isWeakEd25519PublicKey(p));
        assertFalse(Zk1.isWeakEd25519PublicKey(publicKey));
    }

    @Test
    void hmacAesGcmPbkdf2Kats() throws Exception {
        JsonObject hm = kat("hmac_sha256", 0);
        assertEquals(s(hm, "mac"), hex(Zk1.hmacSha256(h(hm, "key"), h(hm, "data"))));
        for (JsonElement e : v.getAsJsonObject("kat").getAsJsonArray("aes_gcm")) {
            JsonObject g = e.getAsJsonObject();
            byte[] in = Zk1.concat(h(g, "ciphertext"), h(g, "tag"));
            assertEquals(s(g, "plaintext"), hex(Zk1.aesGcmDecrypt(h(g, "key"), h(g, "nonce"), h(g, "aad"), in, 0, in.length)));
        }
        JsonObject pb = kat("pbkdf2_sha256", 0);
        assertEquals(s(pb, "dk"), hex(Zk1.pbkdf2Sha256(s(pb, "password").getBytes(StandardCharsets.UTF_8),
                h(pb, "salt"), pb.get("iterations").getAsInt(), 32)));
    }

    @Test
    void base64url() {
        byte[] data = pattern(100, 3);
        for (int n = 0; n < data.length; n++) {
            byte[] part = Arrays.copyOf(data, n);
            String text = Zk1.b64uEncode(part);
            assertFalse(text.contains("="));
            if (n > 0) assertArrayEquals(part, Zk1.b64uDecode(text, 100));
        }
        assertNull(Zk1.b64uDecode("", 10));
        assertNull(Zk1.b64uDecode("AAAA=", 10));   // padding is not base64url here
        assertNull(Zk1.b64uDecode("AA+A", 10));
        assertNull(Zk1.b64uDecode("AAAAA", 10));   // length % 4 == 1
        assertNull(Zk1.b64uDecode("AAAAAAAAAAAAAAAAAAAA", 4));  // too long
    }

    // ------------------------------------------------------------------
    // Keys
    // ------------------------------------------------------------------

    @Test
    void sdkKeyDecodeFingerprintAndHashKey() {
        for (JsonElement e : list("appKeys")) {
            JsonObject a = e.getAsJsonObject();
            byte[][] parts = Zk1.sdkKeyDecode(s(a, "sdkKey"));
            assertNotNull(parts);
            assertEquals(s(a, "sdkSecret"), hex(parts[0]));
            assertEquals(s(a, "signPublic"), hex(parts[1]));
            Zk1.ContentKey key = Zk1.ContentKey.fromSdkKey(s(a, "sdkKey"));
            assertNotNull(key);
            assertEquals(s(a, "sdkPublic"), hex(key.sdkPublic()));
            assertEquals(s(a, "hashKey"), hex(Zk1.hashKey(parts[0])));
            assertEquals(s(a, "hashKey"), hex(key.hashKey));
            assertEquals(s(a, "fingerprint"), key.fingerprint());
            assertEquals(s(a, "fingerprint"), Zk1.fingerprint(h(a, "sdkPublic"), h(a, "signPublic")));
            assertNotNull(Zk1.sdkKeyDecode(" \t" + s(a, "sdkKey") + "\r\n"));
        }
    }

    @Test
    void invalidSdkKeysAreRefused() {
        JsonObject a = item("appKeys", 0);
        String good = s(a, "sdkKey");
        assertEquals(Zk1.SDK_KEY_CHARS, good.length());
        // checksum: change the last character
        char last = good.charAt(good.length() - 1);
        assertNull(Zk1.sdkKeyDecode(good.substring(0, good.length() - 1) + (last == 'A' ? 'B' : 'A')));
        // key bytes changed (checksum no longer matches)
        char c = good.charAt(10);
        assertNull(Zk1.sdkKeyDecode(good.substring(0, 10) + (c == 'A' ? 'B' : 'A') + good.substring(11)));
        // version 1 with a valid checksum
        byte[] body = Zk1.concat(new byte[] {1}, h(a, "sdkSecret"), h(a, "signPublic"));
        byte[] check = Arrays.copyOf(Zk1.sha256("vaultix-vxk".getBytes(StandardCharsets.US_ASCII), body), 4);
        String v1 = "vxk_" + Zk1.b64uEncode(Zk1.concat(body, check));
        assertEquals(96, v1.length());
        assertNull(Zk1.sdkKeyDecode(v1));
        assertNull(Zk1.sdkKeyDecode("vxx_" + good.substring(4)));
        assertNull(Zk1.sdkKeyDecode(good.substring(0, 95)));
        assertNull(Zk1.sdkKeyDecode(good.substring(0, 50) + "+" + good.substring(51)));
        assertNull(Zk1.sdkKeyDecode(null));
        assertNull(Zk1.ContentKey.fromSdkKey("vxk_"));
    }

    @Test
    void keyedHashes() {
        Zk1.ContentKey key = appKey(0);
        for (JsonElement e : list("files")) {
            JsonObject f = e.getAsJsonObject();
            assertEquals(s(f, "keyedHash"), hex(Zk1.keyedHash(key.hashKey, h(f, "plainSha256"))));
        }
        for (JsonElement e : list("variables")) {
            JsonObject var = e.getAsJsonObject();
            byte[] digest = Zk1.sha256(s(var, "value").getBytes(StandardCharsets.UTF_8));
            assertEquals(s(var, "keyedHash"), hex(Zk1.keyedHash(key.hashKey, digest)));
        }
    }

    // ------------------------------------------------------------------
    // Seal
    // ------------------------------------------------------------------

    @Test
    void unsealVectors() throws Exception {
        JsonObject a = item("appKeys", 0);
        byte[] secret = h(a, "sdkSecret");
        byte[] otherSecret = h(item("appKeys", 1), "sdkSecret");
        for (JsonElement e : list("seal")) {
            JsonObject sv = e.getAsJsonObject();
            byte[] context = Zk1.sealContext(s(sv, "kind"), s(sv, "name"), s(sv, "productId"));
            assertEquals(s(sv, "context"), hex(context));
            byte[] sealed = h(sv, "sealed");
            assertArrayEquals(sealed, TestSupport.seal(h(a, "sdkPublic"), h(sv, "payload"), context, h(sv, "ephSecret")));
            assertEquals(s(sv, "payload"), hex(Zk1.unseal(secret, sealed, context)));

            byte[] tampered = sealed.clone();
            tampered[tampered.length - 1] ^= 1;
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.unseal(secret, tampered, context));
            byte[] otherContext = Zk1.sealContext(s(sv, "kind"), s(sv, "name") + "x", s(sv, "productId"));
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.unseal(secret, sealed, otherContext));
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.unseal(otherSecret, sealed, context));
            byte[] version2 = sealed.clone();
            version2[0] = 2;
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.unseal(secret, version2, context));
        }
        assertEquals(0, Zk1.sealContext("grant", "x", "").length);
    }

    // ------------------------------------------------------------------
    // Signed messages and signature blocks
    // ------------------------------------------------------------------

    @Test
    void messagesMatchVectors() {
        for (JsonElement e : list("certs")) {
            JsonObject c = e.getAsJsonObject();
            byte[] member = Zk1.memberMessage(s(c, "appId"), s(c, "userId"), h(c, "encPublic"), h(c, "signPublic"),
                    c.get("issuedAt").getAsLong());
            assertEquals(s(c, "message"), hex(member));
            assertTrue(Zk1.ed25519Verify(h(item("appKeys", 0), "signPublic"), member, h(c, "signature")));
        }
        for (JsonElement e : list("files")) {
            JsonObject f = e.getAsJsonObject();
            byte[] message = Zk1.uploadMessage(appId, s(f, "kind"), s(f, "productId"), s(f, "name"), h(f, "keyedHash"),
                    f.get("plainLength").getAsLong(), f.get("signedAt").getAsLong());
            assertEquals(s(f, "uploadMessage"), hex(message));
        }
        for (JsonElement e : list("variables")) {
            JsonObject var = e.getAsJsonObject();
            byte[] message = Zk1.variableMessage(appId, s(var, "productId"), s(var, "name"), h(var, "keyedHash"),
                    var.get("signedAt").getAsLong());
            assertEquals(s(var, "message"), hex(message));
        }
        assertNull(Zk1.uploadMessage(appId, "var", "", "x", new byte[32], 0, 0));
        assertNull(Zk1.uploadMessage(appId, "file", "", "a\0b", new byte[32], 0, 0));
        assertNull(Zk1.variableMessage("a\0", "p", "n", new byte[32], 0));
    }

    @Test
    void signatureBlocksVerifyAndTamperedOnesFail() throws Exception {
        byte[] appSign = h(item("appKeys", 0), "signPublic");
        byte[] otherAppSign = h(item("appKeys", 1), "signPublic");
        for (JsonElement e : list("files")) {
            JsonObject f = e.getAsJsonObject();
            byte[] block = h(f, "signature");
            byte[] keyed = h(f, "keyedHash");
            long size = f.get("plainLength").getAsLong();
            String kind = s(f, "kind"), scope = s(f, "productId"), name = s(f, "name");
            Zk1.SignatureBlock parsed = Zk1.verifySignatureBlock(block, 0, block.length, appId, appSign,
                    at -> Zk1.uploadMessage(appId, kind, scope, name, keyed, size, at));
            assertEquals(f.get("signedAt").getAsLong(), parsed.signedAtMs);
            assertEquals(s(f, "uploader"), parsed.userId);

            byte[] badSig = block.clone();
            badSig[badSig.length - 1] ^= 1;
            assertEquals("invalid signature", assertThrows(Zk1.Zk1Exception.class, () -> Zk1.verifySignatureBlock(
                    badSig, 0, badSig.length, appId, appSign,
                    at -> Zk1.uploadMessage(appId, kind, scope, name, keyed, size, at))).getMessage());

            byte[] badCert = block.clone();
            int certAt = 3 + parsed.userId.getBytes(StandardCharsets.UTF_8).length + 32 + 32 + 8;
            badCert[certAt + 5] ^= 1;
            assertEquals("the signer is not approved by the app owner", assertThrows(Zk1.Zk1Exception.class,
                    () -> Zk1.verifySignatureBlock(badCert, 0, badCert.length, appId, appSign,
                            at -> Zk1.uploadMessage(appId, kind, scope, name, keyed, size, at))).getMessage());

            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.verifySignatureBlock(block, 0, block.length, "app-2", appSign,
                    at -> Zk1.uploadMessage("app-2", kind, scope, name, keyed, size, at)));
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.verifySignatureBlock(block, 0, block.length, appId, otherAppSign,
                    at -> Zk1.uploadMessage(appId, kind, scope, name, keyed, size, at)));
            assertEquals("invalid signature", assertThrows(Zk1.Zk1Exception.class, () -> Zk1.verifySignatureBlock(
                    block, 0, block.length, appId, appSign,
                    at -> Zk1.uploadMessage(appId, kind, scope, name, keyed, size + 1, at))).getMessage());
            assertEquals("invalid signature block", assertThrows(Zk1.Zk1Exception.class, () -> Zk1.verifySignatureBlock(
                    block, 0, block.length - 1, appId, appSign, at -> new byte[1])).getMessage());
            byte[] version2 = block.clone();
            version2[0] = 2;
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.verifySignatureBlock(version2, 0, version2.length, appId,
                    appSign, at -> Zk1.uploadMessage(appId, kind, scope, name, keyed, size, at)));
        }
    }

    // ------------------------------------------------------------------
    // Stream
    // ------------------------------------------------------------------

    @Test
    void streamVectorsDecrypt() throws Exception {
        for (JsonElement e : list("stream")) {
            JsonObject st = e.getAsJsonObject();
            byte[] key = h(st, "key");
            byte[] plain = pattern(st.get("plainLength").getAsInt(), st.get("seed").getAsInt());
            assertEquals(s(st, "plainSha256"), sha256Hex(plain));
            byte[] blob = st.has("cipher") ? h(st, "cipher") : TestSupport.streamEncrypt(key, plain, "VXZ1");
            assertEquals(st.get("cipherLength").getAsInt(), blob.length);
            assertEquals(s(st, "cipherSha256"), sha256Hex(blob));
            assertArrayEquals(plain, Zk1.streamDecrypt(key, blob, Zk1.STORED_MAGIC));
            // incremental, in odd pieces
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Zk1.StreamDecryptor decryptor = new Zk1.StreamDecryptor(key, Zk1.STORED_MAGIC, (d, o, n) -> {
                out.write(d, o, n);
                return true;
            });
            for (int at = 0; at < blob.length; at += 77777) {
                assertTrue(decryptor.update(blob, at, Math.min(77777, blob.length - at)));
            }
            assertTrue(decryptor.finish(), decryptor.error());
            assertArrayEquals(plain, out.toByteArray());
        }
    }

    @Test
    void truncatedFlippedAndWrongStreamsFail() throws Exception {
        for (JsonElement e : list("stream")) {
            JsonObject st = e.getAsJsonObject();
            byte[] key = h(st, "key");
            byte[] plain = pattern(st.get("plainLength").getAsInt(), st.get("seed").getAsInt());
            byte[] blob = st.has("cipher") ? h(st, "cipher") : TestSupport.streamEncrypt(key, plain, "VXZ1");

            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(key, Arrays.copyOf(blob, blob.length - 1), "VXZ1"));
            byte[] flipped = blob.clone();
            flipped[9 + (blob.length - 9) / 2] ^= 0x20;
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(key, flipped, "VXZ1"));
            byte[] longer = Arrays.copyOf(blob, blob.length + 1);
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(key, longer, "VXZ1"));
            assertEquals("unsupported stream header",
                    assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(key, blob, "VXD1")).getMessage());
            byte[] otherKey = key.clone();
            otherKey[0] ^= 1;
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(otherKey, blob, "VXZ1"));
            byte[] header = Arrays.copyOf(blob, 9);
            assertEquals("stream too short",
                    assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(key, header, "VXZ1")).getMessage());
            byte[] chunkSize = blob.clone();
            chunkSize[8] ^= 1;
            assertEquals("unsupported chunk size",
                    assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(key, chunkSize, "VXZ1")).getMessage());

            int full = Zk1.CHUNK_SIZE + Zk1.TAG_BYTES;
            if (blob.length > 9 + full) {
                // Cut after whole chunks: the last remaining chunk was not sealed as final.
                byte[] cut = Arrays.copyOf(blob, 9 + full);
                assertEquals("chunk 0 failed authentication",
                        assertThrows(Zk1.Zk1Exception.class, () -> Zk1.streamDecrypt(key, cut, "VXZ1")).getMessage());
            }
            // A single-chunk stream that fails releases no plaintext at all.
            if (blob.length <= 9 + full) {
                int[] released = {0};
                Zk1.StreamDecryptor decryptor = new Zk1.StreamDecryptor(key, "VXZ1", (d, o, n) -> {
                    released[0] += n;
                    return true;
                });
                decryptor.update(flipped, 0, flipped.length);
                assertFalse(decryptor.finish());
                assertEquals(0, released[0]);
            }
        }
    }

    // ------------------------------------------------------------------
    // Delivery
    // ------------------------------------------------------------------

    private static byte[] deliveryPayload(JsonObject d) {
        if (d.has("payload")) return h(d, "payload");
        JsonObject p = d.getAsJsonObject("payloadPattern");
        return pattern(p.get("length").getAsInt(), p.get("seed").getAsInt());
    }

    private static byte[] deliveryBody(JsonObject d) throws Exception {
        if (d.has("body")) return h(d, "body");
        byte[] clientPublic = Zk1.x25519Public(h(d, "clientSecret"));
        Object[] built = TestSupport.delivery(clientPublic, h(d, "serverSecret"), s(d, "kind"), s(d, "objectId"), deliveryPayload(d));
        assertEquals(s(d, "header"), built[0]);
        return (byte[]) built[1];
    }

    @Test
    void deliveryVectorsOpen() throws Exception {
        JsonArray deliveries = list("delivery");
        for (int i = 0; i < deliveries.size(); i++) {
            JsonObject d = deliveries.get(i).getAsJsonObject();
            byte[] clientSecret = h(d, "clientSecret");
            assertEquals(s(d, "clientPublicB64u"), Zk1.b64uEncode(Zk1.x25519Public(clientSecret)));
            byte[] payload = deliveryPayload(d);
            assertEquals(s(d, "payloadSha256"), sha256Hex(payload));
            byte[] body = deliveryBody(d);
            assertEquals(d.get("bodyLength").getAsInt(), body.length);
            assertEquals(s(d, "bodySha256"), sha256Hex(body));

            Zk1.OpenedDelivery opened = Zk1.openDelivery(clientSecret, s(d, "header"), body, s(d, "kind"));
            assertEquals(s(d, "kind"), opened.kind);
            assertEquals(s(d, "objectId"), opened.objectId);
            assertArrayEquals(payload, opened.payload);

            // the wrong client secret (another delivery's) cannot open it
            byte[] wrongSecret = h(deliveries.get((i + 1) % deliveries.size()).getAsJsonObject(), "clientSecret");
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openDelivery(wrongSecret, s(d, "header"), body, null));
            String otherKind = "file".equals(s(d, "kind")) ? "folder" : "file";
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openDelivery(clientSecret, s(d, "header"), body, otherKind));
            byte[] flipped = body.clone();
            flipped[body.length - 3] ^= 1;
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openDelivery(clientSecret, s(d, "header"), flipped, null));
            // a header for another object derives another key
            String moved = s(d, "header").substring(0, s(d, "header").lastIndexOf('.') + 1) + "other";
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openDelivery(clientSecret, moved, body, null));
        }
    }

    @Test
    void deliveryHeaderParsing() {
        String header = s(item("delivery", 0), "header");
        Zk1.DeliveryHeader parsed = Zk1.parseDeliveryHeader(header);
        assertNotNull(parsed);
        assertEquals("file", parsed.kind);
        assertEquals("6f1c2a8e-file", parsed.objectId);
        assertNull(Zk1.parseDeliveryHeader("enc_key_123"));
        assertNull(Zk1.parseDeliveryHeader(header + ".extra"));
        assertNull(Zk1.parseDeliveryHeader(header.replace(".file.", ".grant.")));
        assertNull(Zk1.parseDeliveryHeader(header.substring(0, header.lastIndexOf('.') + 1)));
        assertNull(Zk1.parseDeliveryHeader("zk1d.AAAA.file.x"));
    }

    // ------------------------------------------------------------------
    // Files through the delivery opener (what the SDK does with a download)
    // ------------------------------------------------------------------

    private static final class Opened {
        boolean ok;
        String error;
        byte[] content;
        long signedAt;
        String scope;
    }

    private static Opened open(byte[] clientSecret, String header, byte[] body, String kind, Zk1.ContentKey key,
                               String app, String name, String productId) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Zk1.DeliveryOpener opener = new Zk1.DeliveryOpener(clientSecret, kind);
        if (key != null) opener.setFileContext(key, app, name, productId, (d, o, n) -> {
            out.write(d, o, n);
            return true;
        });
        Opened result = new Opened();
        boolean ok = opener.begin(header);
        for (int at = 0; ok && at < body.length; at += 5000) ok = opener.update(body, at, Math.min(5000, body.length - at));
        result.ok = ok && opener.finish();
        result.error = opener.error();
        result.content = out.toByteArray();
        result.signedAt = opener.signedAt();
        result.scope = opener.scope();
        opener.close();
        return result;
    }

    /** A file vector's stored stream (from the vector, or rebuilt and checked against its SHA-256). */
    private static byte[] fileCipher(JsonObject f) throws Exception {
        if (f.has("cipher")) return h(f, "cipher");
        byte[] blob = TestSupport.streamEncrypt(h(f, "fileKey"), pattern(f.get("plainLength").getAsInt(), f.get("seed").getAsInt()), "VXZ1");
        assertEquals(s(f, "cipherSha256"), sha256Hex(blob));
        return blob;
    }

    @Test
    void fileDeliveryVectorOpensThroughTheOpener() {
        JsonObject d = item("delivery", 0);
        JsonObject f = item("files", 0);
        byte[] body = h(d, "body");
        Opened r = open(h(d, "clientSecret"), s(d, "header"), body, "file", appKey(0), appId, s(f, "name"), s(f, "productId"));
        assertTrue(r.ok, r.error);
        assertArrayEquals(pattern(1000, 100), r.content);
        assertEquals(s(f, "plainSha256"), sha256Hex(r.content));
        assertEquals(f.get("signedAt").getAsLong(), r.signedAt);
        assertEquals("prod-1234", r.scope);
    }

    @Test
    void fileDeliveryFailures() {
        JsonObject d = item("delivery", 0);
        JsonObject f = item("files", 0);
        byte[] body = h(d, "body");
        byte[] clientSecret = h(d, "clientSecret");
        String header = s(d, "header");
        String name = s(f, "name");

        Opened wrongKey = open(clientSecret, header, body, "file", appKey(1), appId, name, "prod-1234");
        assertFalse(wrongKey.ok);
        assertTrue(wrongKey.error.startsWith("cannot open the sealed file key"), wrongKey.error);
        assertEquals(0, wrongKey.content.length);

        Opened wrongApp = open(clientSecret, header, body, "file", appKey(0), "app-2", name, "prod-1234");
        assertFalse(wrongApp.ok);
        assertEquals("signature check failed: the signer is not approved by the app owner", wrongApp.error);
        assertEquals(0, wrongApp.content.length);

        Opened wrongName = open(clientSecret, header, body, "file", appKey(0), appId, "other.exe", "prod-1234");
        assertFalse(wrongName.ok);
        assertEquals(0, wrongName.content.length);

        // sealed for product prod-1234: no fallback from the general scope to a product
        Opened general = open(clientSecret, header, body, "file", appKey(0), appId, name, "");
        assertFalse(general.ok);

        Opened wrongClient = open(h(item("delivery", 1), "clientSecret"), header, body, "file", appKey(0), appId, name, "prod-1234");
        assertFalse(wrongClient.ok);
        assertEquals(0, wrongClient.content.length);

        Opened wrongKind = open(clientSecret, header, body, "folder", appKey(0), appId, name, "prod-1234");
        assertFalse(wrongKind.ok);
        assertTrue(wrongKind.error.startsWith("unexpected delivery kind"), wrongKind.error);

        Opened noKey = open(clientSecret, header, body, "file", null, appId, name, "prod-1234");
        assertFalse(noKey.ok);
        assertEquals("no content key", noKey.error);

        byte[] truncated = Arrays.copyOf(body, body.length - 1);
        Opened cut = open(clientSecret, header, truncated, "file", appKey(0), appId, name, "prod-1234");
        assertFalse(cut.ok);
    }

    @Test
    void tamperedSignatureInsideADeliveryFails() throws Exception {
        JsonObject f = item("files", 0);
        byte[] signature = h(f, "signature");
        signature[signature.length - 1] ^= 1;
        byte[] payload = Zk1.concat(TestSupport.fileDeliveryPrefix(h(f, "sealed"), signature), fileCipher(f));
        byte[] clientSecret = Zk1.sha256("client".getBytes(StandardCharsets.US_ASCII));
        Object[] built = TestSupport.delivery(Zk1.x25519Public(clientSecret),
                Zk1.sha256("server".getBytes(StandardCharsets.US_ASCII)), "file", "f-1", payload);
        Opened r = open(clientSecret, (String) built[0], (byte[]) built[1], "file", appKey(0), appId, s(f, "name"), "prod-1234");
        assertFalse(r.ok);
        assertEquals("signature check failed: invalid signature", r.error);
        assertEquals(0, r.content.length);
        assertEquals(0, r.signedAt);
    }

    @Test
    void generalScopeFallbackAndOtherFileVectors() throws Exception {
        for (int i = 1; i < list("files").size(); i++) {
            JsonObject f = item("files", i);
            assertEquals("", s(f, "productId"));
            byte[] payload = Zk1.concat(TestSupport.fileDeliveryPrefix(h(f, "sealed"), h(f, "signature")), fileCipher(f));
            byte[] clientSecret = Zk1.sha256(("client-" + i).getBytes(StandardCharsets.US_ASCII));
            Object[] built = TestSupport.delivery(Zk1.x25519Public(clientSecret),
                    Zk1.sha256(("server-" + i).getBytes(StandardCharsets.US_ASCII)), s(f, "kind"), "obj-" + i, payload);
            for (String requested : new String[] {"", "prod-requested"}) {
                Opened r = open(clientSecret, (String) built[0], (byte[]) built[1], s(f, "kind"), appKey(0), appId,
                        s(f, "name"), requested);
                assertTrue(r.ok, r.error);
                assertEquals("", r.scope);
                assertEquals(s(f, "plainSha256"), sha256Hex(r.content));
                assertEquals(f.get("plainLength").getAsInt(), r.content.length);
                assertEquals(f.get("signedAt").getAsLong(), r.signedAt);
            }
        }
    }

    /** An approved uploader who seals a wrong size or hash: the final checks refuse the file. */
    @Test
    void sealedSizeAndHashAreEnforced() throws Exception {
        JsonObject a = item("appKeys", 0);
        JsonObject signer = item("personal", 1);
        JsonObject cert = item("certs", 1);
        assertEquals(s(signer, "userId"), s(cert, "userId"));
        Zk1.ContentKey key = appKey(0);
        byte[] data = pattern(3000, 9);
        byte[] fileKey = Zk1.sha256("file-key".getBytes(StandardCharsets.US_ASCII));
        byte[] blob = TestSupport.streamEncrypt(fileKey, data, "VXZ1");

        String[] expected = {
            "the file does not match its sealed SHA-256",
            "the file is larger than its sealed size",
            "the file does not match its sealed size",
            null,
        };
        for (int variant = 0; variant < expected.length; variant++) {
            byte[] digest = variant == 0 ? Zk1.sha256(pattern(3000, 10)) : Zk1.sha256(data);
            long size = variant == 1 ? 2999 : variant == 2 ? 3001 : 3000;
            byte[] keyed = Zk1.keyedHash(key.hashKey, digest);
            long signedAt = 1_760_000_500_000L + variant;
            byte[] message = Zk1.uploadMessage(appId, "file", "p-1", "tool.bin", keyed, size, signedAt);
            byte[] block = TestSupport.signatureBlock(s(cert, "userId"), h(cert, "encPublic"), h(cert, "signPublic"),
                    cert.get("issuedAt").getAsLong(), h(cert, "signature"), signedAt,
                    TestSupport.ed25519Sign(h(signer, "signSeed"), message));
            byte[] payloadKey = Zk1.concat(fileKey, digest, java.nio.ByteBuffer.allocate(8).putLong(size).array());
            byte[] sealed = TestSupport.seal(h(a, "sdkPublic"), payloadKey, Zk1.sealContext("file", "tool.bin", "p-1"),
                    Zk1.sha256(("eph-" + variant).getBytes(StandardCharsets.US_ASCII)));
            byte[] clientSecret = Zk1.sha256(("c-" + variant).getBytes(StandardCharsets.US_ASCII));
            Object[] built = TestSupport.delivery(Zk1.x25519Public(clientSecret),
                    Zk1.sha256(("s-" + variant).getBytes(StandardCharsets.US_ASCII)), "file", "id-" + variant,
                    Zk1.concat(TestSupport.fileDeliveryPrefix(sealed, block), blob));
            Opened r = open(clientSecret, (String) built[0], (byte[]) built[1], "file", key, appId, "tool.bin", "p-1");
            if (expected[variant] == null) {
                assertTrue(r.ok, r.error);
                assertArrayEquals(data, r.content);
                assertEquals(signedAt, r.signedAt);
            } else {
                assertFalse(r.ok);
                assertEquals(expected[variant], r.error);
            }
        }
    }

    // ------------------------------------------------------------------
    // Variables
    // ------------------------------------------------------------------

    @Test
    void variablesDeliveryVectorOpens() throws Exception {
        JsonObject d = item("delivery", 1);
        assertEquals("vars", s(d, "kind"));
        Zk1.OpenedDelivery opened = Zk1.openDelivery(h(d, "clientSecret"), s(d, "header"), h(d, "body"), "vars");
        List<Map.Entry<String, String>> values = Zk1.openVariables(opened.payload, appKey(0), appId, "prod-1234");
        assertEquals(2, values.size());
        assertEquals("apiUrl", values.get(0).getKey());
        assertEquals("https://example.com/v1?x=\u00e4", values.get(0).getValue());
        assertEquals("legacy", values.get(1).getKey());
        assertEquals("plain", values.get(1).getValue());

        // the same through the incremental opener
        Zk1.DeliveryOpener opener = new Zk1.DeliveryOpener(h(d, "clientSecret"), "vars");
        byte[] body = h(d, "body");
        assertTrue(opener.begin(s(d, "header")));
        assertTrue(opener.update(body, 0, body.length));
        assertTrue(opener.finish(), opener.error());
        assertEquals("prod-1234", opener.objectId());
        assertArrayEquals(opened.payload, opener.varsPayload());

        // a zk1 value needs the content key
        assertEquals(Zk1.NEED_CONTENT_KEY, assertThrows(Zk1.Zk1Exception.class,
                () -> Zk1.openVariables(opened.payload, null, appId, "prod-1234")).getMessage());
        // sealed for prod-1234 only
        assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables(opened.payload, appKey(0), appId, "prod-9"));
        // another app's key
        assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables(opened.payload, appKey(1), appId, "prod-1234"));
    }

    private static byte[] varsJson(String... items) {
        return ("[" + String.join(",", items) + "]").getBytes(StandardCharsets.UTF_8);
    }

    private static String zk1Item(JsonObject var, String sig) {
        return "{\"id\":\"v\",\"name\":\"" + s(var, "name") + "\",\"enc\":\"zk1\",\"value\":\"" + s(var, "sealedB64u")
                + "\",\"sig\":" + (sig == null ? "null" : "\"" + sig + "\"") + "}";
    }

    @Test
    void variableVectorsOpenAndTamperedOnesFail() throws Exception {
        Zk1.ContentKey key = appKey(0);
        for (JsonElement e : list("variables")) {
            JsonObject var = e.getAsJsonObject();
            String product = s(var, "productId");
            List<Map.Entry<String, String>> values = Zk1.openVariables(varsJson(zk1Item(var, s(var, "signatureB64u"))),
                    key, appId, product);
            assertEquals(1, values.size());
            assertEquals(s(var, "name"), values.get(0).getKey());
            assertEquals(s(var, "value"), values.get(0).getValue());

            byte[] sig = h(var, "signature");
            sig[sig.length - 1] ^= 1;
            Zk1.Zk1Exception bad = assertThrows(Zk1.Zk1Exception.class,
                    () -> Zk1.openVariables(varsJson(zk1Item(var, Zk1.b64uEncode(sig))), key, appId, product));
            assertEquals("variable '" + s(var, "name") + "': signature check failed: invalid signature", bad.getMessage());
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables(varsJson(zk1Item(var, null)), key, appId, product));
            assertThrows(Zk1.Zk1Exception.class,
                    () -> Zk1.openVariables(varsJson(zk1Item(var, s(var, "signatureB64u"))), key, "app-2", product));
            // a failing value means no values at all
            assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables(
                    varsJson("{\"name\":\"ok\",\"enc\":null,\"value\":\"plain\"}", zk1Item(var, null)), key, appId, product));
        }
    }

    @Test
    void variablesPayloadIsParsedStrictly() throws Exception {
        assertEquals(0, Zk1.openVariables(varsJson(), null, appId, "p").size());
        List<Map.Entry<String, String>> plain = Zk1.openVariables(
                varsJson("{\"id\":1,\"name\":\"a\",\"value\":\"x\\u00e4\\n\",\"extra\":{\"n\":[1,2.5e3,true]}}",
                         "{\"name\":\"b\",\"value\":null}"), null, appId, "p");
        assertEquals("x\u00e4\n", plain.get(0).getValue());
        assertEquals("", plain.get(1).getValue());
        assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables(varsJson("{\"name\":\"a\",\"name\":\"b\"}"), null, appId, "p"));
        assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables("[] x".getBytes(StandardCharsets.UTF_8), null, appId, "p"));
        assertEquals("a variable has no name", assertThrows(Zk1.Zk1Exception.class,
                () -> Zk1.openVariables(varsJson("{\"value\":\"x\"}"), null, appId, "p")).getMessage());
        assertEquals("variable 'a' uses an unknown encoding", assertThrows(Zk1.Zk1Exception.class,
                () -> Zk1.openVariables(varsJson("{\"name\":\"a\",\"enc\":\"zk2\",\"value\":\"x\"}"), null, appId, "p")).getMessage());
        assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables(new byte[] {'[', (byte) 0xC3, ']'}, null, appId, "p"));
        assertThrows(Zk1.Zk1Exception.class, () -> Zk1.openVariables(varsJson("{\"name\":\"\\ud800\"}"), null, appId, "p"));
    }
}
