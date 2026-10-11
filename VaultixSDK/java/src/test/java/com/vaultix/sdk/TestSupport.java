package com.vaultix.sdk;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;

/**
 * Test helpers: vector loading and the writer side of the format (stream
 * encryption, sealing, signing), so tests can build inputs the SDK must open
 * or refuse. The writer side mirrors backend/content_crypto.py and
 * backend/tests/zk1_reference.py.
 */
final class TestSupport {

    private TestSupport() {}

    /**
     * zk1.json: -Dvaultix.vectors=PATH or VAULTIX_VECTORS (the backend's
     * crypto_vectors/zk1.json), else the copy in src/test/resources.
     */
    static JsonObject zk1Vectors() throws IOException {
        return loadJson("vaultix.vectors", "VAULTIX_VECTORS", "/vectors/zk1.json");
    }

    static JsonObject responseGolden() throws IOException {
        return loadJson("vaultix.responseGolden", "VAULTIX_RESPONSE_GOLDEN", "/vectors/response_signing_golden.json");
    }

    static String vectorsSource() {
        String path = configured("vaultix.vectors", "VAULTIX_VECTORS");
        return path != null ? path : "classpath:/vectors/zk1.json";
    }

    private static String configured(String property, String env) {
        String value = System.getProperty(property);
        if (value == null || value.isEmpty()) value = System.getenv(env);
        return value == null || value.isEmpty() ? null : value;
    }

    private static JsonObject loadJson(String property, String env, String resource) throws IOException {
        String path = configured(property, env);
        String text;
        if (path != null) {
            text = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        } else {
            try (InputStream in = TestSupport.class.getResourceAsStream(resource)) {
                if (in == null) throw new IOException("missing test resource " + resource);
                text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        return JsonParser.parseString(text).getAsJsonObject();
    }

    static Path fixturePath() {
        String path = configured("vaultix.fixture", "VAULTIX_SDK_FIXTURE");
        return path == null ? null : Paths.get(path);
    }

    static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String hex(byte[] data) {
        return Zk1.hex(data);
    }

    static String sha256Hex(byte[] data) {
        return Zk1.hex(Zk1.sha256(data));
    }

    static JsonArray array(JsonObject json, String key) {
        return json.getAsJsonArray(key);
    }

    /** Deterministic test plaintext: byte i = (i * 31 + 7 + seed) mod 256. */
    static byte[] pattern(int length, int seed) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) out[i] = (byte) ((i * 31 + 7 + seed) & 0xFF);
        return out;
    }

    static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plain) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        if (aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(plain);
    }

    /** content_crypto.stream_encrypt */
    static byte[] streamEncrypt(byte[] key, byte[] data, String magic) throws Exception {
        byte[] header = ByteBuffer.allocate(9).put(magic.getBytes(StandardCharsets.US_ASCII)).put((byte) 1)
                .putInt(Zk1.CHUNK_SIZE).array();
        int chunks = Math.max(1, (data.length + Zk1.CHUNK_SIZE - 1) / Zk1.CHUNK_SIZE);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(header);
        for (int i = 0; i < chunks; i++) {
            int start = i * Zk1.CHUNK_SIZE;
            int end = Math.min(data.length, start + Zk1.CHUNK_SIZE);
            byte[] nonce = ByteBuffer.allocate(12).put(new byte[7]).putInt(i).put((byte) (i == chunks - 1 ? 1 : 0)).array();
            byte[] chunk = new byte[end - start];
            System.arraycopy(data, start, chunk, 0, chunk.length);
            out.write(aesGcmEncrypt(key, nonce, header, chunk));
        }
        return out.toByteArray();
    }

    /** zk1_reference.seal with a given ephemeral secret. */
    static byte[] seal(byte[] appPublic, byte[] payload, byte[] context, byte[] ephSecret) throws Exception {
        byte[] ephPublic = Zk1.x25519Public(ephSecret);
        byte[] shared = Zk1.x25519Shared(ephSecret, appPublic);
        byte[] key = Zk1.hkdfSha256(shared, Zk1.concat(ephPublic, appPublic),
                Zk1.concat("vaultix-zk1-seal".getBytes(StandardCharsets.US_ASCII), new byte[] {0}, context), 32);
        return Zk1.concat(new byte[] {1}, ephPublic, aesGcmEncrypt(key, new byte[12], context, payload));
    }

    static byte[] ed25519Sign(byte[] seed, byte[] message) throws Exception {
        PrivateKey key = KeyFactory.getInstance("Ed25519")
                .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }

    /** content_crypto.build_signature_block */
    static byte[] signatureBlock(String userId, byte[] encPublic, byte[] signPublic, long issuedAtMs, byte[] cert,
                                 long signedAtMs, byte[] signature) {
        byte[] user = userId.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(3 + user.length + 32 + 32 + 8 + 64 + 8 + 64).put((byte) 1)
                .putShort((short) user.length).put(user).put(encPublic).put(signPublic).putLong(issuedAtMs)
                .put(cert).putLong(signedAtMs).put(signature).array();
    }

    /** content_crypto.file_delivery_prefix */
    static byte[] fileDeliveryPrefix(byte[] sealed, byte[] signatureBlock) {
        return ByteBuffer.allocate(2 + sealed.length + 2 + signatureBlock.length).putShort((short) sealed.length)
                .put(sealed).putShort((short) signatureBlock.length).put(signatureBlock).array();
    }

    /** A layer-3 delivery as the server builds it: {header value, body}. */
    static Object[] delivery(byte[] clientPublic, byte[] serverSecret, String kind, String objectId, byte[] payload)
            throws Exception {
        byte[] serverPublic = Zk1.x25519Public(serverSecret);
        byte[] shared = Zk1.x25519Shared(serverSecret, clientPublic);
        byte[] info = Zk1.concat("vaultix-zk1-deliver".getBytes(StandardCharsets.US_ASCII), new byte[] {0},
                kind.getBytes(StandardCharsets.US_ASCII), new byte[] {0}, objectId.getBytes(StandardCharsets.UTF_8));
        byte[] key = Zk1.hkdfSha256(shared, Zk1.concat(clientPublic, serverPublic), info, 32);
        String header = "zk1d." + Zk1.b64uEncode(serverPublic) + "." + kind + "." + objectId;
        return new Object[] {header, streamEncrypt(key, payload, Zk1.DELIVERY_MAGIC)};
    }
}
