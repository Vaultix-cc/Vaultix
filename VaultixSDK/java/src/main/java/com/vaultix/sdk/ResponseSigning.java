package com.vaultix.sdk;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Response signature verification (vaultix-resp-v1), as in the C++ SDK and
 * {@code backend/response_signing.py}.
 *
 * <p>Every request carries a fresh random {@code X-Vaultix-Nonce}. Vaultix
 * answers with {@code X-Vaultix-Signature} (base64url Ed25519),
 * {@code X-Vaultix-Key-Id} and {@code X-Vaultix-Signed-At} (Unix seconds).
 * The signature covers these 11 lines joined by '\n' (no field can contain a
 * line break):
 *
 * <pre>
 *   vaultix-resp-v1
 *   key id
 *   nonce (as sent)
 *   signed_at (as received)
 *   HTTP method (as sent)
 *   path?query (as sent; no '?' when there is no query)
 *   status code
 *   SHA-256 hex of the complete response body ("zk1-stream" for zk1 deliveries)
 *   X-Encryption-Key value or ""
 *   X-Encryption-IV value or ""
 *   Content-Type value or ""
 * </pre>
 */
final class ResponseSigning {

    private ResponseSigning() {}

    static final String STREAM_BODY_MARKER = "zk1-stream";

    /**
     * Keys Vaultix signs responses with: {key id, raw Ed25519 public key (hex)}.
     * A key rotation ships an SDK that lists the old and the new key side by
     * side for a while. Same table as kTrustedResponseKeys in the C++ SDK.
     */
    static final String[][] TRUSTED_RESPONSE_KEYS = {
        {"vx-sig-22545e6918734982", "c21b9ba40714e61eaaf8529941400264996decd9fb8480121d3e4c7533cf2d8c"},
    };

    /** "vx-sig-" + first 16 hex characters of SHA-256(raw public key). */
    static String keyIdFor(byte[] publicKey) {
        return "vx-sig-" + Zk1.hex(Zk1.sha256(publicKey)).substring(0, 16);
    }

    /** Raw public key of a built-in trusted key id, or null. */
    static byte[] trustedPublicKey(String keyId) {
        for (String[] key : TRUSTED_RESPONSE_KEYS) {
            if (key[0].equals(keyId)) return Zk1.fromHex32(key[1]);
        }
        return null;
    }

    private static boolean hasLineBreak(String value) {
        return value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0;
    }

    /**
     * The canonical bytes, or null if a field contains a line break. Header
     * values are taken as the bytes that were received (ISO-8859-1, which is
     * how the JDK HTTP client exposes header bytes).
     */
    static byte[] canonical(String keyId, String nonce, String signedAt, String method, String pathAndQuery,
                            String status, String bodySha256Hex, String encryptionKey, String encryptionIv,
                            String contentType) {
        String[] fields = {keyId, nonce, signedAt, method, pathAndQuery, status, bodySha256Hex,
                           encryptionKey, encryptionIv, contentType};
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] version = "vaultix-resp-v1".getBytes(StandardCharsets.US_ASCII);
        out.write(version, 0, version.length);
        for (String field : fields) {
            String value = field == null ? "" : field;
            if (hasLineBreak(value)) return null;
            out.write('\n');
            byte[] bytes = value.getBytes(StandardCharsets.ISO_8859_1);
            out.write(bytes, 0, bytes.length);
        }
        return out.toByteArray();
    }

    /** At most 48 characters of a server-supplied value, safe to show. */
    static String printable(String value) {
        StringBuilder out = new StringBuilder();
        String head = value.length() > 48 ? value.substring(0, 48) : value;
        for (char c : head.toCharArray()) {
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            out.append(ok ? c : '?');
        }
        return out.toString();
    }
}
