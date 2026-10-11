package com.vaultix.sdk;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.LongFunction;

/**
 * End-to-end encryption ("zk1") as the SDK uses it: the content key, sealed
 * keys, signed content, the chunked stream and the one-time delivery.
 *
 * <p>The format is specified in Vaultix's {@code docs/E2EE_FORMAT.md}; the
 * reference implementation is {@code backend/tests/zk1_reference.py}, and the
 * unit tests check this class against {@code crypto_vectors/zk1.json} byte for
 * byte. {@link VaultixClient} uses it internally; integrations normally only
 * call {@link VaultixClient#setContentKey(String)}.
 *
 * <p>Only JDK 17 built-ins are used: X25519 ("XDH"), Ed25519, AES-256-GCM,
 * HMAC-SHA256 and SHA-256; HKDF-SHA256 (RFC 5869) is implemented here.
 * Byte arrays this class owns are wiped when they are no longer needed. JDK
 * key objects and {@code String}s cannot be wiped reliably.
 */
public final class Zk1 {

    private Zk1() {}

    /** Plaintext bytes per stream chunk. */
    public static final int CHUNK_SIZE = 1048576;
    /** AES-GCM tag after every chunk. */
    public static final int TAG_BYTES = 16;
    /** magic(4) || version(1) || u32be chunk size. */
    public static final int HEADER_BYTES = 9;
    /** 0x01 || eph pk || GCM(fk || sha256 || u64be size). */
    public static final int SEALED_FILE_KEY_BYTES = 121;
    /** Largest sealed variable value. */
    public static final int MAX_SEALED_BYTES = 65536;
    /** "vxk_" + b64u(0x02 || sk_sdk || aspk || checksum(4)). */
    public static final int SDK_KEY_CHARS = 96;
    public static final int MAX_USER_ID_BYTES = 128;
    /** Signature block with a 1-byte user id. */
    public static final int MIN_SIGNATURE_BLOCK_BYTES = 3 + 1 + 208;
    /** Signature block with the longest user id (339 bytes). */
    public static final int MAX_SIGNATURE_BLOCK_BYTES = 3 + MAX_USER_ID_BYTES + 208;
    /** Magic of a stored stream. */
    public static final String STORED_MAGIC = "VXZ1";
    /** Magic of a layer-3 delivery stream. */
    public static final String DELIVERY_MAGIC = "VXD1";

    static final int FILE_KEY_PAYLOAD_BYTES = 72;               // fk || sha256 || u64be size
    static final int MAX_VARS_PAYLOAD_BYTES = 64 * 1024 * 1024; // decrypted variables JSON
    static final String NEED_CONTENT_KEY =
            "This app uses end-to-end encryption: call setContentKey with the vxk_ key from App Settings";

    private static final byte SEAL_VERSION = 1;
    private static final byte STREAM_VERSION = 1;
    private static final byte SDK_KEY_VERSION = 2;
    private static final int FULL_CHUNK = CHUNK_SIZE + TAG_BYTES;
    private static final String B64U_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final byte[] X25519_BASE_POINT = new byte[32];
    static {
        X25519_BASE_POINT[0] = 9;
    }

    /** A zk1 format or verification failure. The message says what failed. */
    public static final class Zk1Exception extends Exception {
        private static final long serialVersionUID = 1L;

        public Zk1Exception(String message) {
            super(message);
        }
    }

    /** Receives authenticated plaintext; return false to abort. */
    @FunctionalInterface
    public interface Sink {
        boolean accept(byte[] data, int offset, int length);
    }

    // ---------------------------------------------------------------------
    // Small helpers
    // ---------------------------------------------------------------------

    /** Overwrites an array with zeros (null is ignored). */
    public static void wipe(byte[] data) {
        if (data != null) Arrays.fill(data, (byte) 0);
    }

    static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] utf8(String text) {
        return (text == null ? "" : text).getBytes(StandardCharsets.UTF_8);
    }

    private static boolean hasNul(String text) {
        return text != null && text.indexOf('\0') >= 0;
    }

    static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) length += part.length;
        byte[] out = new byte[length];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
    }

    private static byte[] u64be(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    private static int readU16be(byte[] data, int at) {
        return ((data[at] & 0xFF) << 8) | (data[at + 1] & 0xFF);
    }

    private static long readU32be(byte[] data, int at) {
        return ((long) (data[at] & 0xFF) << 24) | ((data[at + 1] & 0xFF) << 16)
                | ((data[at + 2] & 0xFF) << 8) | (data[at + 3] & 0xFF);
    }

    private static long readU64be(byte[] data, int at) {
        return (readU32be(data, at) << 32) | readU32be(data, at + 4);
    }

    private static byte[] reversed(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = data[data.length - 1 - i];
        return out;
    }

    /** Strict UTF-8 (like Python's bytes.decode("utf-8")), or null. */
    static String decodeUtf8Strict(byte[] data, int offset, int length) {
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data, offset, length));
            return chars.toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    static String hex(byte[] data) {
        StringBuilder out = new StringBuilder(data.length * 2);
        for (byte b : data) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    /** 64 hex characters as 32 bytes, or null. */
    static byte[] fromHex32(String text) {
        if (text == null || text.length() != 64) return null;
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            int high = Character.digit(text.charAt(2 * i), 16);
            int low = Character.digit(text.charAt(2 * i + 1), 16);
            if (high < 0 || low < 0) return null;
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    // ---------------------------------------------------------------------
    // Primitives (JDK built-ins)
    // ---------------------------------------------------------------------

    /** SHA-256 of the concatenation of the parts. */
    public static byte[] sha256(byte[]... parts) {
        MessageDigest digest = newSha256();
        for (byte[] part : parts) digest.update(part);
        return digest.digest();
    }

    static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static Mac hmac(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // An empty HMAC key equals 32 zero bytes (both are zero-padded to the
            // block size); SecretKeySpec refuses empty keys.
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }

    /** HMAC-SHA256 of the concatenation of the parts. */
    public static byte[] hmacSha256(byte[] key, byte[]... parts) {
        Mac mac = hmac(key);
        for (byte[] part : parts) mac.update(part);
        return mac.doFinal();
    }

    /** HKDF-SHA256 (RFC 5869). An empty salt means 32 zero bytes, as in the RFC. */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length <= 0 || length > 255 * 32) throw new IllegalArgumentException("invalid HKDF length");
        byte[] prk = hmacSha256(salt == null ? new byte[0] : salt, ikm);
        Mac mac = hmac(prk);
        byte[] out = new byte[length];
        byte[] block = new byte[0];
        int done = 0;
        for (int counter = 1; done < length; counter++) {
            mac.update(block);
            mac.update(info == null ? new byte[0] : info);
            mac.update((byte) counter);
            wipe(block);
            block = mac.doFinal();
            int take = Math.min(32, length - done);
            System.arraycopy(block, 0, out, done, take);
            done += take;
        }
        wipe(prk);
        wipe(block);
        return out;
    }

    /** PBKDF2-HMAC-SHA256 over raw password bytes (legacy downloads). */
    static byte[] pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int length) {
        Mac mac = hmac(password);
        byte[] out = new byte[length];
        int done = 0;
        for (int blockIndex = 1; done < length; blockIndex++) {
            mac.update(salt);
            mac.update(ByteBuffer.allocate(4).putInt(blockIndex).array());
            byte[] u = mac.doFinal();
            byte[] t = u.clone();
            for (int i = 1; i < iterations; i++) {
                u = mac.doFinal(u);
                for (int k = 0; k < t.length; k++) t[k] ^= u[k];
            }
            int take = Math.min(t.length, length - done);
            System.arraycopy(t, 0, out, done, take);
            done += take;
            wipe(u);
            wipe(t);
        }
        return out;
    }

    /**
     * X25519 (RFC 7748) of a 32-byte secret and a 32-byte u-coordinate, or
     * null when the JDK refuses it or the result is all zero (low-order peer).
     */
    static byte[] x25519(byte[] secret, byte[] u) {
        if (secret == null || secret.length != 32 || u == null || u.length != 32) return null;
        try {
            KeyFactory factory = KeyFactory.getInstance("XDH");
            PrivateKey privateKey = factory.generatePrivate(
                    new XECPrivateKeySpec(NamedParameterSpec.X25519, secret.clone()));
            byte[] masked = u.clone();
            masked[31] &= 0x7F;  // RFC 7748: ignore the top bit
            BigInteger coordinate = new BigInteger(1, reversed(masked)).mod(P25519);
            PublicKey publicKey = factory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, coordinate));
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            byte[] shared = agreement.generateSecret();
            if (shared.length != 32) return null;
            int any = 0;
            for (byte b : shared) any |= b;
            if (any == 0) return null;
            return shared;
        } catch (GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    /** X25519 public key of a 32-byte secret, or null. */
    public static byte[] x25519Public(byte[] secret) {
        return x25519(secret, X25519_BASE_POINT);
    }

    /** X25519 shared secret; null for a low-order peer key (all-zero result) or invalid input. */
    public static byte[] x25519Shared(byte[] secret, byte[] peerPublic) {
        return x25519(secret, peerPublic);
    }

    /** A fresh key pair {secret, public} from the given CSPRNG, or null. */
    public static byte[][] x25519Generate(SecureRandom random) {
        byte[] secret = new byte[32];
        random.nextBytes(secret);
        byte[] publicKey = x25519Public(secret);
        if (publicKey == null) {
            wipe(secret);
            return null;
        }
        return new byte[][] {secret, publicKey};
    }

    // y coordinates (little-endian, sign bit cleared) of the points of small
    // order, as in frontend/src/crypto/ed25519.js and content_crypto.py.
    private static final byte[][] SMALL_ORDER_Y = {
        fromHex32("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex32("0100000000000000000000000000000000000000000000000000000000000000"),
        fromHex32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        fromHex32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        fromHex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    };

    /**
     * True for an Ed25519 public key of small order or with a non-canonical
     * encoding (y &gt;= p). Such keys are refused (docs/E2EE_FORMAT.md).
     */
    public static boolean isWeakEd25519PublicKey(byte[] publicKey) {
        if (publicKey == null || publicKey.length != 32) return true;
        byte[] y = publicKey.clone();
        y[31] &= 0x7F;
        if (new BigInteger(1, reversed(y)).compareTo(P25519) >= 0) return true;
        for (byte[] small : SMALL_ORDER_Y) {
            if (Arrays.equals(small, y)) return true;
        }
        return false;
    }

    /** Ed25519 (RFC 8032) verification of a 64-byte signature. Never throws. */
    public static boolean ed25519Verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey == null || publicKey.length != 32 || signature == null || signature.length != 64
                || message == null || isWeakEd25519PublicKey(publicKey)) {
            return false;
        }
        try {
            // Raw encoding: y little-endian, top bit of the last byte = x is odd.
            boolean xOdd = (publicKey[31] & 0x80) != 0;
            byte[] y = publicKey.clone();
            y[31] &= 0x7F;
            EdECPoint point = new EdECPoint(xOdd, new BigInteger(1, reversed(y)));
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** AES-256-GCM; {@code in} is ciphertext || tag(16). Throws on a bad tag. */
    static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] in, int offset, int length)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(in, offset, length);
    }

    // ---------------------------------------------------------------------
    // Base64url (no padding, strict, like content_crypto.b64u_decode)
    // ---------------------------------------------------------------------

    public static String b64uEncode(byte[] data) {
        StringBuilder out = new StringBuilder((data.length * 4 + 2) / 3);
        int i = 0;
        for (; i + 3 <= data.length; i += 3) {
            int v = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8) | (data[i + 2] & 0xFF);
            out.append(B64U_ALPHABET.charAt((v >> 18) & 63)).append(B64U_ALPHABET.charAt((v >> 12) & 63))
               .append(B64U_ALPHABET.charAt((v >> 6) & 63)).append(B64U_ALPHABET.charAt(v & 63));
        }
        int rest = data.length - i;
        if (rest == 1) {
            int v = (data[i] & 0xFF) << 16;
            out.append(B64U_ALPHABET.charAt((v >> 18) & 63)).append(B64U_ALPHABET.charAt((v >> 12) & 63));
        } else if (rest == 2) {
            int v = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8);
            out.append(B64U_ALPHABET.charAt((v >> 18) & 63)).append(B64U_ALPHABET.charAt((v >> 12) & 63))
               .append(B64U_ALPHABET.charAt((v >> 6) & 63));
        }
        return out.toString();
    }

    /** Base64url without padding and no other characters, at most maxBytes; null otherwise. */
    public static byte[] b64uDecode(String text, int maxBytes) {
        if (text == null || text.isEmpty() || text.length() > 4L * maxBytes / 3 + 4 || text.length() % 4 == 1) {
            return null;
        }
        byte[] out = new byte[text.length() * 3 / 4];
        int length = 0;
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < text.length(); i++) {
            int value = B64U_ALPHABET.indexOf(text.charAt(i));
            if (value < 0) {
                wipe(out);
                return null;
            }
            buffer = (buffer << 6) | value;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[length++] = (byte) ((buffer >> bits) & 0xFF);
            }
        }
        if (length == out.length) return out;
        byte[] exact = Arrays.copyOf(out, length);
        wipe(out);
        return exact;
    }

    // ---------------------------------------------------------------------
    // Keys (section 1)
    // ---------------------------------------------------------------------

    /**
     * Decodes a version-2 {@code vxk_} key: {secret, signPublic}, or null if
     * the prefix, length, version byte or checksum is wrong.
     */
    public static byte[][] sdkKeyDecode(String vxk) {
        if (vxk == null) return null;
        int start = 0;
        int end = vxk.length();
        while (start < end && isTrimmed(vxk.charAt(start))) start++;
        while (end > start && isTrimmed(vxk.charAt(end - 1))) end--;
        String value = vxk.substring(start, end);
        if (value.length() != SDK_KEY_CHARS || !value.startsWith("vxk_")) return null;
        byte[] raw = b64uDecode(value.substring(4), 69);
        try {
            if (raw == null || raw.length != 69 || raw[0] != SDK_KEY_VERSION) return null;
            byte[] digest = sha256(ascii("vaultix-vxk"), Arrays.copyOfRange(raw, 0, 65));
            boolean ok = MessageDigest.isEqual(Arrays.copyOfRange(digest, 0, 4), Arrays.copyOfRange(raw, 65, 69));
            wipe(digest);
            if (!ok) return null;
            return new byte[][] {Arrays.copyOfRange(raw, 1, 33), Arrays.copyOfRange(raw, 33, 65)};
        } finally {
            wipe(raw);
        }
    }

    private static boolean isTrimmed(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\u000B' || c == '\f';
    }

    /** kh = HKDF(sk_sdk, "vaultix-e2ee-v1", "hash-key"). */
    public static byte[] hashKey(byte[] sdkSecret) {
        return hkdfSha256(sdkSecret, ascii("vaultix-e2ee-v1"), ascii("hash-key"), 32);
    }

    /** keyedHash = HMAC(kh, SHA-256 digest). */
    public static byte[] keyedHash(byte[] hashKey, byte[] sha256Digest) {
        return hmacSha256(hashKey, sha256Digest);
    }

    /** SHA256("vaultix-fp" || pk_sdk || aspk)[0:8] as "XXXX-XXXX-XXXX-XXXX". */
    public static String fingerprint(byte[] sdkPublic, byte[] signPublic) {
        byte[] digest = sha256(ascii("vaultix-fp"), sdkPublic, signPublic);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i > 0 && i % 2 == 0) out.append('-');
            out.append(Character.toUpperCase(Character.forDigit((digest[i] >> 4) & 0xF, 16)))
               .append(Character.toUpperCase(Character.forDigit(digest[i] & 0xF, 16)));
        }
        return out.toString();
    }

    /** What the SDK holds of an app (from its {@code vxk_} key). */
    public static final class ContentKey {
        final byte[] sdkSecret;   // sk_sdk: opens sealed file keys and values
        final byte[] signPublic;  // aspk: approves the team members who sign content
        final byte[] hashKey;     // kh: keyed hashes

        private ContentKey(byte[] sdkSecret, byte[] signPublic, byte[] hashKey) {
            this.sdkSecret = sdkSecret;
            this.signPublic = signPublic;
            this.hashKey = hashKey;
        }

        /** The key of a {@code vxk_} string, or null if it is invalid. */
        public static ContentKey fromSdkKey(String vxk) {
            byte[][] parts = sdkKeyDecode(vxk);
            if (parts == null) return null;
            return new ContentKey(parts[0], parts[1], hashKey(parts[0]));
        }

        ContentKey copy() {
            return new ContentKey(sdkSecret.clone(), signPublic.clone(), hashKey.clone());
        }

        /** The app signing public key (aspk), a copy. */
        public byte[] signPublic() {
            return signPublic.clone();
        }

        /** pk_sdk, or null if it cannot be computed. */
        public byte[] sdkPublic() {
            return x25519Public(sdkSecret);
        }

        /** "XXXX-XXXX-XXXX-XXXX", as shown in App Settings; "" if it cannot be computed. */
        public String fingerprint() {
            byte[] sdkPublic = sdkPublic();
            return sdkPublic == null ? "" : Zk1.fingerprint(sdkPublic, signPublic);
        }

        /** Overwrites the key material. The object is unusable afterwards. */
        public void wipe() {
            Zk1.wipe(sdkSecret);
            Zk1.wipe(signPublic);
            Zk1.wipe(hashKey);
        }
    }

    // ---------------------------------------------------------------------
    // Seal (section 3)
    // ---------------------------------------------------------------------

    /**
     * kind || 0x00 || scope || 0x00 || name for "file", "folder" and "var"; an
     * empty array for another kind. The scope is the product ID, or "" for a
     * general file or folder.
     */
    public static byte[] sealContext(String kind, String name, String productId) {
        if (!"file".equals(kind) && !"folder".equals(kind) && !"var".equals(kind)) return new byte[0];
        return concat(ascii(kind), new byte[] {0}, utf8(productId), new byte[] {0}, utf8(name));
    }

    /** Opens a sealed key or value; throws if it does not open with this secret and context. */
    public static byte[] unseal(byte[] appSecret, byte[] sealed, byte[] context) throws Zk1Exception {
        if (sealed == null || sealed.length < 1 + 32 + TAG_BYTES || sealed[0] != SEAL_VERSION
                || context == null || context.length == 0) {
            throw new Zk1Exception("unsupported sealed format");
        }
        byte[] ephPublic = Arrays.copyOfRange(sealed, 1, 33);
        byte[] appPublic = x25519Public(appSecret);
        byte[] shared = appPublic == null ? null : x25519Shared(appSecret, ephPublic);
        if (shared == null) throw new Zk1Exception("cannot open the sealed key");
        byte[] key = hkdfSha256(shared, concat(ephPublic, appPublic), concat(ascii("vaultix-zk1-seal"), new byte[] {0}, context), 32);
        wipe(shared);
        try {
            return aesGcmDecrypt(key, new byte[12], context, sealed, 33, sealed.length - 33);
        } catch (GeneralSecurityException e) {
            throw new Zk1Exception("cannot open the sealed key");
        } finally {
            wipe(key);
        }
    }

    // ---------------------------------------------------------------------
    // Signed messages and the signature block (sections 4 and 5)
    // ---------------------------------------------------------------------

    /** The member approval message; null if a text contains 0x00. */
    public static byte[] memberMessage(String appId, String userId, byte[] encPublic, byte[] signPublic, long issuedAtMs) {
        if (hasNul(appId) || hasNul(userId)) return null;
        return concat(ascii("vaultix-member-v1"), new byte[] {0}, utf8(appId), new byte[] {0}, utf8(userId),
                new byte[] {0}, encPublic, signPublic, u64be(issuedAtMs));
    }

    /** The upload message; null if a text contains 0x00 or the kind is not "file" or "folder". */
    public static byte[] uploadMessage(String appId, String kind, String scope, String name, byte[] keyedHash,
                                       long size, long signedAtMs) {
        if ((!"file".equals(kind) && !"folder".equals(kind)) || hasNul(appId) || hasNul(scope) || hasNul(name)
                || keyedHash == null || keyedHash.length != 32) {
            return null;
        }
        return concat(ascii("vaultix-upload-v1"), new byte[] {0}, utf8(appId), new byte[] {0}, ascii(kind),
                new byte[] {0}, utf8(scope), new byte[] {0}, utf8(name), new byte[] {0}, keyedHash,
                u64be(size), u64be(signedAtMs));
    }

    /** The variable message; null if a text contains 0x00. */
    public static byte[] variableMessage(String appId, String productId, String name, byte[] keyedHash, long signedAtMs) {
        if (hasNul(appId) || hasNul(productId) || hasNul(name) || keyedHash == null || keyedHash.length != 32) {
            return null;
        }
        return concat(ascii("vaultix-var-v1"), new byte[] {0}, utf8(appId), new byte[] {0}, utf8(productId),
                new byte[] {0}, utf8(name), new byte[] {0}, keyedHash, u64be(signedAtMs));
    }

    /**
     * 0x01 || u16be(len userId) || userId || upk_enc || upk_sign || u64be(issuedAtMs)
     * || certSig(64) || u64be(signedAtMs) || sig(64).
     */
    public static final class SignatureBlock {
        public final String userId;
        public final byte[] encPublic;
        public final byte[] signPublic;
        public final long issuedAtMs;
        public final byte[] certSignature;
        public final long signedAtMs;
        public final byte[] signature;

        private SignatureBlock(String userId, byte[] encPublic, byte[] signPublic, long issuedAtMs,
                               byte[] certSignature, long signedAtMs, byte[] signature) {
            this.userId = userId;
            this.encPublic = encPublic;
            this.signPublic = signPublic;
            this.issuedAtMs = issuedAtMs;
            this.certSignature = certSignature;
            this.signedAtMs = signedAtMs;
            this.signature = signature;
        }

        /** The parsed block, or null if it does not match the format. */
        public static SignatureBlock parse(byte[] raw, int offset, int length) {
            if (raw == null || offset < 0 || length < 3 || offset + length > raw.length || raw[offset] != 1) return null;
            int idLength = readU16be(raw, offset + 1);
            if (idLength < 1 || idLength > MAX_USER_ID_BYTES || length != 3 + idLength + 32 + 32 + 8 + 64 + 8 + 64) {
                return null;
            }
            int p = offset + 3;
            String userId = decodeUtf8Strict(raw, p, idLength);
            if (userId == null) return null;
            p += idLength;
            byte[] encPublic = Arrays.copyOfRange(raw, p, p + 32);
            p += 32;
            byte[] signPublic = Arrays.copyOfRange(raw, p, p + 32);
            p += 32;
            long issuedAt = readU64be(raw, p);
            p += 8;
            byte[] cert = Arrays.copyOfRange(raw, p, p + 64);
            p += 64;
            long signedAt = readU64be(raw, p);
            p += 8;
            byte[] signature = Arrays.copyOfRange(raw, p, p + 64);
            return new SignatureBlock(userId, encPublic, signPublic, issuedAt, cert, signedAt, signature);
        }
    }

    /**
     * Parses a signature block, checks the owner's approval (certSig) with the
     * app signing key over the member message for appId, then the signer's
     * signature over messageFor(signedAtMs) (zk1_reference.verify_signature_block).
     */
    public static SignatureBlock verifySignatureBlock(byte[] raw, int offset, int length, String appId,
                                                      byte[] appSignPublic, LongFunction<byte[]> messageFor)
            throws Zk1Exception {
        SignatureBlock block = SignatureBlock.parse(raw, offset, length);
        if (block == null) throw new Zk1Exception("invalid signature block");
        byte[] member = memberMessage(appId, block.userId, block.encPublic, block.signPublic, block.issuedAtMs);
        if (member == null || !ed25519Verify(appSignPublic, member, block.certSignature)) {
            throw new Zk1Exception("the signer is not approved by the app owner");
        }
        byte[] message = messageFor == null ? null : messageFor.apply(block.signedAtMs);
        if (message == null || !ed25519Verify(block.signPublic, message, block.signature)) {
            throw new Zk1Exception("invalid signature");
        }
        return block;
    }

    // ---------------------------------------------------------------------
    // Layer 3 delivery header and key (section 8)
    // ---------------------------------------------------------------------

    /** A parsed {@code X-Encryption-Key: zk1d.<b64u server pk>.<kind>.<objectId>}. */
    public static final class DeliveryHeader {
        public final byte[] serverPublic;
        public final String kind;
        public final String objectId;

        private DeliveryHeader(byte[] serverPublic, String kind, String objectId) {
            this.serverPublic = serverPublic;
            this.kind = kind;
            this.objectId = objectId;
        }
    }

    /** The parsed header value, or null. */
    public static DeliveryHeader parseDeliveryHeader(String value) {
        String prefix = "zk1d.";
        if (value == null || !value.startsWith(prefix)) return null;
        String rest = value.substring(prefix.length());
        int first = rest.indexOf('.');
        int second = first < 0 ? -1 : rest.indexOf('.', first + 1);
        if (second < 0 || rest.indexOf('.', second + 1) >= 0) return null;
        String publicPart = rest.substring(0, first);
        String kind = rest.substring(first + 1, second);
        String objectId = rest.substring(second + 1);
        if ((!"file".equals(kind) && !"folder".equals(kind) && !"vars".equals(kind)) || objectId.isEmpty()) return null;
        byte[] raw = b64uDecode(publicPart, 32);
        if (raw == null || raw.length != 32) return null;
        return new DeliveryHeader(raw, kind, objectId);
    }

    /** K = HKDF(X25519(c_sk, s_pk), c_pk || s_pk, "vaultix-zk1-deliver" 0 kind 0 objectId); null on failure. */
    public static byte[] deliveryKey(byte[] clientSecret, byte[] serverPublic, String kind, String objectId) {
        byte[] clientPublic = x25519Public(clientSecret);
        byte[] shared = clientPublic == null ? null : x25519Shared(clientSecret, serverPublic);
        if (shared == null) return null;
        byte[] info = concat(ascii("vaultix-zk1-deliver"), new byte[] {0}, ascii(kind), new byte[] {0}, utf8(objectId));
        byte[] key = hkdfSha256(shared, concat(clientPublic, serverPublic), info, 32);
        wipe(shared);
        return key;
    }

    // ---------------------------------------------------------------------
    // Stream (section 6)
    // ---------------------------------------------------------------------

    /**
     * Incremental stream decryption ("VXZ1" stored, "VXD1" delivery). The sink
     * only sees chunks whose tag verified, but the stream as a whole is
     * authentic only when {@link #finish()} returns true: on failure the caller
     * must discard everything the sink received.
     */
    public static final class StreamDecryptor {
        private final byte[] magic;
        private final Sink sink;
        private Cipher cipher;
        private SecretKeySpec keySpec;
        private final byte[] header = new byte[HEADER_BYTES];
        private int headerLength;
        private boolean headerChecked;
        private final byte[] pending = new byte[2 * FULL_CHUNK];  // ciphertext after the header, not yet opened
        private int pendingLength;
        private final byte[] plain = new byte[FULL_CHUNK];
        private long index;
        private long plaintextBytes;
        private boolean failed;
        private boolean finished;
        private String error = "";

        public StreamDecryptor(byte[] key, String magic, Sink sink) {
            this.magic = ascii(magic);
            this.sink = sink;
            try {
                this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
                this.keySpec = new SecretKeySpec(key, "AES");
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                fail("AES-256-GCM is not available");
            }
        }

        private boolean fail(String message) {
            if (!failed) error = message;
            failed = true;
            return false;
        }

        private boolean openChunk(byte[] data, int offset, int length, boolean last) {
            if (length < TAG_BYTES) return fail(index == 0 ? "stream too short" : "truncated stream");
            if (index > 0xFFFFFFFFL) return fail("too many chunks");
            byte[] nonce = new byte[12];
            nonce[7] = (byte) (index >>> 24);
            nonce[8] = (byte) (index >>> 16);
            nonce[9] = (byte) (index >>> 8);
            nonce[10] = (byte) index;
            nonce[11] = (byte) (last ? 1 : 0);
            int plainLength;
            try {
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, nonce));
                cipher.updateAAD(header);
                plainLength = cipher.doFinal(data, offset, length, plain, 0);
            } catch (GeneralSecurityException | RuntimeException e) {
                wipe(plain);
                return fail("chunk " + index + " failed authentication");
            }
            index++;
            plaintextBytes += plainLength;
            if (plainLength > 0 && sink != null && !sink.accept(plain, 0, plainLength)) {
                return fail("the decrypted data could not be stored");
            }
            return true;
        }

        public boolean update(byte[] data, int offset, int length) {
            if (failed) return false;
            if (finished) return fail("data after the end of the stream");
            while (headerLength < HEADER_BYTES && length > 0) {
                header[headerLength++] = data[offset++];
                length--;
            }
            if (headerLength < HEADER_BYTES) return true;
            if (!headerChecked) {
                if (!Arrays.equals(Arrays.copyOfRange(header, 0, 4), magic) || header[4] != STREAM_VERSION) {
                    return fail("unsupported stream header");
                }
                if (readU32be(header, 5) != CHUNK_SIZE) return fail("unsupported chunk size");
                headerChecked = true;
            }
            // While more than one full chunk is buffered, the first one cannot be
            // the final chunk; the rest is decided at finish().
            while (length > 0) {
                int take = Math.min(pending.length - pendingLength, length);
                System.arraycopy(data, offset, pending, pendingLength, take);
                pendingLength += take;
                offset += take;
                length -= take;
                int done = 0;
                while (pendingLength - done > FULL_CHUNK) {
                    if (!openChunk(pending, done, FULL_CHUNK, false)) return false;
                    done += FULL_CHUNK;
                }
                if (done > 0) {
                    System.arraycopy(pending, done, pending, 0, pendingLength - done);
                    pendingLength -= done;
                }
            }
            return true;
        }

        /** Call at the end of the data. */
        public boolean finish() {
            if (failed) return false;
            if (finished) return true;
            if (headerLength < HEADER_BYTES || (index == 0 && pendingLength < TAG_BYTES)) {
                return fail("stream too short");
            }
            if (!openChunk(pending, 0, pendingLength, true)) return false;
            pendingLength = 0;
            finished = true;
            return true;
        }

        public String error() {
            return error;
        }

        public long plaintextBytes() {
            return plaintextBytes;
        }

        /** Wipes the buffers. */
        public void close() {
            wipe(pending);
            wipe(plain);
            pendingLength = 0;
        }
    }

    /** Decrypts a whole stream; throws on any defect and releases no plaintext then. */
    public static byte[] streamDecrypt(byte[] key, byte[] blob, String magic) throws Zk1Exception {
        GrowableBytes out = new GrowableBytes(Math.max(0, blob.length - HEADER_BYTES));
        StreamDecryptor decryptor = new StreamDecryptor(key, magic, out::append);
        try {
            if (!decryptor.update(blob, 0, blob.length) || !decryptor.finish()) {
                out.wipe();
                throw new Zk1Exception(decryptor.error());
            }
            return out.toArray();
        } finally {
            decryptor.close();
            out.wipe();
        }
    }

    /** A byte buffer that wipes what it drops. */
    static final class GrowableBytes {
        private byte[] data;
        private int length;
        private final int limit;

        GrowableBytes(int initialCapacity) {
            this(initialCapacity, Integer.MAX_VALUE - 8);
        }

        GrowableBytes(int initialCapacity, int limit) {
            this.data = new byte[Math.max(16, Math.min(initialCapacity, 1 << 24))];
            this.limit = limit;
        }

        boolean append(byte[] in, int offset, int count) {
            if (count > limit - length) return false;
            if (length + count > data.length) {
                long wanted = Math.max((long) data.length * 2, (long) length + count);
                byte[] bigger = new byte[(int) Math.min(wanted, (long) limit)];
                System.arraycopy(data, 0, bigger, 0, length);
                Zk1.wipe(data);
                data = bigger;
            }
            System.arraycopy(in, offset, data, length, count);
            length += count;
            return true;
        }

        int length() {
            return length;
        }

        byte[] raw() {
            return data;
        }

        byte[] toArray() {
            return Arrays.copyOf(data, length);
        }

        void wipe() {
            Zk1.wipe(data);
            length = 0;
        }
    }

    // ---------------------------------------------------------------------
    // Delivery opener (section 8)
    // ---------------------------------------------------------------------

    /** The result of {@link #openDelivery}. */
    public static final class OpenedDelivery {
        public final String kind;
        public final String objectId;
        public final byte[] payload;

        OpenedDelivery(String kind, String objectId, byte[] payload) {
            this.kind = kind;
            this.objectId = objectId;
            this.payload = payload;
        }
    }

    /** Opens a whole VXD1 delivery body (zk1_reference.open_delivery). */
    public static OpenedDelivery openDelivery(byte[] clientSecret, String headerValue, byte[] body, String expectedKind)
            throws Zk1Exception {
        DeliveryHeader header = parseDeliveryHeader(headerValue);
        if (header == null) throw new Zk1Exception("invalid delivery header");
        if (expectedKind != null && !expectedKind.isEmpty() && !expectedKind.equals(header.kind)) {
            throw new Zk1Exception("unexpected delivery kind");
        }
        byte[] key = deliveryKey(clientSecret, header.serverPublic, header.kind, header.objectId);
        if (key == null) throw new Zk1Exception("invalid server key in the delivery header");
        try {
            return new OpenedDelivery(header.kind, header.objectId, streamDecrypt(key, body, DELIVERY_MAGIC));
        } finally {
            wipe(key);
        }
    }

    /**
     * One layer-3 delivery: VXD1 under the one-time key; for "file" and "folder"
     * also the sealed file key, the signature block and the VXZ1 content. The
     * signature block is verified before the content is decrypted (the content
     * sink sees nothing before that), and the content is checked against the
     * sealed size and SHA-256. The content is authentic only when
     * {@link #finish()} returns true; on failure everything the sink received
     * must be discarded.
     */
    public static final class DeliveryOpener {
        private byte[] clientSecret;
        private final String expectedKind;
        private String kind = "";
        private String objectId = "";
        private ContentKey key;
        private String appId = "";
        private String name = "";
        private String productId = "";
        private String scope = "";
        private Sink contentSink;
        private StreamDecryptor outer;   // VXD1 under the one-time key
        private StreamDecryptor inner;   // VXZ1 under the file key, once the signature verified
        private final byte[] prefix = new byte[2 + SEALED_FILE_KEY_BYTES + 2];
        private int prefixLength;
        private boolean sealedOpened;
        private final byte[] fileKey = new byte[32];
        private final byte[] signatureBlock = new byte[MAX_SIGNATURE_BLOCK_BYTES];
        private int signatureLength;
        private int signatureReceived;
        private long signedAt;
        private final byte[] contentSha256 = new byte[32];
        private long contentSize;
        private long contentWritten;
        private MessageDigest hash;
        private final GrowableBytes vars = new GrowableBytes(4096, MAX_VARS_PAYLOAD_BYTES);
        private String error = "";
        private boolean failed;
        private boolean begun;
        private boolean finished;

        public DeliveryOpener(byte[] clientSecret, String expectedKind) {
            this.clientSecret = clientSecret.clone();
            this.expectedKind = expectedKind == null ? "" : expectedKind;
        }

        /**
         * file/folder: the content key, the app id (signed messages), and the
         * name and product that were requested; the sealed key is opened with
         * the product scope, else with the general scope "".
         */
        public void setFileContext(ContentKey key, String appId, String name, String productId, Sink contentSink) {
            if (this.key != null) this.key.wipe();
            this.key = key == null ? null : key.copy();
            this.appId = appId == null ? "" : appId;
            this.name = name == null ? "" : name;
            this.productId = productId == null ? "" : productId;
            this.contentSink = contentSink;
        }

        private boolean fail(String message) {
            if (!failed) error = message;
            failed = true;
            return false;
        }

        /** The X-Encryption-Key value. */
        public boolean begin(String headerValue) {
            if (failed) return false;
            if (begun || clientSecret == null) return fail("delivery already started");
            DeliveryHeader header = parseDeliveryHeader(headerValue);
            if (header == null) return fail("invalid delivery header");
            if (!expectedKind.isEmpty() && !header.kind.equals(expectedKind)) {
                return fail("unexpected delivery kind '" + header.kind + "' (asked for " + expectedKind + ")");
            }
            if (!"vars".equals(header.kind) && key == null) return fail("no content key");
            byte[] deliveryKey = deliveryKey(clientSecret, header.serverPublic, header.kind, header.objectId);
            wipe(clientSecret);  // one delivery per request key
            clientSecret = null;
            if (deliveryKey == null) return fail("invalid server key in the delivery header");
            kind = header.kind;
            objectId = header.objectId;
            begun = true;
            outer = new StreamDecryptor(deliveryKey, DELIVERY_MAGIC, this::onPayload);
            wipe(deliveryKey);
            if (!outer.error().isEmpty()) return fail(outer.error());
            return true;
        }

        public boolean update(byte[] data, int offset, int length) {
            if (failed) return false;
            if (!begun || finished) return fail("unexpected delivery data");
            if (!outer.update(data, offset, length)) return fail(outer.error());
            return true;
        }

        public boolean finish() {
            if (failed) return false;
            if (!begun) return fail("delivery not started");
            if (finished) return true;
            if (!outer.finish()) return fail(outer.error());
            if (!"vars".equals(kind)) {
                if (inner == null) return fail("delivery too short");
                if (!inner.finish()) return fail(inner.error());
                if (contentWritten != contentSize) return fail("the file does not match its sealed size");
                byte[] digest = hash.digest();
                boolean same = MessageDigest.isEqual(digest, contentSha256);
                wipe(digest);
                if (!same) return fail("the file does not match its sealed SHA-256");
            }
            finished = true;
            return true;
        }

        // The sealed file key and the signature block's length are in.
        private boolean openSealedKey() {
            if (key == null) return fail("no content key");
            // A download by name gets the product's own item or, failing that,
            // the general item of that name: try the product scope, then the
            // general scope (zk1_reference.sdk_unseal_file_key).
            byte[] sealed = Arrays.copyOfRange(prefix, 2, 2 + SEALED_FILE_KEY_BYTES);
            byte[] payload = null;
            try {
                payload = unseal(key.sdkSecret, sealed, sealContext(kind, name, productId));
                scope = productId;
            } catch (Zk1Exception first) {
                if (!productId.isEmpty()) {
                    try {
                        payload = unseal(key.sdkSecret, sealed, sealContext(kind, name, ""));
                        scope = "";
                    } catch (Zk1Exception second) {
                        payload = null;
                    }
                }
            }
            if (payload == null || payload.length != FILE_KEY_PAYLOAD_BYTES) {
                wipe(payload);
                scope = "";
                return fail("cannot open the sealed file key (wrong content key, or it was sealed for another name or product)");
            }
            System.arraycopy(payload, 0, fileKey, 0, 32);
            System.arraycopy(payload, 32, contentSha256, 0, 32);
            contentSize = readU64be(payload, 64);
            wipe(payload);
            sealedOpened = true;
            signatureLength = readU16be(prefix, 2 + SEALED_FILE_KEY_BYTES);
            if (signatureLength < MIN_SIGNATURE_BLOCK_BYTES || signatureLength > MAX_SIGNATURE_BLOCK_BYTES) {
                return fail("invalid signature block in delivery");
            }
            return true;
        }

        // The whole signature block is in: verify it (zk1_reference.sdk_open_file),
        // and only then start decrypting the content.
        private boolean verifySignature() {
            byte[] keyedHash = keyedHash(key.hashKey, contentSha256);
            SignatureBlock block;
            try {
                block = verifySignatureBlock(signatureBlock, 0, signatureLength, appId, key.signPublic,
                        at -> uploadMessage(appId, kind, scope, name, keyedHash, contentSize, at));
            } catch (Zk1Exception e) {
                return fail("signature check failed: " + e.getMessage());
            }
            signedAt = block.signedAtMs;
            key.wipe();  // not needed any more
            key = null;
            hash = newSha256();
            inner = new StreamDecryptor(fileKey, STORED_MAGIC, this::onContent);
            wipe(fileKey);
            if (!inner.error().isEmpty()) return fail(inner.error());
            return true;
        }

        private boolean onPayload(byte[] data, int offset, int length) {
            if (failed) return false;
            if ("vars".equals(kind)) {
                if (!vars.append(data, offset, length)) return fail("variables payload too large");
                return true;
            }
            // u16be(len sealed) || sealed || u16be(len sig) || signature block || VXZ1 stream
            while (prefixLength < prefix.length && length > 0) {
                prefix[prefixLength++] = data[offset++];
                length--;
                if (prefixLength == 2 && readU16be(prefix, 0) != SEALED_FILE_KEY_BYTES) {
                    return fail("invalid sealed key in delivery");
                }
            }
            if (prefixLength < prefix.length) return true;
            if (!sealedOpened && !openSealedKey()) return false;
            if (inner == null) {
                int take = Math.min(signatureLength - signatureReceived, length);
                System.arraycopy(data, offset, signatureBlock, signatureReceived, take);
                signatureReceived += take;
                offset += take;
                length -= take;
                if (signatureReceived < signatureLength) return true;
                if (!verifySignature()) return false;
            }
            if (length == 0) return true;
            if (!inner.update(data, offset, length)) return fail(inner.error());
            return true;
        }

        private boolean onContent(byte[] data, int offset, int length) {
            if (failed) return false;
            if (length > contentSize - contentWritten) return fail("the file is larger than its sealed size");
            hash.update(data, offset, length);
            contentWritten += length;
            if (contentSink != null && !contentSink.accept(data, offset, length)) {
                return fail("the decrypted file could not be stored");
            }
            return true;
        }

        public String error() {
            return error;
        }

        public String kind() {
            return kind;
        }

        public String objectId() {
            return objectId;
        }

        /** file/folder: productId or "" (general), once opened. */
        public String scope() {
            return scope;
        }

        /** file/folder: the sealed plaintext size, once known (else 0). */
        public long contentSize() {
            return sealedOpened ? contentSize : 0;
        }

        /** file/folder: signedAtMs, once the signature verified (else 0). */
        public long signedAt() {
            return inner != null ? signedAt : 0;
        }

        /** "vars": the JSON payload (a copy), valid after finish(). */
        public byte[] varsPayload() {
            return vars.toArray();
        }

        /** Wipes every secret and buffer. */
        public void close() {
            if (outer != null) outer.close();
            if (inner != null) inner.close();
            wipe(clientSecret);
            clientSecret = null;
            if (key != null) key.wipe();
            key = null;
            wipe(fileKey);
            wipe(prefix);
            wipe(contentSha256);
            wipe(signatureBlock);
            vars.wipe();
        }
    }

    // ---------------------------------------------------------------------
    // Variables (strict JSON reader for the delivery payload)
    // ---------------------------------------------------------------------

    /**
     * The JSON of a "vars" delivery as (name, value) pairs. zk1 values are
     * opened with key (may be null if the list has none) and the product id,
     * and their signature blocks ("sig") verified for appId. Any failure
     * throws, and no values are returned at all.
     */
    public static List<Map.Entry<String, String>> openVariables(byte[] payload, ContentKey key, String appId,
                                                                String productId) throws Zk1Exception {
        String json = decodeUtf8Strict(payload, 0, payload.length);
        if (json == null) throw new Zk1Exception("invalid variables payload");
        List<Map.Entry<String, String>> result = new ArrayList<>();
        JsonReader reader = new JsonReader(json);
        if (!reader.eat('[')) throw new Zk1Exception("invalid variables payload");
        if (!reader.eat(']')) {
            do {
                String name = null, enc = null, value = null, sig = null;
                boolean hasName = false, hasEnc = false, hasValue = false, hasSig = false;
                boolean ok = reader.eat('{');
                if (ok && !reader.eat('}')) {
                    do {
                        String field = reader.string();
                        ok = field != null && reader.eat(':');
                        if (!ok) break;
                        switch (field) {
                            case "name":
                                ok = !hasName && (name = reader.string()) != null;
                                hasName = true;
                                break;
                            case "enc":
                                ok = !hasEnc;
                                hasEnc = true;
                                if (ok && !reader.literal("null")) ok = (enc = reader.string()) != null;
                                break;
                            case "value":
                                ok = !hasValue;
                                hasValue = true;
                                if (ok && !reader.literal("null")) ok = (value = reader.string()) != null;
                                break;
                            case "sig":
                                ok = !hasSig;
                                hasSig = true;
                                if (ok && !reader.literal("null")) ok = (sig = reader.string()) != null;
                                break;
                            default:
                                ok = reader.skipValue(0);
                                break;
                        }
                    } while (ok && reader.eat(','));
                    ok = ok && reader.eat('}');
                }
                if (!ok) throw new Zk1Exception("invalid variables payload");
                if (!hasName) throw new Zk1Exception("a variable has no name");
                if (enc == null) {
                    result.add(new AbstractMap.SimpleImmutableEntry<>(name, value == null ? "" : value));
                    continue;
                }
                if (!"zk1".equals(enc)) throw new Zk1Exception("variable '" + name + "' uses an unknown encoding");
                if (key == null) throw new Zk1Exception(NEED_CONTENT_KEY);
                result.add(new AbstractMap.SimpleImmutableEntry<>(name, openVariable(key, appId, productId, name, value, sig)));
            } while (reader.eat(','));
            if (!reader.eat(']')) throw new Zk1Exception("invalid variables payload");
        }
        if (!reader.atEnd()) throw new Zk1Exception("invalid variables payload");
        return result;
    }

    /** One zk1 value (zk1_reference.sdk_open_variable): unsealed and signed by an approved member. */
    static String openVariable(ContentKey key, String appId, String productId, String name, String value, String sig)
            throws Zk1Exception {
        byte[] sealed = value == null ? null : b64uDecode(value, MAX_SEALED_BYTES);
        byte[] plain = null;
        String text = null;
        if (sealed != null) {
            try {
                plain = unseal(key.sdkSecret, sealed, sealContext("var", name, productId));
                text = decodeUtf8Strict(plain, 0, plain.length);
            } catch (Zk1Exception e) {
                plain = null;
            }
        }
        try {
            if (plain == null || text == null) {
                throw new Zk1Exception("cannot open variable '" + name
                        + "' (wrong content key, or it was sealed for another name or product)");
            }
            byte[] block = sig == null ? null : b64uDecode(sig, MAX_SIGNATURE_BLOCK_BYTES);
            if (block == null) throw new Zk1Exception("variable '" + name + "' has no valid signature block");
            byte[] digest = sha256(plain);
            byte[] keyedHash = keyedHash(key.hashKey, digest);
            wipe(digest);
            try {
                verifySignatureBlock(block, 0, block.length, appId, key.signPublic,
                        at -> variableMessage(appId, productId, name, keyedHash, at));
            } catch (Zk1Exception e) {
                throw new Zk1Exception("variable '" + name + "': signature check failed: " + e.getMessage());
            }
            return text;
        } finally {
            wipe(plain);
        }
    }

    /** A strict JSON reader (strings, nested values skipped), as in the C++ SDK. */
    private static final class JsonReader {
        private final String s;
        private int i;

        JsonReader(String text) {
            this.s = text;
        }

        void skipSpace() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
                i++;
            }
        }

        boolean eat(char c) {
            skipSpace();
            if (i < s.length() && s.charAt(i) == c) {
                i++;
                return true;
            }
            return false;
        }

        boolean atEnd() {
            skipSpace();
            return i == s.length();
        }

        boolean literal(String word) {
            skipSpace();
            if (!s.startsWith(word, i)) return false;
            i += word.length();
            return true;
        }

        String string() {
            skipSpace();
            if (i >= s.length() || s.charAt(i) != '"') return null;
            i++;
            StringBuilder out = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return out.toString();
                if (c < 0x20) return null;
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (i >= s.length()) return null;
                char e = s.charAt(i++);
                switch (e) {
                    case '"': case '\\': case '/': out.append(e); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u': {
                        int cp = hex4();
                        if (cp < 0) return null;
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (i + 1 >= s.length() || s.charAt(i) != '\\' || s.charAt(i + 1) != 'u') return null;
                            i += 2;
                            int low = hex4();
                            if (low < 0xDC00 || low > 0xDFFF) return null;
                            out.append((char) cp).append((char) low);
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            return null;
                        } else {
                            out.append((char) cp);
                        }
                        break;
                    }
                    default:
                        return null;
                }
            }
            return null;
        }

        private int hex4() {
            if (s.length() - i < 4) return -1;
            int out = 0;
            for (int k = 0; k < 4; k++) {
                int v = Character.digit(s.charAt(i++), 16);
                if (v < 0) return -1;
                out = (out << 4) | v;
            }
            return out;
        }

        boolean skipValue(int depth) {
            if (depth > 32) return false;
            skipSpace();
            if (i >= s.length()) return false;
            char c = s.charAt(i);
            if (c == '"') return string() != null;
            if (c == '{' || c == '[') {
                char close = c == '{' ? '}' : ']';
                i++;
                if (eat(close)) return true;
                do {
                    if (c == '{' && (string() == null || !eat(':'))) return false;
                    if (!skipValue(depth + 1)) return false;
                } while (eat(','));
                return eat(close);
            }
            if (literal("true") || literal("false") || literal("null")) return true;
            int start = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            int digits = i;
            while (i < s.length()) {
                char d = s.charAt(i);
                if (!(Character.isDigit(d) && d < 128) && d != '.' && d != 'e' && d != 'E' && d != '+' && d != '-') break;
                i++;
            }
            return i > digits && i > start && s.charAt(digits) >= '0' && s.charAt(digits) <= '9';
        }
    }
}
