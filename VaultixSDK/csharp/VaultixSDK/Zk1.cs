using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Vaultix.SDK
{
    /// <summary>
    /// End-to-end encryption ("zk1"): the SDK side of the format. A port of the
    /// zk1 namespace of the C++ SDK (VaultixClient.cpp) and of the Python
    /// reference (backend/tests/zk1_reference.py). The download functions of
    /// <see cref="VaultixClient"/> use this; integrations only call
    /// <see cref="VaultixClient.SetContentKey"/>.
    /// </summary>
    internal static class Zk1
    {
        internal const int ChunkSize = 1048576;          // plaintext bytes per stream chunk
        internal const int TagBytes = 16;                // AES-GCM tag after every chunk
        internal const int HeaderBytes = 9;              // magic(4) || version(1) || u32be chunk size
        internal const int SealedFileKeyBytes = 121;     // 0x01 || eph pk || GCM(fk || sha256 || u64be size)
        internal const int MaxSealedBytes = 65536;       // a sealed variable value
        internal const int SdkKeyChars = 96;             // "vxk_" + b64u(0x02 || sk_sdk || aspk || checksum(4))
        internal const int MaxUserIdBytes = 128;
        internal const int MinSignatureBlockBytes = 3 + 1 + 208;                 // 1-byte user id
        internal const int MaxSignatureBlockBytes = 3 + MaxUserIdBytes + 208;    // 339
        internal const int FileKeyPayloadBytes = 72;                             // fk || sha256 || u64be size
        internal const int MaxVarsPayloadBytes = 64 * 1024 * 1024;               // decrypted variables JSON

        internal const string StoredMagic = "VXZ1";
        internal const string DeliveryMagic = "VXD1";
        internal const string DeliveryHeaderPrefix = "zk1d.";
        internal const string NeedContentKey =
            "This app uses end-to-end encryption: call SetContentKey with the vxk_ key from App Settings";

        private const byte SealVersion = 1;
        private const byte StreamVersion = 1;
        private const string B64uAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        // Strict UTF-8, like Python's bytes.decode("utf-8").
        internal static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        internal delegate bool Sink(ReadOnlySpan<byte> data);

        // ------------------------------------------------------------------
        // Content key
        // ------------------------------------------------------------------

        /// <summary>What the SDK holds of an app (from its vxk_ key). Zeroed on Dispose.</summary>
        internal sealed class ContentKey : IDisposable
        {
            public readonly byte[] SdkSecret = new byte[32];   // sk_sdk: opens the sealed file keys and values
            public readonly byte[] SignPublic = new byte[32];  // aspk: approves the team members who sign content
            public readonly byte[] HashKey = new byte[32];     // kh = HKDF(sk_sdk, "vaultix-e2ee-v1", "hash-key")

            public ContentKey Clone()
            {
                var copy = new ContentKey();
                SdkSecret.CopyTo(copy.SdkSecret, 0);
                SignPublic.CopyTo(copy.SignPublic, 0);
                HashKey.CopyTo(copy.HashKey, 0);
                return copy;
            }

            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(SdkSecret);
                CryptographicOperations.ZeroMemory(SignPublic);
                CryptographicOperations.ZeroMemory(HashKey);
            }
        }

        /// <summary>Decodes a vxk_ key (version 2 only) and derives kh; null for anything else.</summary>
        internal static ContentKey? ContentKeyFromSdkKey(string? vxk)
        {
            var key = new ContentKey();
            if (!SdkKeyDecode(vxk, key.SdkSecret, key.SignPublic))
            {
                key.Dispose();
                return null;
            }
            byte[] kh = HashKey(key.SdkSecret);
            kh.CopyTo(key.HashKey, 0);
            CryptographicOperations.ZeroMemory(kh);
            return key;
        }

        // "vxk_" + b64u(0x02 || sk_sdk(32) || aspk(32) || SHA256("vaultix-vxk" || 0x02 || sk_sdk || aspk)[0:4])
        // (zk1_reference.sdk_key_decode). Other versions, the 52-character
        // version-1 keys included, are refused.
        internal static bool SdkKeyDecode(string? vxk, byte[] secret, byte[] signPublic)
        {
            const int body = 1 + 32 + 32;
            if (vxk == null) return false;
            string value = vxk.Trim(' ', '\t', '\r', '\n', '\v', '\f');
            if (value.Length != SdkKeyChars || !value.StartsWith("vxk_", StringComparison.Ordinal)) return false;
            byte[]? raw = B64uDecode(value.Substring(4), body + 4);
            if (raw == null) return false;
            try
            {
                if (raw.Length != body + 4 || raw[0] != 2) return false;
                byte[] label = Encoding.ASCII.GetBytes("vaultix-vxk");
                byte[] digest = Sha256(label, raw.AsSpan(0, body));
                bool ok = CryptographicOperations.FixedTimeEquals(digest.AsSpan(0, 4), raw.AsSpan(body, 4));
                CryptographicOperations.ZeroMemory(digest);
                if (!ok) return false;
                raw.AsSpan(1, 32).CopyTo(secret);
                raw.AsSpan(33, 32).CopyTo(signPublic);
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(raw);
            }
        }

        internal static byte[] HashKey(byte[] sdkSecret) =>
            Hkdf(sdkSecret, Encoding.ASCII.GetBytes("vaultix-e2ee-v1"), Encoding.ASCII.GetBytes("hash-key"));

        /// <summary>SHA256("vaultix-fp" || pk_sdk || aspk)[0:8] as "XXXX-XXXX-XXXX-XXXX".</summary>
        internal static string Fingerprint(byte[] sdkPublic, byte[] signPublic)
        {
            byte[] keys = new byte[64];
            sdkPublic.CopyTo(keys, 0);
            signPublic.CopyTo(keys, 32);
            byte[] digest = Sha256(Encoding.ASCII.GetBytes("vaultix-fp"), keys);
            string hex = Convert.ToHexString(digest, 0, 8);
            return $"{hex.Substring(0, 4)}-{hex.Substring(4, 4)}-{hex.Substring(8, 4)}-{hex.Substring(12, 4)}";
        }

        // ------------------------------------------------------------------
        // Primitives
        // ------------------------------------------------------------------

        internal static byte[] Sha256(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(a);
            hash.AppendData(b);
            return hash.GetHashAndReset();
        }

        internal static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int length = 32) =>
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info);

        internal static byte[] HmacSha256(byte[] key, ReadOnlySpan<byte> data) => HMACSHA256.HashData(key, data);

        internal static byte[] X25519Public(byte[] secret)
        {
            byte[] pub = new byte[32];
            X25519.ScalarMultBase(secret, 0, pub, 0);
            return pub;
        }

        /// <summary>X25519; false (and zeroed output) for low-order peers, i.e. an all-zero result.</summary>
        internal static bool X25519Shared(byte[] secret, byte[] peerPublic, byte[] shared)
        {
            if (secret.Length != 32 || peerPublic.Length != 32 || shared.Length != 32) return false;
            X25519.ScalarMult(secret, 0, peerPublic, 0, shared, 0);
            int any = 0;
            for (int i = 0; i < 32; ++i) any |= shared[i];
            if (any == 0)
            {
                CryptographicOperations.ZeroMemory(shared);
                return false;
            }
            return true;
        }

        /// <summary>A fresh random X25519 key pair.</summary>
        internal static void X25519Generate(byte[] secret, byte[] publicKey)
        {
            RandomNumberGenerator.Fill(secret);
            X25519.ScalarMultBase(secret, 0, publicKey, 0);
        }

        // Ed25519 points of small order (and the non-canonical encodings of the
        // ones with x = 0). With such a "public key" a trivial signature verifies
        // for any message in permissive implementations, so they are refused like
        // non-canonical encodings (y >= p). Same list as content_crypto.py.
        private static readonly byte[][] SmallOrderEd25519 = new[]
        {
            "0100000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        }.Select(Convert.FromHexString).ToArray();

        /// <summary>True for a small-order or non-canonically encoded Ed25519 public key.</summary>
        internal static bool WeakSigningKey(ReadOnlySpan<byte> raw)
        {
            if (raw.Length != 32) return true;
            foreach (byte[] weak in SmallOrderEd25519)
            {
                if (raw.SequenceEqual(weak)) return true;
            }
            // y = little-endian value with the top (sign) bit cleared; refuse y >= p = 2^255 - 19
            if ((raw[31] & 0x7F) != 0x7F) return false;
            for (int i = 30; i >= 1; --i)
            {
                if (raw[i] != 0xFF) return false;
            }
            return raw[0] >= 0xED;
        }

        /// <summary>Ed25519 (RFC 8032) verification of a 64-byte signature; weak keys are refused.</summary>
        internal static bool Ed25519Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (publicKey.Length != 32 || signature.Length != 64 || WeakSigningKey(publicKey)) return false;
            try
            {
                byte[] msg = message.ToArray();
                return Ed25519.Verify(signature.ToArray(), 0, publicKey.ToArray(), 0, msg, 0, msg.Length);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>AES-256-GCM open; in = ciphertext || tag(16). Null on failure.</summary>
        internal static byte[]? AesGcmDecrypt(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> input)
        {
            if (input.Length < TagBytes) return null;
            byte[] plain = new byte[input.Length - TagBytes];
            try
            {
                using var gcm = new AesGcm(key, TagBytes);
                gcm.Decrypt(nonce, input.Slice(0, plain.Length), input.Slice(plain.Length), plain, aad);
                return plain;
            }
            catch (Exception)
            {
                CryptographicOperations.ZeroMemory(plain);
                return null;
            }
        }

        internal static string B64uEncode(ReadOnlySpan<byte> data) =>
            Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>
        /// Like content_crypto.b64u_decode: base64url without padding, the
        /// reference's length limit, no other characters. Null on failure.
        /// </summary>
        internal static byte[]? B64uDecode(string? text, int maxBytes)
        {
            if (string.IsNullOrEmpty(text) || text.Length > 4L * maxBytes / 3 + 4 || text.Length % 4 == 1) return null;
            var output = new byte[text.Length * 3 / 4];
            int count = 0;
            uint buffer = 0;
            int bits = 0;
            foreach (char c in text)
            {
                int value = B64uAlphabet.IndexOf(c);
                if (value < 0)
                {
                    CryptographicOperations.ZeroMemory(output);
                    return null;
                }
                buffer = (buffer << 6) | (uint)value;
                bits += 6;
                if (bits >= 8)
                {
                    bits -= 8;
                    output[count++] = (byte)((buffer >> bits) & 0xFF);
                }
            }
            if (count == output.Length) return output;
            byte[] exact = output.AsSpan(0, count).ToArray();
            CryptographicOperations.ZeroMemory(output);
            return exact;
        }

        private static ulong ReadU64be(ReadOnlySpan<byte> p) => System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(p);

        private static uint ReadU32be(ReadOnlySpan<byte> p) => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(p);

        private static void AppendU64be(List<byte> output, ulong value)
        {
            for (int shift = 56; shift >= 0; shift -= 8) output.Add((byte)(value >> shift));
        }

        private static void AppendText(List<byte> output, string text) => output.AddRange(Encoding.UTF8.GetBytes(text));

        private static bool HasNul(string text) => text.IndexOf('\0') >= 0;

        // ------------------------------------------------------------------
        // Seal (docs/E2EE_FORMAT.md section 3)
        // ------------------------------------------------------------------

        /// <summary>
        /// kind || 0x00 || scope || 0x00 || name for "file", "folder", "var"; empty
        /// for another kind. scope = the product id, or "" for a general file or folder.
        /// </summary>
        internal static byte[] SealContext(string kind, string name, string productId = "")
        {
            if (kind != "var" && kind != "file" && kind != "folder") return Array.Empty<byte>();
            var context = new List<byte>();
            AppendText(context, kind);
            context.Add(0);
            AppendText(context, productId ?? "");
            context.Add(0);
            AppendText(context, name ?? "");
            return context.ToArray();
        }

        /// <summary>Opens a sealed payload; null if it does not open.</summary>
        internal static byte[]? Unseal(byte[] appSecret, ReadOnlySpan<byte> sealedData, byte[] context)
        {
            if (sealedData.Length < 1 + 32 + TagBytes || sealedData[0] != SealVersion || context.Length == 0) return null;
            byte[] ephPublic = sealedData.Slice(1, 32).ToArray();
            byte[] appPublic = X25519Public(appSecret);
            byte[] shared = new byte[32];
            byte[]? key = null;
            try
            {
                if (!X25519Shared(appSecret, ephPublic, shared)) return null;
                byte[] salt = new byte[64];
                ephPublic.CopyTo(salt, 0);
                appPublic.CopyTo(salt, 32);
                var info = new List<byte>();
                AppendText(info, "vaultix-zk1-seal");
                info.Add(0);
                info.AddRange(context);
                key = Hkdf(shared, salt, info.ToArray());
                return AesGcmDecrypt(key, new byte[12], context, sealedData.Slice(33));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(shared);
                if (key != null) CryptographicOperations.ZeroMemory(key);
            }
        }

        // ------------------------------------------------------------------
        // Signed messages (sections 4 and 5). Empty if a text contains 0x00 or
        // (upload) the kind is not "file" or "folder".
        // ------------------------------------------------------------------

        internal static byte[] MemberMessage(string appId, string userId, ReadOnlySpan<byte> encPublic,
                                             ReadOnlySpan<byte> signPublic, ulong issuedAtMs)
        {
            if (HasNul(appId) || HasNul(userId)) return Array.Empty<byte>();
            var m = new List<byte>();
            AppendText(m, "vaultix-member-v1");
            m.Add(0);
            AppendText(m, appId);
            m.Add(0);
            AppendText(m, userId);
            m.Add(0);
            m.AddRange(encPublic.ToArray());
            m.AddRange(signPublic.ToArray());
            AppendU64be(m, issuedAtMs);
            return m.ToArray();
        }

        internal static byte[] UploadMessage(string appId, string kind, string scope, string name,
                                             ReadOnlySpan<byte> keyedHash, ulong size, ulong signedAtMs)
        {
            if ((kind != "file" && kind != "folder") || keyedHash.Length != 32 ||
                HasNul(appId) || HasNul(scope) || HasNul(name)) return Array.Empty<byte>();
            var m = new List<byte>();
            AppendText(m, "vaultix-upload-v1");
            m.Add(0);
            AppendText(m, appId);
            m.Add(0);
            AppendText(m, kind);
            m.Add(0);
            AppendText(m, scope);
            m.Add(0);
            AppendText(m, name);
            m.Add(0);
            m.AddRange(keyedHash.ToArray());
            AppendU64be(m, size);
            AppendU64be(m, signedAtMs);
            return m.ToArray();
        }

        internal static byte[] VariableMessage(string appId, string productId, string name,
                                               ReadOnlySpan<byte> keyedHash, ulong signedAtMs)
        {
            if (keyedHash.Length != 32 || HasNul(appId) || HasNul(productId) || HasNul(name)) return Array.Empty<byte>();
            var m = new List<byte>();
            AppendText(m, "vaultix-var-v1");
            m.Add(0);
            AppendText(m, appId);
            m.Add(0);
            AppendText(m, productId);
            m.Add(0);
            AppendText(m, name);
            m.Add(0);
            m.AddRange(keyedHash.ToArray());
            AppendU64be(m, signedAtMs);
            return m.ToArray();
        }

        /// <summary>
        /// 0x01 || u16be(len userId) || userId || upk_enc || upk_sign || u64be(issuedAtMs)
        ///      || certSig(64) || u64be(signedAtMs) || sig(64)
        /// </summary>
        internal sealed class SignatureBlock
        {
            public string UserId = "";
            public byte[] EncPublic = new byte[32];
            public byte[] SignPublic = new byte[32];
            public ulong IssuedAtMs;
            public byte[] CertSignature = new byte[64];
            public ulong SignedAtMs;
            public byte[] Signature = new byte[64];
        }

        internal static SignatureBlock? ParseSignatureBlock(ReadOnlySpan<byte> data)
        {
            if (data.Length < 3 || data[0] != 1) return null;
            int idLength = (data[1] << 8) | data[2];
            if (idLength < 1 || idLength > MaxUserIdBytes || data.Length != 3 + idLength + 32 + 32 + 8 + 64 + 8 + 64) return null;
            var block = new SignatureBlock();
            int p = 3;
            try
            {
                block.UserId = StrictUtf8.GetString(data.Slice(p, idLength));
            }
            catch (ArgumentException)
            {
                return null;
            }
            p += idLength;
            data.Slice(p, 32).CopyTo(block.EncPublic);
            p += 32;
            data.Slice(p, 32).CopyTo(block.SignPublic);
            p += 32;
            block.IssuedAtMs = ReadU64be(data.Slice(p, 8));
            p += 8;
            data.Slice(p, 64).CopyTo(block.CertSignature);
            p += 64;
            block.SignedAtMs = ReadU64be(data.Slice(p, 8));
            p += 8;
            data.Slice(p, 64).CopyTo(block.Signature);
            return block;
        }

        /// <summary>
        /// zk1_reference.verify_signature_block: parses the block, checks certSig
        /// with the app signing key (aspk) over the member message for appId, then
        /// sig with the member's upk_sign over messageFor(signedAtMs).
        /// </summary>
        internal static SignatureBlock? VerifySignatureBlock(ReadOnlySpan<byte> data, string appId, byte[] appSignPublic,
                                                            Func<ulong, byte[]> messageFor, out string error)
        {
            error = "";
            SignatureBlock? block = ParseSignatureBlock(data);
            if (block == null)
            {
                error = "invalid signature block";
                return null;
            }
            byte[] member = MemberMessage(appId, block.UserId, block.EncPublic, block.SignPublic, block.IssuedAtMs);
            if (member.Length == 0 || !Ed25519Verify(appSignPublic, member, block.CertSignature))
            {
                error = "the signer is not approved by the app owner";
                return null;
            }
            byte[] message = messageFor(block.SignedAtMs);
            if (message.Length == 0 || !Ed25519Verify(block.SignPublic, message, block.Signature))
            {
                error = "invalid signature";
                return null;
            }
            return block;
        }

        // ------------------------------------------------------------------
        // Layer 3: delivery (section 8)
        // ------------------------------------------------------------------

        /// <summary>"zk1d.&lt;b64u server pk&gt;.&lt;kind&gt;.&lt;objectId&gt;"</summary>
        internal static bool ParseDeliveryHeader(string? value, out byte[] serverPublic, out string kind, out string objectId)
        {
            serverPublic = Array.Empty<byte>();
            kind = "";
            objectId = "";
            if (value == null || !value.StartsWith(DeliveryHeaderPrefix, StringComparison.Ordinal)) return false;
            string[] parts = value.Substring(DeliveryHeaderPrefix.Length).Split('.');
            if (parts.Length != 3) return false;
            if ((parts[1] != "file" && parts[1] != "folder" && parts[1] != "vars") || parts[2].Length == 0) return false;
            byte[]? raw = B64uDecode(parts[0], 32);
            if (raw == null || raw.Length != 32) return false;
            serverPublic = raw;
            kind = parts[1];
            objectId = parts[2];
            return true;
        }

        internal static byte[]? DeliveryKey(byte[] clientSecret, byte[] serverPublic, string kind, string objectId)
        {
            byte[] clientPublic = X25519Public(clientSecret);
            byte[] shared = new byte[32];
            try
            {
                if (!X25519Shared(clientSecret, serverPublic, shared)) return null;
                byte[] salt = new byte[64];
                clientPublic.CopyTo(salt, 0);
                serverPublic.CopyTo(salt, 32);
                var info = new List<byte>();
                AppendText(info, "vaultix-zk1-deliver");
                info.Add(0);
                AppendText(info, kind);
                info.Add(0);
                AppendText(info, objectId);
                return Hkdf(shared, salt, info.ToArray());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(shared);
            }
        }

        // ------------------------------------------------------------------
        // Stream (section 6)
        // ------------------------------------------------------------------

        /// <summary>
        /// Incremental stream decryption ("VXZ1" stored, "VXD1" delivery). The sink
        /// only sees chunks whose tag verified, but the stream as a whole is
        /// authentic only when Finish() returns true: on failure the caller must
        /// discard everything the sink received.
        /// </summary>
        internal sealed class StreamDecryptor : IDisposable
        {
            private const int Full = ChunkSize + TagBytes;
            private readonly AesGcm? _gcm;
            private readonly byte[] _magic;
            private readonly Sink? _sink;
            private readonly byte[] _header = new byte[HeaderBytes];
            private int _headerLength;
            private bool _headerChecked;
            private readonly byte[] _pending = new byte[Full];   // ciphertext after the header, not yet opened
            private int _pendingLength;
            private readonly byte[] _plain = new byte[ChunkSize]; // plaintext of one chunk
            private readonly byte[] _nonce = new byte[12];
            private ulong _index;
            private bool _failed;
            private bool _finished;

            public string Error { get; private set; } = "";
            public ulong PlaintextBytes { get; private set; }

            public StreamDecryptor(byte[] key, string magic, Sink? sink)
            {
                _magic = Encoding.ASCII.GetBytes(magic);
                _sink = sink;
                try
                {
                    _gcm = new AesGcm(key, TagBytes);
                }
                catch (Exception)
                {
                    Fail("AES-256-GCM is not available");
                }
            }

            private bool Fail(string message)
            {
                if (!_failed) Error = message;
                _failed = true;
                return false;
            }

            private bool OpenChunk(ReadOnlySpan<byte> data, bool last)
            {
                if (data.Length < TagBytes) return Fail(_index == 0 ? "stream too short" : "truncated stream");
                if (_index > 0xFFFFFFFFUL) return Fail("too many chunks");
                Array.Clear(_nonce);
                _nonce[7] = (byte)(_index >> 24);
                _nonce[8] = (byte)(_index >> 16);
                _nonce[9] = (byte)(_index >> 8);
                _nonce[10] = (byte)_index;
                _nonce[11] = (byte)(last ? 1 : 0);
                int plainLength = data.Length - TagBytes;
                Span<byte> plain = _plain.AsSpan(0, plainLength);
                try
                {
                    _gcm!.Decrypt(_nonce, data.Slice(0, plainLength), data.Slice(plainLength), plain, _header);
                }
                catch (CryptographicException)
                {
                    CryptographicOperations.ZeroMemory(plain);
                    return Fail($"chunk {_index} failed authentication");
                }
                ++_index;
                PlaintextBytes += (ulong)plainLength;
                if (plainLength > 0 && _sink != null && !_sink(plain))
                {
                    return Fail("the decrypted data could not be stored");
                }
                return true;
            }

            public bool Update(ReadOnlySpan<byte> data)
            {
                if (_failed) return false;
                if (_finished) return Fail("data after the end of the stream");
                while (_headerLength < HeaderBytes && data.Length > 0)
                {
                    _header[_headerLength++] = data[0];
                    data = data.Slice(1);
                }
                if (_headerLength < HeaderBytes) return true;
                if (!_headerChecked)
                {
                    if (!_header.AsSpan(0, 4).SequenceEqual(_magic) || _header[4] != StreamVersion)
                    {
                        return Fail("unsupported stream header");
                    }
                    if (ReadU32be(_header.AsSpan(5, 4)) != ChunkSize) return Fail("unsupported chunk size");
                    _headerChecked = true;
                }
                // A full chunk followed by more data cannot be the final chunk;
                // what is left at Finish() is the final chunk.
                while (data.Length > 0)
                {
                    if (_pendingLength == Full)
                    {
                        if (!OpenChunk(_pending, false)) return false;
                        _pendingLength = 0;
                    }
                    int take = Math.Min(Full - _pendingLength, data.Length);
                    data.Slice(0, take).CopyTo(_pending.AsSpan(_pendingLength));
                    _pendingLength += take;
                    data = data.Slice(take);
                }
                return true;
            }

            /// <summary>Call at the end of the data.</summary>
            public bool Finish()
            {
                if (_failed) return false;
                if (_finished) return true;
                if (_headerLength < HeaderBytes || (_index == 0 && _pendingLength < TagBytes))
                {
                    return Fail("stream too short");
                }
                if (!OpenChunk(_pending.AsSpan(0, _pendingLength), true)) return false;
                _pendingLength = 0;
                _finished = true;
                return true;
            }

            public void Dispose()
            {
                _gcm?.Dispose();
                CryptographicOperations.ZeroMemory(_plain);
                CryptographicOperations.ZeroMemory(_pending);
            }
        }

        /// <summary>
        /// One layer-3 delivery: VXD1 under the one-time key; for "file" and
        /// "folder" also the sealed file key, the signature block and the VXZ1
        /// content. The signature block is verified before the content is
        /// decrypted (the sink sees nothing before that), and the content is
        /// checked against the sealed size and SHA-256. Same failure rule as
        /// <see cref="StreamDecryptor"/>.
        /// </summary>
        internal sealed class DeliveryOpener : IDisposable
        {
            private readonly byte[] _clientSecret = new byte[32];
            private bool _haveClientSecret;
            private readonly string _expectedKind;
            private ContentKey? _key;
            private string _appId = "";
            private string _name = "";
            private string _productId = "";
            private Sink? _contentSink;
            private StreamDecryptor? _outer;   // VXD1 under the one-time key
            private StreamDecryptor? _inner;   // VXZ1 under the file key, once the signature verified
            private readonly byte[] _prefix = new byte[2 + SealedFileKeyBytes + 2];  // u16be(121) || sealed || u16be(len sig)
            private int _prefixLength;
            private bool _sealedOpened;
            private readonly byte[] _fileKey = new byte[32];
            private readonly byte[] _signatureBlock = new byte[MaxSignatureBlockBytes];
            private int _signatureLength;
            private int _signatureReceived;
            private ulong _signedAt;
            private readonly byte[] _contentSha256 = new byte[32];
            private ulong _contentSize;
            private ulong _contentWritten;
            private IncrementalHash? _hash;
            private byte[] _vars = Array.Empty<byte>();
            private int _varsLength;
            private bool _failed;
            private bool _begun;
            private bool _finished;

            public string Error { get; private set; } = "";
            public string Kind { get; private set; } = "";
            public string ObjectId { get; private set; } = "";
            /// <summary>file/folder: productId or "" (general), once opened.</summary>
            public string Scope { get; private set; } = "";
            /// <summary>file/folder: the sealed plaintext size, once known.</summary>
            public ulong ContentSize => _sealedOpened ? _contentSize : 0;
            /// <summary>file/folder: signedAtMs, once the signature verified (else 0).</summary>
            public ulong SignedAt => _inner != null ? _signedAt : 0;
            /// <summary>"vars": the JSON bytes, valid after Finish().</summary>
            public ReadOnlySpan<byte> VarsPayload => _vars.AsSpan(0, _varsLength);

            public DeliveryOpener(byte[] clientSecret, string expectedKind)
            {
                clientSecret.AsSpan(0, 32).CopyTo(_clientSecret);
                _haveClientSecret = true;
                _expectedKind = expectedKind ?? "";
            }

            /// <summary>
            /// file/folder: the content key (the opener takes ownership), the app
            /// id (signed messages), and the name and product that were requested;
            /// the sealed key is opened with the product scope, else with the
            /// general scope "".
            /// </summary>
            public void SetFileContext(ContentKey key, string appId, string name, string productId, Sink? contentSink)
            {
                _key?.Dispose();
                _key = key;
                _appId = appId ?? "";
                _name = name ?? "";
                _productId = productId ?? "";
                _contentSink = contentSink;
            }

            private bool Fail(string message)
            {
                if (!_failed) Error = message;
                _failed = true;
                return false;
            }

            /// <summary>The X-Encryption-Key value.</summary>
            public bool Begin(string headerValue)
            {
                if (_failed) return false;
                if (_begun || !_haveClientSecret) return Fail("delivery already started");
                if (!ParseDeliveryHeader(headerValue, out byte[] serverPublic, out string kind, out string objectId))
                {
                    return Fail("invalid delivery header");
                }
                if (_expectedKind.Length > 0 && kind != _expectedKind)
                {
                    return Fail($"unexpected delivery kind '{kind}' (asked for {_expectedKind})");
                }
                if (kind != "vars" && _key == null) return Fail("no content key");
                byte[]? key = DeliveryKey(_clientSecret, serverPublic, kind, objectId);
                CryptographicOperations.ZeroMemory(_clientSecret);  // one delivery per request key
                _haveClientSecret = false;
                if (key == null) return Fail("invalid server key in the delivery header");
                Kind = kind;
                ObjectId = objectId;
                _begun = true;
                _outer = new StreamDecryptor(key, DeliveryMagic, OnPayload);
                CryptographicOperations.ZeroMemory(key);
                if (_outer.Error.Length > 0) return Fail(_outer.Error);
                return true;
            }

            public bool Update(ReadOnlySpan<byte> data)
            {
                if (_failed) return false;
                if (!_begun || _finished) return Fail("unexpected delivery data");
                if (!_outer!.Update(data)) return Fail(_outer.Error);
                return true;
            }

            public bool Finish()
            {
                if (_failed) return false;
                if (!_begun) return Fail("delivery not started");
                if (_finished) return true;
                if (!_outer!.Finish()) return Fail(_outer.Error);
                if (Kind != "vars")
                {
                    if (_inner == null) return Fail("delivery too short");
                    if (!_inner.Finish()) return Fail(_inner.Error);
                    if (_contentWritten != _contentSize) return Fail("the file does not match its sealed size");
                    byte[] digest = _hash!.GetHashAndReset();
                    if (!CryptographicOperations.FixedTimeEquals(digest, _contentSha256))
                    {
                        return Fail("the file does not match its sealed SHA-256");
                    }
                }
                _finished = true;
                return true;
            }

            // The sealed file key and the signature block's length are in.
            private bool OpenSealedKey()
            {
                if (_key == null) return Fail("no content key");
                // A download by name gets the product's own file or, failing
                // that, the general file of that name: try the product scope,
                // then the general scope (zk1_reference.sdk_unseal_file_key).
                ReadOnlySpan<byte> sealedKey = _prefix.AsSpan(2, SealedFileKeyBytes);
                byte[]? payload = Unseal(_key.SdkSecret, sealedKey, SealContext(Kind, _name, _productId));
                Scope = _productId;
                if (payload == null && _productId.Length > 0)
                {
                    payload = Unseal(_key.SdkSecret, sealedKey, SealContext(Kind, _name, ""));
                    Scope = "";
                }
                if (payload == null || payload.Length != FileKeyPayloadBytes)
                {
                    if (payload != null) CryptographicOperations.ZeroMemory(payload);
                    Scope = "";
                    return Fail("cannot open the sealed file key (wrong content key, or it was sealed for another name or product)");
                }
                payload.AsSpan(0, 32).CopyTo(_fileKey);
                payload.AsSpan(32, 32).CopyTo(_contentSha256);
                _contentSize = ReadU64be(payload.AsSpan(64, 8));
                CryptographicOperations.ZeroMemory(payload);
                _sealedOpened = true;
                int sigAt = 2 + SealedFileKeyBytes;
                _signatureLength = (_prefix[sigAt] << 8) | _prefix[sigAt + 1];
                if (_signatureLength < MinSignatureBlockBytes || _signatureLength > MaxSignatureBlockBytes)
                {
                    return Fail("invalid signature block in delivery");
                }
                return true;
            }

            // The whole signature block is in: verify it (zk1_reference.sdk_open_file),
            // and only then start decrypting the content.
            private bool VerifySignature()
            {
                byte[] keyedHash = HmacSha256(_key!.HashKey, _contentSha256);
                string appId = _appId, kind = Kind, scope = Scope, name = _name;
                ulong size = _contentSize;
                SignatureBlock? block = VerifySignatureBlock(_signatureBlock.AsSpan(0, _signatureLength), appId, _key.SignPublic,
                    at => UploadMessage(appId, kind, scope, name, keyedHash, size, at), out string reason);
                if (block == null) return Fail("signature check failed: " + reason);
                _signedAt = block.SignedAtMs;
                _key.Dispose();   // not needed any more
                _key = null;
                _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                _inner = new StreamDecryptor(_fileKey, StoredMagic, OnContent);
                CryptographicOperations.ZeroMemory(_fileKey);
                if (_inner.Error.Length > 0) return Fail(_inner.Error);
                return true;
            }

            private bool OnPayload(ReadOnlySpan<byte> data)
            {
                if (_failed) return false;
                if (Kind == "vars")
                {
                    if (data.Length > MaxVarsPayloadBytes - _varsLength) return Fail("variables payload too large");
                    if (_varsLength + data.Length > _vars.Length)
                    {
                        int capacity = Math.Min(MaxVarsPayloadBytes, Math.Max(_varsLength + data.Length, Math.Max(4096, _vars.Length * 2)));
                        byte[] grown = new byte[capacity];
                        _vars.AsSpan(0, _varsLength).CopyTo(grown);
                        CryptographicOperations.ZeroMemory(_vars);
                        _vars = grown;
                    }
                    data.CopyTo(_vars.AsSpan(_varsLength));
                    _varsLength += data.Length;
                    return true;
                }
                // u16be(len sealed) || sealed || u16be(len sig) || signature block || VXZ1 stream
                while (_prefixLength < _prefix.Length && data.Length > 0)
                {
                    _prefix[_prefixLength++] = data[0];
                    data = data.Slice(1);
                    if (_prefixLength == 2 && ((_prefix[0] << 8) | _prefix[1]) != SealedFileKeyBytes)
                    {
                        return Fail("invalid sealed key in delivery");
                    }
                }
                if (_prefixLength < _prefix.Length) return true;
                if (!_sealedOpened && !OpenSealedKey()) return false;
                if (_inner == null)
                {
                    int take = Math.Min(_signatureLength - _signatureReceived, data.Length);
                    data.Slice(0, take).CopyTo(_signatureBlock.AsSpan(_signatureReceived));
                    _signatureReceived += take;
                    data = data.Slice(take);
                    if (_signatureReceived < _signatureLength) return true;
                    if (!VerifySignature()) return false;
                }
                if (data.Length == 0) return true;
                if (!_inner!.Update(data)) return Fail(_inner.Error);
                return true;
            }

            private bool OnContent(ReadOnlySpan<byte> data)
            {
                if (_failed) return false;
                if ((ulong)data.Length > _contentSize - _contentWritten) return Fail("the file is larger than its sealed size");
                _hash!.AppendData(data);
                _contentWritten += (ulong)data.Length;
                if (_contentSink != null && !_contentSink(data)) return Fail("the decrypted file could not be stored");
                return true;
            }

            public void Dispose()
            {
                _inner?.Dispose();
                _outer?.Dispose();
                _hash?.Dispose();
                _key?.Dispose();
                _key = null;
                CryptographicOperations.ZeroMemory(_clientSecret);
                CryptographicOperations.ZeroMemory(_fileKey);
                CryptographicOperations.ZeroMemory(_prefix);
                CryptographicOperations.ZeroMemory(_contentSha256);
                CryptographicOperations.ZeroMemory(_vars);
                _varsLength = 0;
            }
        }

        // ------------------------------------------------------------------
        // Variables
        // ------------------------------------------------------------------

        /// <summary>
        /// The JSON of a "vars" delivery to (name, value). zk1 values are opened
        /// with key (may be null if the list has none) and the product id, and
        /// their signature blocks ("sig") verified for appId. Any failure: false
        /// and no values at all.
        /// </summary>
        internal static bool OpenVariables(ReadOnlySpan<byte> json, ContentKey? key, string appId, string productId,
                                           out List<KeyValuePair<string, string>> output, out string error)
        {
            output = new List<KeyValuePair<string, string>>();
            error = "";
            JArray? items;
            try
            {
                string text = StrictUtf8.GetString(json);
                using var reader = new JsonTextReader(new StringReader(text))
                {
                    DateParseHandling = DateParseHandling.None,
                    FloatParseHandling = FloatParseHandling.Decimal,
                    MaxDepth = 32,
                };
                var settings = new JsonLoadSettings
                {
                    DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error,
                    CommentHandling = CommentHandling.Load,
                    LineInfoHandling = LineInfoHandling.Ignore,
                };
                items = JToken.ReadFrom(reader, settings) as JArray;
                if (items != null && reader.Read()) items = null;   // anything after the array
            }
            catch (Exception)
            {
                items = null;
            }
            if (items == null)
            {
                error = "invalid variables payload";
                return false;
            }

            var result = new List<KeyValuePair<string, string>>();
            bool ok = true;
            foreach (JToken item in items)
            {
                if (item is not JObject entry)
                {
                    ok = false;
                    error = "invalid variables payload";
                    break;
                }
                if (!TryText(entry, "name", out string? name, out _) || !TryText(entry, "enc", out string? enc, out bool encNull) ||
                    !TryText(entry, "value", out string? value, out bool valueNull) || !TryText(entry, "sig", out string? sig, out bool sigNull))
                {
                    ok = false;
                    error = "invalid variables payload";
                    break;
                }
                if (name == null)
                {
                    ok = false;
                    error = entry.ContainsKey("name") ? "invalid variables payload" : "a variable has no name";
                    break;
                }
                if (encNull)
                {
                    result.Add(new KeyValuePair<string, string>(name, valueNull ? "" : value!));
                    continue;
                }
                if (enc != "zk1")
                {
                    ok = false;
                    error = $"variable '{name}' uses an unknown encoding";
                    break;
                }
                if (key == null)
                {
                    ok = false;
                    error = NeedContentKey;
                    break;
                }
                byte[]? sealedValue = valueNull ? null : B64uDecode(value, MaxSealedBytes);
                byte[]? plain = sealedValue == null ? null : Unseal(key.SdkSecret, sealedValue, SealContext("var", name, productId));
                string? text = null;
                if (plain != null)
                {
                    try
                    {
                        text = StrictUtf8.GetString(plain);
                    }
                    catch (ArgumentException)
                    {
                        text = null;
                    }
                }
                if (plain == null || text == null)
                {
                    if (plain != null) CryptographicOperations.ZeroMemory(plain);
                    ok = false;
                    error = $"cannot open variable '{name}' (wrong content key, or it was sealed for another name or product)";
                    break;
                }
                // zk1_reference.sdk_open_variable: signed by an approved member,
                // for this app, product, name and value.
                byte[]? block = sigNull ? null : B64uDecode(sig, MaxSignatureBlockBytes);
                if (block == null)
                {
                    CryptographicOperations.ZeroMemory(plain);
                    ok = false;
                    error = $"variable '{name}' has no valid signature block";
                    break;
                }
                byte[] digest = SHA256.HashData(plain);
                byte[] keyedHash = HmacSha256(key.HashKey, digest);
                CryptographicOperations.ZeroMemory(digest);
                CryptographicOperations.ZeroMemory(plain);
                string varName = name;
                SignatureBlock? signer = VerifySignatureBlock(block, appId, key.SignPublic,
                    at => VariableMessage(appId, productId, varName, keyedHash, at), out string reason);
                if (signer == null)
                {
                    ok = false;
                    error = $"variable '{name}': signature check failed: {reason}";
                    break;
                }
                result.Add(new KeyValuePair<string, string>(name, text));
            }
            if (!ok)
            {
                if (error.Length == 0) error = "invalid variables payload";
                return false;
            }
            output = result;
            return true;
        }

        // A field that must be a string or null when present. False for another type.
        private static bool TryText(JObject entry, string field, out string? value, out bool isNull)
        {
            value = null;
            isNull = true;
            if (!entry.TryGetValue(field, StringComparison.Ordinal, out JToken? token)) return true;
            if (token.Type == JTokenType.Null) return true;
            if (token.Type != JTokenType.String) return false;
            value = token.Value<string>();
            isNull = false;
            return true;
        }
    }
}
