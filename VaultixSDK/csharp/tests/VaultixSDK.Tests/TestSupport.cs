using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Xunit;

namespace Vaultix.SDK.Tests
{
    /// <summary>
    /// backend/tests/crypto_vectors/zk1.json of the Vaultix repository. Path from
    /// VAULTIX_ZK1_VECTORS, else the copy in vectors/zk1.json (copied to the output directory).
    /// </summary>
    internal static class Vectors
    {
        private static readonly Lazy<JsonDocument?> Document = new(Load);

        internal static string? FindPath()
        {
            string? fromEnv = Environment.GetEnvironmentVariable("VAULTIX_ZK1_VECTORS");
            if (!string.IsNullOrEmpty(fromEnv)) return File.Exists(fromEnv) ? fromEnv : null;
            string local = Path.Combine(AppContext.BaseDirectory, "vectors", "zk1.json");
            return File.Exists(local) ? local : null;
        }

        private static JsonDocument? Load()
        {
            string? path = FindPath();
            return path == null ? null : JsonDocument.Parse(File.ReadAllBytes(path));
        }

        internal static JsonElement Root => Document.Value?.RootElement
            ?? throw new InvalidOperationException("zk1.json not found (set VAULTIX_ZK1_VECTORS)");
    }

    /// <summary>A fact that needs zk1.json; skipped when the vectors are not available.</summary>
    public sealed class VectorFactAttribute : FactAttribute
    {
        public VectorFactAttribute()
        {
            if (Vectors.FindPath() == null)
            {
                Skip = "zk1.json not found (tests/VaultixSDK.Tests/vectors/zk1.json, or the file VAULTIX_ZK1_VECTORS names)";
            }
        }
    }

    internal static class Hex
    {
        internal static byte[] Bytes(string hex) => Convert.FromHexString(hex);
        internal static string Of(ReadOnlySpan<byte> data) => Convert.ToHexString(data).ToLowerInvariant();
        internal static string Sha256(ReadOnlySpan<byte> data) => Of(SHA256.HashData(data));
    }

    /// <summary>The writer side of the format, for building test inputs (the SDK only reads).</summary>
    internal static class Writer
    {
        internal const int ChunkSize = 1048576;

        /// <summary>byte i = (i * 31 + 7 + seed) mod 256</summary>
        internal static byte[] Pattern(int length, int seed = 0)
        {
            var data = new byte[length];
            for (int i = 0; i < length; ++i) data[i] = (byte)((i * 31 + 7 + seed) & 0xFF);
            return data;
        }

        internal static byte[] StreamEncrypt(byte[] key, byte[] data, string magic)
        {
            byte[] header = new byte[9];
            Encoding.ASCII.GetBytes(magic).CopyTo(header, 0);
            header[4] = 1;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(5), ChunkSize);
            int count = Math.Max(1, (data.Length + ChunkSize - 1) / ChunkSize);
            using var output = new MemoryStream();
            output.Write(header);
            using var gcm = new AesGcm(key, 16);
            for (int i = 0; i < count; ++i)
            {
                int start = i * ChunkSize;
                int length = Math.Min(ChunkSize, data.Length - start);
                byte[] nonce = new byte[12];
                nonce[7] = (byte)(i >> 24);
                nonce[8] = (byte)(i >> 16);
                nonce[9] = (byte)(i >> 8);
                nonce[10] = (byte)i;
                nonce[11] = (byte)(i == count - 1 ? 1 : 0);
                byte[] cipher = new byte[length];
                byte[] tag = new byte[16];
                gcm.Encrypt(nonce, data.AsSpan(start, length), cipher, tag, header);
                output.Write(cipher);
                output.Write(tag);
            }
            return output.ToArray();
        }

        /// <summary>(X-Encryption-Key value, body) of a layer-3 delivery (content_crypto.Delivery).</summary>
        internal static (string Header, byte[] Body) Delivery(byte[] serverSecret, byte[] clientPublic, string kind,
                                                               string objectId, byte[] payload)
        {
            byte[] serverPublic = new byte[32];
            X25519.ScalarMultBase(serverSecret, 0, serverPublic, 0);
            byte[] shared = new byte[32];
            X25519.ScalarMult(serverSecret, 0, clientPublic, 0, shared, 0);
            byte[] salt = clientPublic.Concat(serverPublic).ToArray();
            byte[] info = Encoding.UTF8.GetBytes("vaultix-zk1-deliver\0" + kind + "\0" + objectId);
            byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, salt, info);
            string header = "zk1d." + Zk1.B64uEncode(serverPublic) + "." + kind + "." + objectId;
            return (header, StreamEncrypt(key, payload, "VXD1"));
        }

        /// <summary>u16be(len sealed) || sealed || u16be(len sig) || signature block</summary>
        internal static byte[] FilePrefix(byte[] sealedKey, byte[] signature)
        {
            var prefix = new List<byte> { (byte)(sealedKey.Length >> 8), (byte)sealedKey.Length };
            prefix.AddRange(sealedKey);
            prefix.Add((byte)(signature.Length >> 8));
            prefix.Add((byte)signature.Length);
            prefix.AddRange(signature);
            return prefix.ToArray();
        }

        internal static byte[] X25519Public(byte[] secret)
        {
            byte[] pub = new byte[32];
            X25519.ScalarMultBase(secret, 0, pub, 0);
            return pub;
        }
    }

    /// <summary>Result of opening a delivery with the SDK's DeliveryOpener.</summary>
    internal sealed class Opened
    {
        public bool Ok;
        public string Error = "";
        public byte[] Data = Array.Empty<byte>();
        public string Scope = "";
        public ulong SignedAt;
        public string Vars = "";
    }

    internal static class Open
    {
        /// <summary>Feeds the body in pieces of the given size (0 = all at once).</summary>
        internal static Opened Delivery(byte[] clientSecret, string header, byte[] body, string expectedKind,
                                        Zk1.ContentKey? key = null, string appId = "", string name = "",
                                        string productId = "", int piece = 0)
        {
            var result = new Opened();
            var received = new MemoryStream();
            using var opener = new Zk1.DeliveryOpener(clientSecret, expectedKind);
            if (key != null)
            {
                opener.SetFileContext(key, appId, name, productId, data =>
                {
                    received.Write(data);
                    return true;
                });
            }
            bool ok = opener.Begin(header);
            int step = piece <= 0 ? Math.Max(1, body.Length) : piece;
            for (int offset = 0; ok && offset < body.Length; offset += step)
            {
                ok = opener.Update(body.AsSpan(offset, Math.Min(step, body.Length - offset)));
            }
            ok = ok && opener.Finish();
            result.Ok = ok;
            result.Error = opener.Error;
            result.Data = received.ToArray();
            result.Scope = opener.Scope;
            result.SignedAt = opener.SignedAt;
            if (ok && opener.Kind == "vars") result.Vars = Encoding.UTF8.GetString(opener.VarsPayload);
            return result;
        }
    }
}
