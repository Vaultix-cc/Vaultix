using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;

namespace Vaultix.SDK.Tests
{
    /// <summary>
    /// The SDK side of zk1 against backend/tests/crypto_vectors/zk1.json, byte for byte.
    /// </summary>
    public class Zk1VectorTests
    {
        private static JsonElement V => Vectors.Root;
        private static string S(JsonElement e, string name) => e.GetProperty(name).GetString()!;
        private static byte[] H(JsonElement e, string name) => Hex.Bytes(S(e, name));
        private static string AppId => S(V, "appId");
        private static JsonElement App(int index) => V.GetProperty("appKeys")[index];

        private static Zk1.ContentKey KeyOf(int app) => Zk1.ContentKeyFromSdkKey(S(App(app), "sdkKey"))!;

        // ------------------------------------------------------------------
        // Primitives (RFC known answers)
        // ------------------------------------------------------------------

        [Fact]
        public void X25519_Rfc7748_KnownAnswers()
        {
            // RFC 7748 section 5.2, first vector
            byte[] shared = new byte[32];
            Assert.True(Zk1.X25519Shared(
                Hex.Bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                Hex.Bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"), shared));
            Assert.Equal("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", Hex.Of(shared));
            // RFC 7748 section 6.1: Alice's public key and the shared secret
            byte[] alice = Hex.Bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            byte[] bob = Hex.Bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Hex.Of(Zk1.X25519Public(alice)));
            Assert.Equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Hex.Of(Zk1.X25519Public(bob)));
            Assert.True(Zk1.X25519Shared(alice, Zk1.X25519Public(bob), shared));
            Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", Hex.Of(shared));
            // A low-order peer gives an all-zero secret: refused
            Assert.False(Zk1.X25519Shared(alice, new byte[32], shared));
        }

        [VectorFact]
        public void Kat_FromVectorFile()
        {
            JsonElement kat = V.GetProperty("kat");
            foreach (JsonElement c in kat.GetProperty("x25519").EnumerateArray())
            {
                byte[] shared = new byte[32];
                Assert.True(Zk1.X25519Shared(H(c, "scalar"), H(c, "u"), shared));
                Assert.Equal(S(c, "out"), Hex.Of(shared));
            }
            foreach (JsonElement c in kat.GetProperty("x25519_public").EnumerateArray())
            {
                Assert.Equal(S(c, "public"), Hex.Of(Zk1.X25519Public(H(c, "scalar"))));
            }
            foreach (JsonElement c in kat.GetProperty("hkdf").EnumerateArray())
            {
                Assert.Equal(S(c, "okm"), Hex.Of(Zk1.Hkdf(H(c, "ikm"), H(c, "salt"), H(c, "info"), c.GetProperty("length").GetInt32())));
            }
            foreach (JsonElement c in kat.GetProperty("hmac_sha256").EnumerateArray())
            {
                Assert.Equal(S(c, "mac"), Hex.Of(Zk1.HmacSha256(H(c, "key"), H(c, "data"))));
            }
            foreach (JsonElement c in kat.GetProperty("aes_gcm").EnumerateArray())
            {
                byte[] input = H(c, "ciphertext").Concat(H(c, "tag")).ToArray();
                byte[]? plain = Zk1.AesGcmDecrypt(H(c, "key"), H(c, "nonce"), H(c, "aad"), input);
                Assert.NotNull(plain);
                Assert.Equal(S(c, "plaintext"), Hex.Of(plain));
                input[^1] ^= 1;
                Assert.Null(Zk1.AesGcmDecrypt(H(c, "key"), H(c, "nonce"), H(c, "aad"), input));
            }
            foreach (JsonElement c in kat.GetProperty("ed25519").EnumerateArray())
            {
                byte[] pub = H(c, "public"), msg = H(c, "message"), sig = H(c, "signature");
                Assert.True(Zk1.Ed25519Verify(pub, msg, sig));
                byte[] flipped = (byte[])sig.Clone();
                flipped[0] ^= 1;
                Assert.False(Zk1.Ed25519Verify(pub, msg, flipped));
                Assert.False(Zk1.Ed25519Verify(pub, Encoding.ASCII.GetBytes("x"), sig));
            }
        }

        [Fact]
        public void Ed25519_RefusesWeakKeysAndMalleableSignatures()
        {
            // RFC 8032 7.1 test 1
            byte[] pub = Hex.Bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            byte[] sig = Hex.Bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
            Assert.True(Zk1.Ed25519Verify(pub, Array.Empty<byte>(), sig));
            // S + L (the same signature, non-canonical S) is refused
            BigInteger l = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
            BigInteger s = new BigInteger(sig.AsSpan(32), isUnsigned: true, isBigEndian: false) + l;
            byte[] malleable = (byte[])sig.Clone();
            byte[] sBytes = s.ToByteArray(isUnsigned: true, isBigEndian: false);
            Array.Clear(malleable, 32, 32);
            sBytes.AsSpan(0, Math.Min(32, sBytes.Length)).CopyTo(malleable.AsSpan(32));
            Assert.False(Zk1.Ed25519Verify(pub, Array.Empty<byte>(), malleable));
            // Identity point as public key with the trivial signature (R = identity, S = 0)
            byte[] identity = Hex.Bytes("0100000000000000000000000000000000000000000000000000000000000000");
            byte[] trivial = new byte[64];
            trivial[0] = 1;
            Assert.True(Zk1.WeakSigningKey(identity));
            Assert.False(Zk1.Ed25519Verify(identity, Encoding.ASCII.GetBytes("any message"), trivial));
            // y >= p (non-canonical encoding) is weak
            Assert.True(Zk1.WeakSigningKey(Hex.Bytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")));
            Assert.False(Zk1.WeakSigningKey(pub));
        }

        [Fact]
        public void B64u_IsStrict()
        {
            Assert.Equal("AQID", Zk1.B64uEncode(new byte[] { 1, 2, 3 }));
            Assert.Equal("_-8", Zk1.B64uEncode(new byte[] { 0xFF, 0xEF }));
            Assert.Equal(new byte[] { 0xFF, 0xEF }, Zk1.B64uDecode("_-8", 2));
            Assert.Null(Zk1.B64uDecode("_-8=", 2));      // no padding
            Assert.Null(Zk1.B64uDecode("/+8", 2));       // not base64url
            Assert.Null(Zk1.B64uDecode("A", 2));          // length % 4 == 1
            Assert.Null(Zk1.B64uDecode("", 2));
            Assert.Null(Zk1.B64uDecode(new string('A', 100), 32));  // longer than the limit
        }

        // ------------------------------------------------------------------
        // vxk_ key, hash key, fingerprint
        // ------------------------------------------------------------------

        [VectorFact]
        public void SdkKey_DecodesAndDerives()
        {
            foreach (int index in new[] { 0, 1 })
            {
                JsonElement a = App(index);
                string vxk = S(a, "sdkKey");
                Assert.Equal(96, vxk.Length);
                byte[] secret = new byte[32], signPublic = new byte[32];
                Assert.True(Zk1.SdkKeyDecode(vxk, secret, signPublic));
                Assert.Equal(S(a, "sdkSecret"), Hex.Of(secret));
                Assert.Equal(S(a, "signPublic"), Hex.Of(signPublic));
                Assert.Equal(S(a, "sdkPublic"), Hex.Of(Zk1.X25519Public(secret)));
                Assert.Equal(S(a, "hashKey"), Hex.Of(Zk1.HashKey(secret)));
                using Zk1.ContentKey key = Zk1.ContentKeyFromSdkKey(vxk)!;
                Assert.Equal(S(a, "hashKey"), Hex.Of(key.HashKey));
                Assert.Equal(S(a, "fingerprint"), Zk1.Fingerprint(H(a, "sdkPublic"), H(a, "signPublic")));
            }
        }

        [VectorFact]
        public void SetContentKey_ClientBehaviour()
        {
            JsonElement a = App(0);
            string vxk = S(a, "sdkKey");
            string fingerprint = S(a, "fingerprint");
            using var client = new VaultixClient("http://127.0.0.1:9/api");
            Assert.False(client.HasContentKey);
            Assert.Equal("", client.GetContentKeyFingerprint());
            Assert.Equal(0, client.GetLastSignedAt());
            Assert.True(client.SetContentKey("  " + vxk + "\n"), "surrounding whitespace is ignored");
            Assert.True(client.HasContentKey);
            Assert.Equal(fingerprint, client.GetContentKeyFingerprint());

            // bad checksum: refused, current key unchanged
            char last = vxk[^1];
            string broken = vxk.Substring(0, 95) + (last == 'A' ? 'B' : 'A');
            Assert.False(client.SetContentKey(broken));
            Assert.Contains("96 characters", client.GetLastError());
            Assert.Equal(fingerprint, client.GetContentKeyFingerprint());

            // another version byte (checksum recomputed) and the old 52-character v1 keys: refused
            byte[] secret = H(a, "sdkSecret"), signPublic = H(a, "signPublic");
            foreach (byte version in new byte[] { 0, 1, 3, 255 })
            {
                Assert.False(client.SetContentKey(SdkKeyWithVersion(version, secret, signPublic)));
            }
            Assert.Equal(vxk, SdkKeyWithVersion(2, secret, signPublic));
            // v1: "vxk_" + b64u(sk_sdk || SHA256("vaultix-vxk" || sk_sdk)[0:4])
            string v1 = "vxk_" + Zk1.B64uEncode(secret.Concat(SHA256.HashData(Encoding.ASCII.GetBytes("vaultix-vxk").Concat(secret).ToArray()).Take(4)).ToArray());
            Assert.Equal(52, v1.Length);
            Assert.False(client.SetContentKey(v1));
            Assert.Contains("96 characters", client.GetLastError());
            Assert.False(client.SetContentKey(vxk.Substring(0, 50) + " " + vxk.Substring(50)), "inner whitespace");
            Assert.False(client.SetContentKey("not a key"));
            Assert.False(client.SetContentKey(""));
            Assert.Equal(fingerprint, client.GetContentKeyFingerprint());

            // another valid key replaces it; ClearContentKey forgets it
            Assert.True(client.SetContentKey(S(App(1), "sdkKey")));
            Assert.Equal(S(App(1), "fingerprint"), client.GetContentKeyFingerprint());
            client.ClearContentKey();
            Assert.False(client.HasContentKey);
            Assert.Equal("", client.GetContentKeyFingerprint());
        }

        private static string SdkKeyWithVersion(byte version, byte[] secret, byte[] signPublic)
        {
            byte[] body = new[] { version }.Concat(secret).Concat(signPublic).ToArray();
            byte[] check = SHA256.HashData(Encoding.ASCII.GetBytes("vaultix-vxk").Concat(body).ToArray()).Take(4).ToArray();
            return "vxk_" + Zk1.B64uEncode(body.Concat(check).ToArray());
        }

        [VectorFact]
        public void ContentKey_ZeroedOnDispose()
        {
            var key = KeyOf(0);
            Assert.Contains(key.SdkSecret, b => b != 0);
            key.Dispose();
            Assert.All(key.SdkSecret, b => Assert.Equal(0, b));
            Assert.All(key.HashKey, b => Assert.Equal(0, b));
            Assert.All(key.SignPublic, b => Assert.Equal(0, b));
        }

        // ------------------------------------------------------------------
        // Seal
        // ------------------------------------------------------------------

        [VectorFact]
        public void Unseal_Vectors()
        {
            byte[] secret = H(App(0), "sdkSecret");
            byte[] otherSecret = H(App(1), "sdkSecret");
            foreach (JsonElement c in V.GetProperty("seal").EnumerateArray())
            {
                string what = $"{S(c, "kind")} {S(c, "name")}";
                byte[] context = Zk1.SealContext(S(c, "kind"), S(c, "name"), S(c, "productId"));
                Assert.Equal(S(c, "context"), Hex.Of(context));
                byte[]? payload = Zk1.Unseal(secret, H(c, "sealed"), context);
                Assert.True(payload != null, "unseal " + what);
                Assert.Equal(S(c, "payload"), Hex.Of(payload));
                Assert.Null(Zk1.Unseal(otherSecret, H(c, "sealed"), context));
                Assert.Null(Zk1.Unseal(secret, H(c, "sealed"), Zk1.SealContext(S(c, "kind"), S(c, "name") + "x", S(c, "productId"))));
                byte[] tampered = H(c, "sealed");
                tampered[^1] ^= 1;
                Assert.Null(Zk1.Unseal(secret, tampered, context));
            }
            Assert.Empty(Zk1.SealContext("grant", "x"));
        }

        // ------------------------------------------------------------------
        // Stream
        // ------------------------------------------------------------------

        private static (bool Ok, byte[] Data, string Error) Decrypt(byte[] key, byte[] blob, string magic, int piece)
        {
            var received = new MemoryStream();
            using var decryptor = new Zk1.StreamDecryptor(key, magic, data =>
            {
                received.Write(data);
                return true;
            });
            bool ok = true;
            int step = piece <= 0 ? Math.Max(1, blob.Length) : piece;
            for (int offset = 0; ok && offset < blob.Length; offset += step)
            {
                ok = decryptor.Update(blob.AsSpan(offset, Math.Min(step, blob.Length - offset)));
            }
            ok = ok && decryptor.Finish();
            return (ok, received.ToArray(), decryptor.Error);
        }

        [VectorFact]
        public void Stream_Vectors()
        {
            foreach (JsonElement c in V.GetProperty("stream").EnumerateArray())
            {
                int length = c.GetProperty("plainLength").GetInt32();
                string what = $"stream of {length} bytes";
                byte[] key = H(c, "key");
                byte[] data = Writer.Pattern(length, c.GetProperty("seed").GetInt32());
                Assert.Equal(S(c, "plainSha256"), Hex.Sha256(data));
                byte[] blob = Writer.StreamEncrypt(key, data, S(c, "magic"));
                Assert.Equal(c.GetProperty("cipherLength").GetInt32(), blob.Length);
                Assert.Equal(S(c, "cipherSha256"), Hex.Sha256(blob));
                if (c.TryGetProperty("cipher", out JsonElement cipher)) Assert.Equal(cipher.GetString(), Hex.Of(blob));

                foreach (int piece in new[] { 0, 7, 65536, 1048576 + 16 })
                {
                    var result = Decrypt(key, blob, "VXZ1", piece);
                    Assert.True(result.Ok, $"{what} (pieces of {piece}): {result.Error}");
                    Assert.True(data.AsSpan().SequenceEqual(result.Data), what + " plaintext");
                }
                if (length <= 64) Assert.True(Decrypt(key, blob, "VXZ1", 1).Ok, what + " byte by byte");

                // truncated, flipped, wrong key, wrong magic, extra data: all fail
                Assert.False(Decrypt(key, blob.AsSpan(0, blob.Length - 1).ToArray(), "VXZ1", 0).Ok, what + " truncated");
                byte[] flipped = (byte[])blob.Clone();
                flipped[^1] ^= 0x80;
                Assert.False(Decrypt(key, flipped, "VXZ1", 0).Ok, what + " flipped tag");
                flipped = (byte[])blob.Clone();
                flipped[9] ^= 1;
                Assert.False(Decrypt(key, flipped, "VXZ1", 0).Ok, what + " flipped first byte");
                flipped = (byte[])blob.Clone();
                flipped[5] ^= 1;
                Assert.False(Decrypt(key, flipped, "VXZ1", 0).Ok, what + " other chunk size");
                Assert.False(Decrypt(H(V.GetProperty("stream")[0], "key").Reverse().ToArray(), blob, "VXZ1", 0).Ok, what + " wrong key");
                Assert.False(Decrypt(key, blob, "VXD1", 0).Ok, what + " wrong magic");
                Assert.False(Decrypt(key, blob.Concat(new byte[] { 0 }).ToArray(), "VXZ1", 0).Ok, what + " trailing byte");
                if (length > Writer.ChunkSize)
                {
                    // Cut off at a chunk boundary: the last full chunk is not flagged final.
                    var cut = Decrypt(key, blob.AsSpan(0, 9 + Writer.ChunkSize + 16).ToArray(), "VXZ1", 0);
                    Assert.False(cut.Ok, what + " cut at a chunk boundary");
                    Assert.Contains("failed authentication", cut.Error);
                }
            }
            Assert.False(Decrypt(new byte[32], Encoding.ASCII.GetBytes("VXZ1"), "VXZ1", 0).Ok, "header only");
        }

        // ------------------------------------------------------------------
        // Signed content
        // ------------------------------------------------------------------

        [VectorFact]
        public void SignatureBlocks_VerifyAndTamperingFails()
        {
            using Zk1.ContentKey key = KeyOf(0);
            byte[] otherSignPublic = H(App(1), "signPublic");
            foreach (JsonElement c in V.GetProperty("files").EnumerateArray())
            {
                string kind = S(c, "kind"), name = S(c, "name"), product = S(c, "productId");
                ulong size = (ulong)c.GetProperty("plainLength").GetInt64();
                ulong signedAt = c.GetProperty("signedAt").GetUInt64();
                byte[] keyedHash = Zk1.HmacSha256(key.HashKey, H(c, "plainSha256"));
                Assert.Equal(S(c, "keyedHash"), Hex.Of(keyedHash));
                Assert.Equal(S(c, "uploadMessage"), Hex.Of(Zk1.UploadMessage(AppId, kind, product, name, keyedHash, size, signedAt)));
                byte[] signature = H(c, "signature");
                Assert.Equal(signature, Zk1.B64uDecode(S(c, "signatureB64u"), 1024));

                Func<ulong, byte[]> message = at => Zk1.UploadMessage(AppId, kind, product, name, keyedHash, size, at);
                Zk1.SignatureBlock? block = Zk1.VerifySignatureBlock(signature, AppId, key.SignPublic, message, out string error);
                Assert.True(block != null, $"{name}: {error}");
                Assert.Equal(S(c, "uploader"), block!.UserId);
                Assert.Equal(signedAt, block.SignedAtMs);

                // another app's signing key: the signer is not approved
                Assert.Null(Zk1.VerifySignatureBlock(signature, AppId, otherSignPublic, message, out error));
                Assert.Equal("the signer is not approved by the app owner", error);
                // another app id, name, size or scope: invalid
                Assert.Null(Zk1.VerifySignatureBlock(signature, "app-2", key.SignPublic, message, out error));
                Assert.Null(Zk1.VerifySignatureBlock(signature, AppId, key.SignPublic,
                    at => Zk1.UploadMessage(AppId, kind, product, name + ".bak", keyedHash, size, at), out error));
                Assert.Equal("invalid signature", error);
                Assert.Null(Zk1.VerifySignatureBlock(signature, AppId, key.SignPublic,
                    at => Zk1.UploadMessage(AppId, kind, product, name, keyedHash, size + 1, at), out error));
                Assert.Null(Zk1.VerifySignatureBlock(signature, AppId, key.SignPublic,
                    at => Zk1.UploadMessage(AppId, kind, product + "x", name, keyedHash, size, at), out error));
                // every single flipped byte of the block fails
                for (int i = 0; i < signature.Length; ++i)
                {
                    byte[] tampered = (byte[])signature.Clone();
                    tampered[i] ^= 0x01;
                    Assert.True(Zk1.VerifySignatureBlock(tampered, AppId, key.SignPublic, message, out _) == null,
                        $"{name}: flipped byte {i} must fail");
                }
                Assert.Null(Zk1.VerifySignatureBlock(signature.AsSpan(0, signature.Length - 1), AppId, key.SignPublic, message, out error));
                Assert.Equal("invalid signature block", error);
            }
            // NUL in a text field: no message at all
            Assert.Empty(Zk1.UploadMessage("a\0b", "file", "", "n", new byte[32], 1, 2));
            Assert.Empty(Zk1.UploadMessage("a", "var", "", "n", new byte[32], 1, 2));
            Assert.Empty(Zk1.MemberMessage("a", "u\0", new byte[32], new byte[32], 1));
        }

        [VectorFact]
        public void Certs_MemberMessages()
        {
            byte[] signPublic = H(App(0), "signPublic");
            foreach (JsonElement c in V.GetProperty("certs").EnumerateArray())
            {
                byte[] message = Zk1.MemberMessage(S(c, "appId"), S(c, "userId"), H(c, "encPublic"), H(c, "signPublic"),
                    c.GetProperty("issuedAt").GetUInt64());
                Assert.Equal(S(c, "message"), Hex.Of(message));
                Assert.True(Zk1.Ed25519Verify(signPublic, message, H(c, "signature")));
                Assert.False(Zk1.Ed25519Verify(H(App(1), "signPublic"), message, H(c, "signature")));
            }
        }

        // ------------------------------------------------------------------
        // Files: the full SDK path (delivery, unseal, signature, stream, checks)
        // ------------------------------------------------------------------

        [VectorFact]
        public void Files_OpenThroughDelivery()
        {
            JsonElement[] files = V.GetProperty("files").EnumerateArray().ToArray();
            for (int i = 0; i < files.Length; ++i)
            {
                JsonElement c = files[i];
                string kind = S(c, "kind"), name = S(c, "name"), product = S(c, "productId");
                int size = c.GetProperty("plainLength").GetInt32();
                byte[] data = Writer.Pattern(size, c.GetProperty("seed").GetInt32());
                Assert.Equal(S(c, "plainSha256"), Hex.Sha256(data));
                byte[] blob = Writer.StreamEncrypt(H(c, "fileKey"), data, "VXZ1");
                Assert.Equal(S(c, "cipherSha256"), Hex.Sha256(blob));
                if (c.TryGetProperty("cipher", out JsonElement cipher)) Assert.Equal(cipher.GetString(), Hex.Of(blob));
                byte[] sealedKey = H(c, "sealed");
                Assert.Equal(Zk1.SealedFileKeyBytes, sealedKey.Length);
                byte[] payload = Writer.FilePrefix(sealedKey, H(c, "signature")).Concat(blob).ToArray();

                byte[] clientSecret = SHA256.HashData(Encoding.ASCII.GetBytes("client-" + i));
                byte[] serverSecret = SHA256.HashData(Encoding.ASCII.GetBytes("server-" + i));
                var (header, body) = Writer.Delivery(serverSecret, Writer.X25519Public(clientSecret), kind, "obj-" + i, payload);

                foreach (int piece in new[] { 0, 1000, 65536 })
                {
                    Opened opened = Open.Delivery(clientSecret, header, body, kind, KeyOf(0), AppId, name, product, piece);
                    Assert.True(opened.Ok, $"{name} (pieces of {piece}): {opened.Error}");
                    Assert.True(data.AsSpan().SequenceEqual(opened.Data), name + " plaintext");
                    Assert.Equal(product, opened.Scope);
                    Assert.Equal(c.GetProperty("signedAt").GetUInt64(), opened.SignedAt);
                }

                // A product download of a general file opens via the general scope;
                // a product file asked for under another product does not open.
                Opened other = Open.Delivery(clientSecret, header, body, kind, KeyOf(0), AppId, name, product.Length == 0 ? "prod-x" : "prod-x");
                if (product.Length == 0)
                {
                    Assert.True(other.Ok, name + " via the general scope: " + other.Error);
                    Assert.Equal("", other.Scope);
                }
                else
                {
                    Assert.False(other.Ok);
                    Assert.Contains("cannot open the sealed file key", other.Error);
                }

                // wrong content key, wrong name, wrong app id, wrong client secret, wrong kind
                Opened wrongKey = Open.Delivery(clientSecret, header, body, kind, KeyOf(1), AppId, name, product);
                Assert.False(wrongKey.Ok);
                Assert.Contains("cannot open the sealed file key", wrongKey.Error);
                Assert.Empty(wrongKey.Data);
                Assert.False(Open.Delivery(clientSecret, header, body, kind, KeyOf(0), AppId, name + "2", product).Ok);
                Opened wrongApp = Open.Delivery(clientSecret, header, body, kind, KeyOf(0), "app-2", name, product);
                Assert.False(wrongApp.Ok);
                Assert.Contains("signature check failed", wrongApp.Error);
                Assert.Empty(wrongApp.Data);
                byte[] otherClient = SHA256.HashData(Encoding.ASCII.GetBytes("someone else"));
                Opened wrongClient = Open.Delivery(otherClient, header, body, kind, KeyOf(0), AppId, name, product);
                Assert.False(wrongClient.Ok);
                Assert.Contains("chunk 0 failed authentication", wrongClient.Error);
                Assert.False(Open.Delivery(clientSecret, header, body, kind == "file" ? "folder" : "file", KeyOf(0), AppId, name, product).Ok);

                // a forged signature block (flipped byte inside the delivery): nothing is released
                byte[] forged = Writer.FilePrefix(sealedKey, Flip(H(c, "signature"), 30)).Concat(blob).ToArray();
                var (forgedHeader, forgedBody) = Writer.Delivery(serverSecret, Writer.X25519Public(clientSecret), kind, "obj-" + i, forged);
                Opened forgedOpen = Open.Delivery(clientSecret, forgedHeader, forgedBody, kind, KeyOf(0), AppId, name, product);
                Assert.False(forgedOpen.Ok);
                Assert.Empty(forgedOpen.Data);

                // truncated delivery
                Assert.False(Open.Delivery(clientSecret, header, body.AsSpan(0, body.Length - 1).ToArray(), kind, KeyOf(0), AppId, name, product).Ok);
                // a stored stream that does not match the sealed size/hash
                if (size > 0)
                {
                    byte[] changed = (byte[])data.Clone();
                    changed[0] ^= 1;
                    byte[] badPayload = Writer.FilePrefix(sealedKey, H(c, "signature"))
                        .Concat(Writer.StreamEncrypt(H(c, "fileKey"), changed, "VXZ1")).ToArray();
                    var (badHeader, badBody) = Writer.Delivery(serverSecret, Writer.X25519Public(clientSecret), kind, "obj-" + i, badPayload);
                    Opened bad = Open.Delivery(clientSecret, badHeader, badBody, kind, KeyOf(0), AppId, name, product);
                    Assert.False(bad.Ok);
                    Assert.Contains("does not match its sealed SHA-256", bad.Error);
                }
            }
        }

        private static byte[] Flip(byte[] data, int index)
        {
            byte[] copy = (byte[])data.Clone();
            copy[index] ^= 1;
            return copy;
        }

        // ------------------------------------------------------------------
        // Deliveries (layer 3) from the vector file
        // ------------------------------------------------------------------

        [VectorFact]
        public void Delivery_Vectors()
        {
            JsonElement fileVector = V.GetProperty("files")[0];
            foreach (JsonElement c in V.GetProperty("delivery").EnumerateArray())
            {
                string kind = S(c, "kind"), objectId = S(c, "objectId");
                byte[] clientSecret = H(c, "clientSecret");
                Assert.Equal(S(c, "clientPublicB64u"), Zk1.B64uEncode(Zk1.X25519Public(clientSecret)));
                Assert.True(Zk1.ParseDeliveryHeader(S(c, "header"), out byte[] serverPublic, out string parsedKind, out string parsedObject));
                Assert.Equal(kind, parsedKind);
                Assert.Equal(objectId, parsedObject);
                Assert.Equal(Hex.Of(Writer.X25519Public(H(c, "serverSecret"))), Hex.Of(serverPublic));

                byte[] payload = c.TryGetProperty("payload", out JsonElement p)
                    ? Hex.Bytes(p.GetString()!)
                    : Writer.Pattern(c.GetProperty("payloadPattern").GetProperty("length").GetInt32(),
                                     c.GetProperty("payloadPattern").GetProperty("seed").GetInt32());
                Assert.Equal(S(c, "payloadSha256"), Hex.Sha256(payload));
                var (header, body) = Writer.Delivery(H(c, "serverSecret"), Zk1.X25519Public(clientSecret), kind, objectId, payload);
                Assert.Equal(S(c, "header"), header);
                Assert.Equal(c.GetProperty("bodyLength").GetInt32(), body.Length);
                Assert.Equal(S(c, "bodySha256"), Hex.Sha256(body));
                if (c.TryGetProperty("body", out JsonElement b)) Assert.Equal(b.GetString(), Hex.Of(body));

                // the outer layer opens to the payload
                byte[]? key = Zk1.DeliveryKey(clientSecret, serverPublic, kind, objectId);
                Assert.NotNull(key);
                var outer = Decrypt(key!, body, "VXD1", 4096);
                Assert.True(outer.Ok, outer.Error);
                Assert.Equal(S(c, "payloadSha256"), Hex.Sha256(outer.Data));

                // a wrong client secret does not open it; neither does another object id
                byte[]? wrong = Zk1.DeliveryKey(H(V.GetProperty("delivery")[(kind == "file" ? 1 : 0)], "clientSecret"), serverPublic, kind, objectId);
                Assert.False(Decrypt(wrong!, body, "VXD1", 0).Ok);
                Assert.False(Decrypt(Zk1.DeliveryKey(clientSecret, serverPublic, kind, objectId + "x")!, body, "VXD1", 0).Ok);

                if (kind == "file")
                {
                    Opened opened = Open.Delivery(clientSecret, header, body, "file", KeyOf(0), AppId,
                        S(fileVector, "name"), S(fileVector, "productId"));
                    Assert.True(opened.Ok, opened.Error);
                    Assert.Equal(S(fileVector, "plainSha256"), Hex.Sha256(opened.Data));
                    Assert.Equal(fileVector.GetProperty("signedAt").GetUInt64(), opened.SignedAt);
                    Assert.False(Open.Delivery(H(V.GetProperty("delivery")[1], "clientSecret"), header, body, "file", KeyOf(0), AppId,
                        S(fileVector, "name"), S(fileVector, "productId")).Ok, "wrong client secret");
                }
                else if (kind == "vars")
                {
                    Opened opened = Open.Delivery(clientSecret, header, body, "vars");
                    Assert.True(opened.Ok, opened.Error);
                    Assert.True(Zk1.OpenVariables(Encoding.UTF8.GetBytes(opened.Vars), KeyOf(0), AppId, objectId,
                        out var variables, out string error), error);
                    Assert.Equal(2, variables.Count);
                    Assert.Equal(new KeyValuePair<string, string>("apiUrl", "https://example.com/v1?x=ä"), variables[0]);
                    Assert.Equal(new KeyValuePair<string, string>("legacy", "plain"), variables[1]);
                    Assert.False(Open.Delivery(clientSecret, header, body, "file", KeyOf(0), AppId, "x", "").Ok, "unexpected kind");
                }
            }
            Assert.False(Zk1.ParseDeliveryHeader("zk1d.AAAA.file.x", out _, out _, out _), "short key");
            Assert.False(Zk1.ParseDeliveryHeader("zk1d." + new string('A', 43) + ".grant.x", out _, out _, out _), "kind");
            Assert.False(Zk1.ParseDeliveryHeader("zk1d." + new string('A', 43) + ".file.", out _, out _, out _), "empty id");
            Assert.False(Zk1.ParseDeliveryHeader("zk1d." + new string('A', 43) + ".file.a.b", out _, out _, out _), "dots");
            Assert.False(Zk1.ParseDeliveryHeader("enc_key_123", out _, out _, out _), "legacy header");
        }

        // ------------------------------------------------------------------
        // Variables
        // ------------------------------------------------------------------

        private static byte[] VarsJson(params object[] items) =>
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(items));

        [VectorFact]
        public void Variables_OpenAndVerify()
        {
            JsonElement[] vars = V.GetProperty("variables").EnumerateArray().ToArray();
            using Zk1.ContentKey key = KeyOf(0);
            foreach (JsonElement c in vars)
            {
                string product = S(c, "productId"), name = S(c, "name"), value = S(c, "value");
                byte[] keyedHash = Zk1.HmacSha256(key.HashKey, SHA256.HashData(Encoding.UTF8.GetBytes(value)));
                Assert.Equal(S(c, "keyedHash"), Hex.Of(keyedHash));
                Assert.Equal(S(c, "message"), Hex.Of(Zk1.VariableMessage(AppId, product, name, keyedHash, c.GetProperty("signedAt").GetUInt64())));
                byte[] json = VarsJson(new { id = "v", name, enc = "zk1", value = S(c, "sealedB64u"), sig = S(c, "signatureB64u") });
                Assert.True(Zk1.OpenVariables(json, key, AppId, product, out var opened, out string error), error);
                Assert.Single(opened);
                Assert.Equal(value, opened[0].Value);

                // another product, app, key or name: nothing at all
                Assert.False(Zk1.OpenVariables(json, key, AppId, "prod-x", out opened, out error));
                Assert.Empty(opened);
                Assert.Contains("cannot open variable", error);
                Assert.False(Zk1.OpenVariables(json, key, "app-2", product, out opened, out error));
                Assert.Contains("signature check failed", error);
                using (Zk1.ContentKey other = KeyOf(1))
                {
                    Assert.False(Zk1.OpenVariables(json, other, AppId, product, out opened, out error));
                }
                Assert.False(Zk1.OpenVariables(VarsJson(new { name = name + "x", enc = "zk1", value = S(c, "sealedB64u"), sig = S(c, "signatureB64u") }),
                    key, AppId, product, out opened, out error));
                // a tampered or missing signature block
                string tamperedSig = Zk1.B64uEncode(Flip(H(c, "signature"), 40));
                Assert.False(Zk1.OpenVariables(VarsJson(new { name, enc = "zk1", value = S(c, "sealedB64u"), sig = tamperedSig }),
                    key, AppId, product, out opened, out error));
                Assert.Contains("signature check failed", error);
                Assert.False(Zk1.OpenVariables(VarsJson(new { name, enc = "zk1", value = S(c, "sealedB64u"), sig = (string?)null }),
                    key, AppId, product, out opened, out error));
                Assert.Contains("no valid signature block", error);
                // no content key
                Assert.False(Zk1.OpenVariables(json, null, AppId, product, out opened, out error));
                Assert.Equal(Zk1.NeedContentKey, error);
            }

            // one bad value among good ones: no values at all
            JsonElement a = vars[0], b = vars[1];
            byte[] mixed = VarsJson(
                new { name = S(a, "name"), enc = "zk1", value = S(a, "sealedB64u"), sig = S(a, "signatureB64u") },
                new { name = "plain", enc = (string?)null, value = "text", sig = (string?)null },
                new { name = S(b, "name"), enc = "zk1", value = S(b, "sealedB64u"), sig = S(a, "signatureB64u") });
            Assert.False(Zk1.OpenVariables(mixed, key, AppId, "prod-1234", out var none, out _));
            Assert.Empty(none);

            // plaintext values pass through without a key; malformed payloads fail
            Assert.True(Zk1.OpenVariables(VarsJson(new { name = "a", enc = (string?)null, value = "1" }, new { name = "b", value = (string?)null }),
                null, AppId, "p", out var plain, out string plainError), plainError);
            Assert.Equal(new[] { "a=1", "b=" }, plain.Select(kv => kv.Key + "=" + kv.Value));
            Assert.True(Zk1.OpenVariables(Encoding.UTF8.GetBytes("[]"), null, AppId, "p", out plain, out _));
            Assert.Empty(plain);
            foreach (string bad in new[] { "", "{}", "[1]", "[{\"value\":\"x\"}]", "[{\"name\":1}]", "[{\"name\":\"a\",\"enc\":\"zk2\"}]",
                                           "[{\"name\":\"a\",\"name\":\"b\"}]", "[] x", "[{\"name\":\"a\",\"value\":5}]" })
            {
                Assert.False(Zk1.OpenVariables(Encoding.UTF8.GetBytes(bad), key, AppId, "p", out plain, out string badError), bad);
                Assert.NotEqual("", badError);
            }
            Assert.False(Zk1.OpenVariables(new byte[] { (byte)'[', 0xC3, (byte)']' }, key, AppId, "p", out _, out _), "invalid UTF-8");
        }
    }
}
