using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;

namespace Vaultix.SDK.Tests
{
    /// <summary>
    /// vaultix-resp-v1: the golden vectors of backend/tests/response_signing_golden.json
    /// (TEST KEY ONLY: its seed is public) and the client's verification rules.
    /// </summary>
    public class ResponseSigningTests
    {
        private const string GoldenPublicKeyHex = "3446279cd5e1d6e691c3e35db837c803c6272056951e15c280e531bd167d26a8";
        private const string GoldenKeyId = "vx-sig-93a08c6579dcf5bd";

        private static readonly (string Nonce, string SignedAt, string Method, string PathAndQuery, string Status,
                                 string BodyHex, string EncryptionKey, string EncryptionIV, string ContentType,
                                 string BodySha256, string Signature)[] Golden =
        {
            ("3f9a1c0e5b7d2468ace013579bdf2468", "1790000000", "GET",
             "/api/files/download/Tools%20Valuables.json?productId=74d8b072-46fe-4c29-a53d-3f2aabfff895", "200",
             "676f6c64656e20626f647900ff0a", "enc_key_golden_0123", "iv_golden_4567", "application/octet-stream",
             "36f190070daa04fa3aa09be9810680c694ba0a3e890a9b85d89aa5508041e2e5",
             "G9b5q6DWTEGobUM4ftkx1kMqj3usucWwsIg8JwtJUbCvv6WJzX_XwAgc3_pI4h0oWd2qbI-GAgWMMDR2QWRxAQ"),
            ("Zm9vYmFyX2Jhei1xdXV4LTEyMzQ1Ng", "1790000123", "POST", "/api/app_auth/login_key", "401",
             "7b2264657461696c223a22496e76616c6964206b6579227d", "", "", "application/json",
             "53c4c95ff90d3fb42ad4f6e9f732a95d1100c6682367ee3674ae74f98badb28d",
             "OZNc9qnVt_KQLcJ7RX8nJoKrhriV35RJA5SCZgbiIbE8MtvRRbGC2kp4OiB4tVqexQjomnalqZEfGPxDioGcDA"),
        };

        [Fact]
        public void Golden_CanonicalAndSignature()
        {
            byte[] publicKey = Hex.Bytes(GoldenPublicKeyHex);
            Assert.Equal(GoldenKeyId, ResponseSigning.KeyIdFor(publicKey));
            foreach (var g in Golden)
            {
                Assert.Equal(g.BodySha256, ResponseSigning.Sha256Hex(Hex.Bytes(g.BodyHex)));
                string? canonical = ResponseSigning.Canonical(GoldenKeyId, g.Nonce, g.SignedAt, g.Method, g.PathAndQuery,
                    g.Status, g.BodySha256, g.EncryptionKey, g.EncryptionIV, g.ContentType);
                Assert.Equal(string.Join("\n", "vaultix-resp-v1", GoldenKeyId, g.Nonce, g.SignedAt, g.Method, g.PathAndQuery,
                    g.Status, g.BodySha256, g.EncryptionKey, g.EncryptionIV, g.ContentType), canonical);
                Assert.True(ResponseSigning.VerifyEd25519(publicKey, canonical!, g.Signature));
                Assert.False(ResponseSigning.VerifyEd25519(publicKey, canonical! + " ", g.Signature));
                Assert.False(ResponseSigning.VerifyEd25519(publicKey, canonical!, g.Signature.Substring(0, 10) + (g.Signature[10] == 'A' ? 'B' : 'A') + g.Signature.Substring(11)));
            }
            Assert.Null(ResponseSigning.Canonical(GoldenKeyId, "n", "1", "GET", "/x\n", "200", "h", "", "", ""));
        }

        [Fact]
        public void PathAndQuery_AsSent()
        {
            Assert.Equal("/api/files/download/a%20b.bin?productId=p1",
                ResponseSigning.PathAndQuery(new Uri("http://127.0.0.1:5098/api/files/download/a%20b.bin?productId=p1")));
            Assert.Equal("/api/products", ResponseSigning.PathAndQuery(new Uri("https://vaultix.cc/api/products")));
            Assert.Equal(48, ResponseSigning.GenerateNonce().Length);
            Assert.NotEqual(ResponseSigning.GenerateNonce(), ResponseSigning.GenerateNonce());
        }

        [Fact]
        public void ProductionKey_IsTheOneOfTheCppSdk()
        {
            var key = Assert.Single(ResponseSigning.TrustedResponseKeys);
            Assert.Equal("vx-sig-22545e6918734982", key.KeyId);
            Assert.Equal("c21b9ba40714e61eaaf8529941400264996decd9fb8480121d3e4c7533cf2d8c", key.PublicKeyHex);
            Assert.Equal(key.KeyId, ResponseSigning.KeyIdFor(Hex.Bytes(key.PublicKeyHex)));
        }

        // A throwaway signer for the client checks below.
        private sealed class Signer
        {
            public readonly byte[] Seed = RandomNumberGenerator.GetBytes(32);
            public readonly byte[] PublicKey = new byte[32];
            public Signer() => Ed25519.GeneratePublicKey(Seed, 0, PublicKey, 0);
            public string KeyId => ResponseSigning.KeyIdFor(PublicKey);
            public string PublicHex => Hex.Of(PublicKey);

            public Dictionary<string, string> Headers(string nonce, long signedAt, string method, string path, int status,
                                                      string bodyHash, string encryptionKey = "", string contentType = "application/json")
            {
                string canonical = ResponseSigning.Canonical(KeyId, nonce, signedAt.ToString(), method, path, status.ToString(),
                    bodyHash, encryptionKey, "", contentType)!;
                byte[] message = Encoding.UTF8.GetBytes(canonical);
                byte[] signature = new byte[64];
                Ed25519.Sign(Seed, 0, message, 0, message.Length, signature, 0);
                var headers = new Dictionary<string, string>
                {
                    ["x-vaultix-signature"] = Zk1.B64uEncode(signature),
                    ["x-vaultix-key-id"] = KeyId,
                    ["x-vaultix-signed-at"] = signedAt.ToString(),
                    ["content-type"] = contentType,
                };
                if (encryptionKey.Length > 0) headers["x-encryption-key"] = encryptionKey;
                return headers;
            }
        }

        [Fact]
        public void Client_VerifiesWithTheTestingKeyOnly()
        {
            var signer = new Signer();
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string nonce = ResponseSigning.GenerateNonce();
            string bodyHash = ResponseSigning.Sha256Hex(Encoding.UTF8.GetBytes("{}"));
            var headers = signer.Headers(nonce, now, "GET", "/api/products", 200, bodyHash);
            using var client = new VaultixClient("http://127.0.0.1:9/api");
            Assert.True(client.RequireSignedResponses);
            Assert.True(client.GetRequireSignedResponses());
            Assert.Equal(600, client.ResponseClockSkewTolerance);

            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, headers, nonce, out string reason));
            Assert.StartsWith("unknown signing key", reason);

            Assert.False(client.TrustResponseKeyForTestingOnly("vx-sig-0000000000000000", signer.PublicHex), "key id must match the key");
            Assert.False(client.TrustResponseKeyForTestingOnly(signer.KeyId, "zz"), "not hex");
            Assert.False(client.TrustResponseKeyForTestingOnly("vx-sig-" + Hex.Sha256(new byte[32]).Substring(0, 16), new string('0', 64)), "weak key");
            Assert.True(client.TrustResponseKeyForTestingOnly(signer.KeyId, signer.PublicHex));
            Assert.True(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, headers, nonce, out reason), reason);

            // every covered field matters
            Assert.False(client.VerifyResponseSignatureFields("POST", "/api/products", 200, bodyHash, headers, nonce, out reason));
            Assert.StartsWith("invalid signature", reason);
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products?x=1", 200, bodyHash, headers, nonce, out _));
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 201, bodyHash, headers, nonce, out _));
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, ResponseSigning.Sha256Hex(new byte[1]), headers, nonce, out _));
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, headers, ResponseSigning.GenerateNonce(), out _), "replay with another nonce");
            var changed = new Dictionary<string, string>(headers) { ["content-type"] = "text/html" };
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, changed, nonce, out _));
            changed = new Dictionary<string, string>(headers) { ["x-encryption-key"] = "enc_key_x" };
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, changed, nonce, out _));

            // unsigned, bad time, clock skew
            var unsigned = new Dictionary<string, string>(headers);
            unsigned.Remove("x-vaultix-signature");
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, unsigned, nonce, out reason));
            Assert.Equal("the response is not signed", reason);
            changed = new Dictionary<string, string>(headers) { ["x-vaultix-signed-at"] = "-1" };
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, changed, nonce, out reason));
            Assert.Equal("invalid signing time", reason);
            var old = signer.Headers(nonce, now - 3600, "GET", "/api/products", 200, bodyHash);
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, old, nonce, out reason));
            Assert.Contains("differs from this computer's clock", reason);
            client.SetResponseClockSkewTolerance(7200);
            Assert.True(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, old, nonce, out reason), reason);
            client.SetResponseClockSkewTolerance(0);
            Assert.Equal(600, client.ResponseClockSkewTolerance);

            // zk1 deliveries are signed with the literal "zk1-stream" as the body field
            string delivery = "zk1d." + new string('A', 43) + ".file.obj1";
            var streamed = signer.Headers(nonce, now, "GET", "/api/files/download/a?productId=p", 200, "zk1-stream", delivery, "application/octet-stream");
            Assert.True(client.VerifyResponseSignatureFields("GET", "/api/files/download/a?productId=p", 200, "zk1-stream", streamed, nonce, out reason), reason);
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/files/download/a?productId=p", 200, ResponseSigning.Sha256Hex(Array.Empty<byte>()), streamed, nonce, out _));

            client.ClearTestingResponseKeys();
            Assert.False(client.VerifyResponseSignatureFields("GET", "/api/products", 200, bodyHash, headers, nonce, out reason));
            Assert.StartsWith("unknown signing key", reason);
        }

        [Fact]
        public async Task Client_WithoutSession_FailsClearly()
        {
            using var client = new VaultixClient("http://127.0.0.1:9/api");
            Assert.Null(await client.DownloadFileToMemoryAsync("p", "f"));
            Assert.Equal("No valid session", client.GetLastError());
            Assert.False(await client.AuthenticateWithKeyAsync("KEY"));
            Assert.Equal("API key not set", client.GetLastError());
            Assert.Empty(await client.GetProductVariablesAsync("p"));
        }
    }
}
