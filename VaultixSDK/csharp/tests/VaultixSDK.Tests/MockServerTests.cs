using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;

namespace Vaultix.SDK.Tests
{
    /// <summary>
    /// The client's HTTP rules against a small local server that signs its
    /// responses like Vaultix (with a throwaway key trusted through the testing
    /// hook) and serves file vector 0 of zk1.json as an end-to-end encrypted
    /// delivery: what the shared test backend cannot be made to do.
    /// </summary>
    public sealed class MockServerTests : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly byte[] _seed = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _publicKey = new byte[32];
        private readonly string _baseUrl;
        private readonly List<string> _verifyHashBodies = new();
        private bool _tamperDelivery;

        public MockServerTests()
        {
            Ed25519.GeneratePublicKey(_seed, 0, _publicKey, 0);
            int port;
            using (var probe = new TcpListener(IPAddress.Loopback, 0))
            {
                probe.Start();
                port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();
            }
            _baseUrl = $"http://127.0.0.1:{port}/api";
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            _listener.Start();
            _ = Task.Run(ServeAsync);
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch (ObjectDisposedException) { }
            _listener.Close();
        }

        private string KeyId => ResponseSigning.KeyIdFor(_publicKey);
        private static JsonElement FileVector => Vectors.Root.GetProperty("files")[0];

        private async Task ServeAsync()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync();
                }
                catch (Exception)
                {
                    return;
                }
                try
                {
                    Handle(context);
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 500;
                    context.Response.Close();
                }
            }
        }

        private void Handle(HttpListenerContext context)
        {
            HttpListenerRequest request = context.Request;
            string path = request.Url!.AbsolutePath;
            string body = new StreamReader(request.InputStream, Encoding.UTF8).ReadToEnd();
            switch (path)
            {
                case "/api/app_auth/login_key":
                    Reply(context, 200, "application/json", Encoding.UTF8.GetBytes(
                        "{\"access_token\":\"token-1\",\"appId\":\"app-1\",\"appUserId\":\"user-1\",\"subscriptions\":[\"prod-1234\"]," +
                        "\"expiresAt\":\"2030-01-01T00:00:00\",\"sessionId\":\"session-1\"}"));
                    return;
                case "/api/files/download/loader.exe":
                {
                    JsonElement f = FileVector;
                    byte[] payload = Writer.FilePrefix(Hex.Bytes(f.GetProperty("sealed").GetString()!),
                                                       Hex.Bytes(f.GetProperty("signature").GetString()!))
                        .Concat(Hex.Bytes(f.GetProperty("cipher").GetString()!)).ToArray();
                    byte[] clientPublic = Zk1.B64uDecode(request.Headers["X-Vaultix-Eph"], 32)!;
                    var (header, delivery) = Writer.Delivery(RandomNumberGenerator.GetBytes(32), clientPublic, "file", "file-id-1", payload);
                    if (_tamperDelivery) delivery[delivery.Length - 20] ^= 1;
                    Reply(context, 200, "application/octet-stream", delivery, header, streamed: true);
                    return;
                }
                case "/api/files/download/old-sdk.bin":
                    Reply(context, 409, "application/json", Encoding.UTF8.GetBytes(
                        "{\"detail\":\"This app uses end-to-end encryption.\",\"code\":\"e2ee_sdk_update_required\"}"));
                    return;
                case "/api/files/verify-hash":
                    lock (_verifyHashBodies) _verifyHashBodies.Add(body);
                    bool plain = JsonDocument.Parse(body).RootElement.TryGetProperty("hash", out _);
                    Reply(context, 200, "application/json", Encoding.UTF8.GetBytes(plain
                        ? "{\"valid\":true}"
                        : "{\"valid\":false,\"code\":\"plain_hash_required\"}"));
                    return;
                case "/api/api/products/moved/status":
                    context.Response.StatusCode = 302;
                    context.Response.RedirectLocation = "/api/products";
                    context.Response.Close();
                    return;
                case "/api/products":
                    Reply(context, 200, "application/json", Encoding.UTF8.GetBytes("[]"));
                    return;
                case "/api/me":
                    Reply(context, 200, "application/json", Encoding.UTF8.GetBytes("{\"username\":\"x\"}"), sign: false);
                    return;
                default:
                    Reply(context, 404, "application/json", Encoding.UTF8.GetBytes("{\"detail\":\"Not Found\"}"));
                    return;
            }
        }

        private void Reply(HttpListenerContext context, int status, string contentType, byte[] body,
                           string encryptionKey = "", bool streamed = false, bool sign = true)
        {
            HttpListenerResponse response = context.Response;
            response.StatusCode = status;
            response.ContentType = contentType;
            if (encryptionKey.Length > 0) response.Headers["X-Encryption-Key"] = encryptionKey;
            string? nonce = context.Request.Headers["X-Vaultix-Nonce"];
            if (sign && nonce != null)
            {
                long signedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                string canonical = ResponseSigning.Canonical(KeyId, nonce, signedAt.ToString(), context.Request.HttpMethod,
                    context.Request.RawUrl!, status.ToString(), streamed ? "zk1-stream" : ResponseSigning.Sha256Hex(body),
                    encryptionKey, "", contentType)!;
                byte[] message = Encoding.UTF8.GetBytes(canonical);
                byte[] signature = new byte[64];
                Ed25519.Sign(_seed, 0, message, 0, message.Length, signature, 0);
                response.Headers["X-Vaultix-Signature"] = Zk1.B64uEncode(signature);
                response.Headers["X-Vaultix-Key-Id"] = KeyId;
                response.Headers["X-Vaultix-Signed-At"] = signedAt.ToString();
            }
            response.ContentLength64 = body.Length;
            response.OutputStream.Write(body);
            response.Close();
        }

        private async Task<VaultixClient> SignedInClient(bool contentKey = true)
        {
            var client = new VaultixClient(_baseUrl);
            Assert.True(client.TrustResponseKeyForTestingOnly(KeyId, Hex.Of(_publicKey)));
            client.SetApiKey("ap_test");
            if (contentKey) Assert.True(client.SetContentKey(Vectors.Root.GetProperty("appKeys")[0].GetProperty("sdkKey").GetString()!));
            Assert.True(await client.AuthenticateWithKeyAsync("KEY-1"), client.GetLastError());
            Assert.Equal("app-1", client.GetCurrentSession().AppId);
            return client;
        }

        [VectorFact]
        public async Task VerifiedZk1File_PlainHashIsNeverSent()
        {
            using VaultixClient client = await SignedInClient();
            byte[]? data = await client.DownloadFileToMemoryAsync("prod-1234", "loader.exe");
            Assert.True(data != null, client.GetLastError());
            Assert.Equal(FileVector.GetProperty("plainSha256").GetString(), Hex.Sha256(data));
            Assert.Equal(FileVector.GetProperty("signedAt").GetInt64(), client.GetLastSignedAt());

            string path = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(path, data!);
                // The server asks for the plain hash of a file received as a verified zk1 delivery: refused.
                Assert.False(await client.IsValidFileHashAsync("prod-1234", "loader.exe", path));
                Assert.Equal("verify-hash: the server asked for the plain hash of an end-to-end encrypted file", client.GetLastError());
                Assert.Single(_verifyHashBodies);
                Assert.Contains("\"keyedHash\":\"", _verifyHashBodies[0]);
                Assert.DoesNotContain("\"hash\"", _verifyHashBodies[0]);
                string keyed = Hex.Of(Zk1.HmacSha256(Zk1.ContentKeyFromSdkKey(
                    Vectors.Root.GetProperty("appKeys")[0].GetProperty("sdkKey").GetString()!)!.HashKey, SHA256.HashData(data!)));
                Assert.Contains(keyed, _verifyHashBodies[0]);

                // Another file: keyed hash first, then once more with the plain SHA-256.
                Assert.True(await client.IsValidFileHashAsync("prod-1234", "other.bin", path), client.GetLastError());
                Assert.Equal(3, _verifyHashBodies.Count);
                Assert.Contains("\"hash\":\"" + Hex.Sha256(data!) + "\"", _verifyHashBodies[2]);

                // ClearContentKey forgets which files were verified; without a key only the plain hash is sent.
                client.ClearContentKey();
                Assert.True(await client.IsValidFileHashAsync("prod-1234", "loader.exe", path));
                Assert.Equal(4, _verifyHashBodies.Count);
                Assert.DoesNotContain("keyedHash", _verifyHashBodies[3]);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [VectorFact]
        public async Task TamperedDelivery_NothingSaved()
        {
            using VaultixClient client = await SignedInClient();
            _tamperDelivery = true;
            string dir = Path.Combine(Path.GetTempPath(), "vaultix-mock-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string target = Path.Combine(dir, "loader.exe");
                Assert.False(await client.DownloadFileAsync("prod-1234", "loader.exe", target));
                Assert.StartsWith("End-to-end encrypted download failed: chunk 0 failed authentication", client.GetLastError());
                Assert.Empty(Directory.GetFiles(dir));
                Assert.Null(await client.DownloadFileToMemoryAsync("prod-1234", "loader.exe"));
                Assert.Equal(0, client.GetLastSignedAt());
            }
            finally
            {
                Directory.Delete(dir, true);
            }
        }

        [VectorFact]
        public async Task Http_RulesOfTheClient()
        {
            using VaultixClient client = await SignedInClient(contentKey: false);
            // the server never received the one-time key (e.g. stripped by a proxy)
            Assert.Null(await client.DownloadFileToMemoryAsync("prod-1234", "old-sdk.bin"));
            Assert.StartsWith(Zk1.NeedContentKey, client.GetLastError());
            Assert.Contains("e2ee_sdk_update_required", client.GetLastError());
            Assert.True(client.SetContentKey(Vectors.Root.GetProperty("appKeys")[0].GetProperty("sdkKey").GetString()!));
            Assert.Null(await client.DownloadFileToMemoryAsync("prod-1234", "old-sdk.bin"));
            Assert.Contains("did not receive the one-time request key", client.GetLastError());

            // a zk1 delivery without the content key
            client.ClearContentKey();
            Assert.Null(await client.DownloadFileToMemoryAsync("prod-1234", "loader.exe"));
            Assert.Equal(Zk1.NeedContentKey, client.GetLastError());

            // an unsigned response, and a redirected one, are refused
            Assert.Null(await client.GetAccountInfoAsync());
            Assert.Equal("Server response could not be verified (HTTP 200): the response is not signed", client.GetLastError());
            client.SetRequireSignedResponses(false);
            Assert.NotNull(await client.GetAccountInfoAsync());
            client.SetRequireSignedResponses(true);
            Assert.Empty(await client.GetUserProductsAsync());
            Assert.Equal("", client.GetLastError());
            Assert.False((await client.GetProductStatusAsync("moved")).HasStatus);
            Assert.Equal("Server response could not be verified (HTTP 200): the request was redirected", client.GetLastError());

            // HTTP errors keep the server's message
            Assert.Null(await client.GetFileInfoAsync("prod-1234", "missing.bin"));
            Assert.StartsWith("HTTP Error 404", client.GetLastError());
        }
    }
}
