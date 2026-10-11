using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using Xunit.Abstractions;

namespace Vaultix.SDK.Tests
{
    /// <summary>
    /// The fixture of a running Vaultix test backend (JSON file named by
    /// VAULTIX_SDK_FIXTURE): base URL, the test backend's response signing key,
    /// an app with end-to-end encryption and one without. Read-only use: log
    /// in, download, verify hashes.
    /// </summary>
    public sealed class BackendFixture
    {
        public readonly JsonElement Root;
        public BackendFixture()
        {
            string? path = Environment.GetEnvironmentVariable("VAULTIX_SDK_FIXTURE");
            Root = path != null && File.Exists(path)
                ? JsonDocument.Parse(File.ReadAllBytes(path)).RootElement
                : default;
        }

        public string BaseUrl => Root.GetProperty("baseUrl").GetString()!;
        public string KeyId => Root.GetProperty("testResponseKey").GetProperty("keyId").GetString()!;
        public string KeyHex => Root.GetProperty("testResponseKey").GetProperty("publicKeyHex").GetString()!;
        public JsonElement E2ee => Root.GetProperty("e2ee");
        public JsonElement Legacy => Root.GetProperty("legacy");
        public static string S(JsonElement e, params string[] path)
        {
            foreach (string name in path) e = e.GetProperty(name);
            return e.GetString()!;
        }
    }

    /// <summary>Skipped unless VAULTIX_SDK_FIXTURE names an existing fixture file.</summary>
    public sealed class IntegrationFactAttribute : FactAttribute
    {
        public IntegrationFactAttribute()
        {
            string? path = Environment.GetEnvironmentVariable("VAULTIX_SDK_FIXTURE");
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) Skip = "set VAULTIX_SDK_FIXTURE to run against a test backend";
        }
    }

    public class IntegrationTests : IClassFixture<BackendFixture>
    {
        private readonly BackendFixture _f;
        private readonly ITestOutputHelper _out;

        public IntegrationTests(BackendFixture fixture, ITestOutputHelper output)
        {
            _f = fixture;
            _out = output;
        }

        private VaultixClient NewClient(bool trustTestKey = true)
        {
            var client = new VaultixClient(_f.BaseUrl);
            if (trustTestKey) Assert.True(client.TrustResponseKeyForTestingOnly(_f.KeyId, _f.KeyHex));
            return client;
        }

        private async Task<VaultixClient> E2eeClient(string? contentKey)
        {
            VaultixClient client = NewClient();
            client.SetApiKey(BackendFixture.S(_f.E2ee, "apiKey"));
            if (contentKey != null) Assert.True(client.SetContentKey(contentKey));
            Assert.True(await client.AuthenticateWithKeyAsync(BackendFixture.S(_f.E2ee, "licenseKey")), client.GetLastError());
            return client;
        }

        private string Product => BackendFixture.S(_f.E2ee, "productId");
        private string FileName => BackendFixture.S(_f.E2ee, "file", "name");
        private string FileSha => BackendFixture.S(_f.E2ee, "file", "sha256");
        private string ContentKey => BackendFixture.S(_f.E2ee, "contentKey");
        private string FolderName => BackendFixture.S(_f.E2ee, "folder", "name");

        private static string TempDir()
        {
            string dir = Path.Combine(Path.GetTempPath(), "vaultix-sdk-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        [IntegrationFact]
        public async Task E2ee_KeyLogin_FileToMemory_TwiceWithNewOneTimeKeys()
        {
            using VaultixClient client = await E2eeClient(ContentKey);
            _out.WriteLine("fingerprint " + client.GetContentKeyFingerprint());
            Assert.Matches("^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$", client.GetContentKeyFingerprint());
            Assert.True(client.IsSessionValid);
            Assert.NotEqual("", client.GetCurrentSession().AppId);

            byte[]? data = await client.DownloadFileToMemoryAsync(Product, FileName);
            Assert.True(data != null, client.GetLastError());
            Assert.Equal(FileSha, Hex.Sha256(data));
            Assert.Equal("", client.GetLastError());
            long signedAt = client.GetLastSignedAt();
            Assert.True(signedAt > 0);
            _out.WriteLine($"{FileName}: {data!.Length} bytes, signed at {DateTimeOffset.FromUnixTimeMilliseconds(signedAt):O}");

            byte[]? again = await client.DownloadFileToMemoryAsync(Product, FileName);
            Assert.True(again != null, client.GetLastError());
            Assert.Equal(FileSha, Hex.Sha256(again));
            Assert.Equal(signedAt, client.GetLastSignedAt());

            int chunks = 0;
            long total = 0;
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            Assert.True(await client.StreamFileAsync(Product, FileName, (chunk, received, all) =>
            {
                chunks++;
                sha.AppendData(chunk);
                total = all;
            }), client.GetLastError());
            Assert.Equal(FileSha, Hex.Of(sha.GetHashAndReset()));
            Assert.Equal(data.Length, total);
            Assert.True(chunks >= 1);

            FileInfo? info = await client.GetFileInfoAsync(Product, FileName);
            Assert.True(info != null, client.GetLastError());
            Assert.Equal("zk1", info!.Enc);
            Assert.Equal(FileName, info.Name);
            await client.EndSessionAsync();
            Assert.False(client.IsSessionValid);
        }

        [IntegrationFact]
        public async Task E2ee_FileToDisk_LeavesNoPartFile()
        {
            using VaultixClient client = await E2eeClient(ContentKey);
            string dir = TempDir();
            try
            {
                string path = Path.Combine(dir, "sub", FileName);
                Assert.True(await client.DownloadFileAsync(Product, FileName, path), client.GetLastError());
                Assert.Equal(FileSha, Hex.Sha256(File.ReadAllBytes(path)));
                Assert.True(client.GetLastSignedAt() > 0);
                Assert.Empty(Directory.GetFiles(dir, "*.vxpart", SearchOption.AllDirectories));

                // a failing download leaves neither the file nor a .vxpart behind
                client.ClearContentKey();
                string failed = Path.Combine(dir, "failed.bin");
                Assert.False(await client.DownloadFileAsync(Product, FileName, failed));
                Assert.False(File.Exists(failed));
                Assert.Empty(Directory.GetFiles(dir, "*.vxpart", SearchOption.AllDirectories));
                Assert.Equal(0, client.GetLastSignedAt());
            }
            finally
            {
                Directory.Delete(dir, true);
                await client.EndSessionAsync();
            }
        }

        private void CheckZip(byte[] zip)
        {
            using var archive = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read);
            var entries = archive.Entries.Where(e => !e.FullName.EndsWith("/")).ToDictionary(e => e.FullName);
            _out.WriteLine("zip entries: " + string.Join(", ", entries.Select(e => $"{e.Key} ({e.Value.Length})")));
            foreach (JsonElement expected in _f.E2ee.GetProperty("folder").GetProperty("zipEntries").EnumerateArray())
            {
                string path = expected.GetProperty("path").GetString()!;
                Assert.True(entries.ContainsKey(path), "zip entry " + path);
                Assert.Equal(expected.GetProperty("size").GetInt64(), entries[path].Length);
                if (expected.TryGetProperty("content", out JsonElement content))
                {
                    using var reader = new StreamReader(entries[path].Open(), Encoding.UTF8);
                    Assert.Equal(content.GetString(), reader.ReadToEnd());
                }
            }
            Assert.Equal(3000, entries["bin/app.exe"].Length);
        }

        [IntegrationFact]
        public async Task E2ee_Folder_AsZip_MemoryAndDisk()
        {
            using VaultixClient client = await E2eeClient(ContentKey);
            FolderInfo? folder = await client.GetFolderInfoAsync(Product, FolderName);
            Assert.True(folder != null, client.GetLastError());

            byte[]? zip = await client.DownloadFolderToMemoryAsync(Product, FolderName);
            Assert.True(zip != null, client.GetLastError());
            Assert.True(client.GetLastSignedAt() > 0);
            CheckZip(zip!);

            string dir = TempDir();
            try
            {
                string path = Path.Combine(dir, FolderName + ".zip");
                Assert.True(await client.DownloadFolderAsync(Product, FolderName, path), client.GetLastError());
                CheckZip(File.ReadAllBytes(path));
                Assert.Empty(Directory.GetFiles(dir, "*.vxpart"));
            }
            finally
            {
                Directory.Delete(dir, true);
                await client.EndSessionAsync();
            }
        }

        [IntegrationFact]
        public async Task E2ee_Variables()
        {
            using VaultixClient client = await E2eeClient(ContentKey);
            Dictionary<string, string> variables = await client.GetProductVariablesAsync(Product);
            Assert.Equal("", client.GetLastError());
            string name = BackendFixture.S(_f.E2ee, "variable", "name");
            Assert.True(variables.ContainsKey(name), "variables: " + string.Join(", ", variables.Keys));
            Assert.Equal(BackendFixture.S(_f.E2ee, "variable", "value"), variables[name]);
            await client.EndSessionAsync();
        }

        [IntegrationFact]
        public async Task E2ee_HashCheck_KeyedHash()
        {
            using VaultixClient client = await E2eeClient(ContentKey);
            string dir = TempDir();
            try
            {
                string path = Path.Combine(dir, "file.bin");
                Assert.True(await client.DownloadFileAsync(Product, FileName, path), client.GetLastError());
                Assert.True(await client.IsValidFileHashAsync(Product, FileName, path), client.GetLastError());
                File.AppendAllText(path, "x");
                Assert.False(await client.IsValidFileHashAsync(Product, FileName, path));
                Assert.False(await client.IsValidFileHashAsync(Product, FileName, Path.Combine(dir, "missing.bin")));
                Assert.StartsWith("Failed to open file", client.GetLastError());
            }
            finally
            {
                Directory.Delete(dir, true);
                await client.EndSessionAsync();
            }
        }

        [IntegrationFact]
        public async Task E2ee_WithoutContentKey_FailsClearly()
        {
            using VaultixClient client = await E2eeClient(null);
            Assert.Null(await client.DownloadFileToMemoryAsync(Product, FileName));
            _out.WriteLine("file: " + client.GetLastError());
            Assert.Contains("SetContentKey", client.GetLastError());
            Assert.Contains("end-to-end encryption", client.GetLastError());
            Assert.Null(await client.DownloadFolderToMemoryAsync(Product, FolderName));
            Assert.Contains("SetContentKey", client.GetLastError());
            Assert.Empty(await client.GetProductVariablesAsync(Product));
            _out.WriteLine("variables: " + client.GetLastError());
            Assert.Contains("SetContentKey", client.GetLastError());
            Assert.Equal(0, client.GetLastSignedAt());
            await client.EndSessionAsync();
        }

        [IntegrationFact]
        public async Task E2ee_WrongContentKey_Fails()
        {
            using VaultixClient client = await E2eeClient(BackendFixture.S(_f.E2ee, "wrongContentKey"));
            Assert.Null(await client.DownloadFileToMemoryAsync(Product, FileName));
            _out.WriteLine("file: " + client.GetLastError());
            Assert.StartsWith("End-to-end encrypted download failed: cannot open the sealed file key", client.GetLastError());
            Assert.Null(await client.DownloadFolderToMemoryAsync(Product, FolderName));
            Assert.Contains("cannot open the sealed file key", client.GetLastError());
            Assert.Empty(await client.GetProductVariablesAsync(Product));
            _out.WriteLine("variables: " + client.GetLastError());
            Assert.Contains("cannot open variable", client.GetLastError());
            Assert.Equal(0, client.GetLastSignedAt());
            await client.EndSessionAsync();
        }

        [IntegrationFact]
        public async Task Legacy_App_DownloadsAndHashes()
        {
            using VaultixClient client = NewClient();
            client.SetApiKey(BackendFixture.S(_f.Legacy, "apiKey"));
            Assert.True(await client.AuthenticateWithKeyAsync(BackendFixture.S(_f.Legacy, "licenseKey")), client.GetLastError());
            string product = BackendFixture.S(_f.Legacy, "productId");
            string name = BackendFixture.S(_f.Legacy, "file", "name");
            string sha = BackendFixture.S(_f.Legacy, "file", "sha256");

            byte[]? data = await client.DownloadFileToMemoryAsync(product, name);
            Assert.True(data != null, client.GetLastError());
            Assert.Equal(sha, Hex.Sha256(data));
            Assert.Equal(_f.Legacy.GetProperty("file").GetProperty("size").GetInt32(), data!.Length);
            Assert.Equal(0, client.GetLastSignedAt());
            Dictionary<string, string> variables = await client.GetProductVariablesAsync(product);
            Assert.Equal("", client.GetLastError());
            _out.WriteLine($"legacy variables: {variables.Count}");

            string dir = TempDir();
            try
            {
                string path = Path.Combine(dir, name);
                Assert.True(await client.DownloadFileAsync(product, name, path), client.GetLastError());
                Assert.Equal(sha, Hex.Sha256(File.ReadAllBytes(path)));
                Assert.Empty(Directory.GetFiles(dir, "*.vxpart"));
                // plain SHA-256 without a content key ...
                Assert.True(await client.IsValidFileHashAsync(product, name, path), client.GetLastError());
                // ... and with one: keyed hash first, then the plain hash (not a zk1 file)
                Assert.True(client.SetContentKey(ContentKey));
                Assert.True(await client.IsValidFileHashAsync(product, name, path), client.GetLastError());
                byte[]? withKey = await client.DownloadFileToMemoryAsync(product, name);
                Assert.Equal(sha, Hex.Sha256(withKey!));
                File.AppendAllText(path, "x");
                Assert.False(await client.IsValidFileHashAsync(product, name, path));
            }
            finally
            {
                Directory.Delete(dir, true);
                await client.EndSessionAsync();
            }
        }

        [IntegrationFact]
        public async Task E2ee_OtherEndpoints()
        {
            using VaultixClient client = await E2eeClient(ContentKey);
            List<Dictionary<string, string>> products = await client.GetUserProductsAsync();
            Assert.Contains(products, p => p["id"] == Product);
            Assert.True(client.HasProductAccess(Product));
            SubscriptionInfo subscription = await client.GetUserSubscriptionByProductAsync(Product);
            Assert.True(subscription.SubscriptionId.Length > 0, client.GetLastError());
            AccountInfo? account = await client.GetAccountInfoAsync();
            Assert.True(account != null, client.GetLastError());
            ProductStatusInfo status = await client.GetProductStatusAsync(Product);
            Assert.Equal("", client.GetLastError());
            ProductNewsInfo news = await client.GetProductNewsAsync(Product);
            Assert.Equal("", client.GetLastError());
            _out.WriteLine($"products {products.Count}, subscription {subscription.Status}, status {status.HasStatus}, news {news.HasNews}");

            List<FileInfo> files = await client.GetFileListAsync(Product);
            _out.WriteLine($"GetFileListAsync: {files.Count} files, error '{client.GetLastError()}'");
            List<FolderInfo> folders = await client.GetFolderListAsync(Product);
            _out.WriteLine($"GetFolderListAsync: {folders.Count} folders, error '{client.GetLastError()}'");
            await client.EndSessionAsync();
        }

        [IntegrationFact]
        public async Task WithoutTestingKey_EveryResponseIsRefused()
        {
            // Login: the test backend signs with its own key, which this build does not trust.
            using (VaultixClient untrusted = NewClient(trustTestKey: false))
            {
                untrusted.SetApiKey(BackendFixture.S(_f.E2ee, "apiKey"));
                Assert.True(untrusted.SetContentKey(ContentKey));
                Assert.False(await untrusted.AuthenticateWithKeyAsync(BackendFixture.S(_f.E2ee, "licenseKey")));
                _out.WriteLine("login: " + untrusted.GetLastError());
                Assert.StartsWith("Server response could not be verified (HTTP 200): unknown signing key", untrusted.GetLastError());
                Assert.False(untrusted.IsSessionValid);

                untrusted.SetApiKey(BackendFixture.S(_f.Legacy, "apiKey"));
                Assert.False(await untrusted.AuthenticateWithKeyAsync(BackendFixture.S(_f.Legacy, "licenseKey")));
                Assert.StartsWith("Server response could not be verified", untrusted.GetLastError());
            }

            // A signed-in client that stops trusting the test key: every call fails.
            using VaultixClient client = await E2eeClient(ContentKey);
            client.ClearTestingResponseKeys();
            Assert.Null(await client.DownloadFileToMemoryAsync(Product, FileName));
            _out.WriteLine("file: " + client.GetLastError());
            Assert.StartsWith("Server response could not be verified (HTTP 200): unknown signing key", client.GetLastError());
            Assert.Null(await client.DownloadFolderToMemoryAsync(Product, FolderName));
            Assert.StartsWith("Server response could not be verified", client.GetLastError());
            Assert.Empty(await client.GetProductVariablesAsync(Product));
            Assert.StartsWith("Server response could not be verified", client.GetLastError());
            string dir = TempDir();
            try
            {
                string path = Path.Combine(dir, "f.bin");
                File.WriteAllText(path, "x");
                Assert.False(await client.IsValidFileHashAsync(Product, FileName, path));
                Assert.StartsWith("Server response could not be verified", client.GetLastError());
                Assert.False(await client.DownloadFileAsync(Product, FileName, Path.Combine(dir, "out.bin")));
                Assert.StartsWith("Server response could not be verified", client.GetLastError());
                Assert.Equal(new[] { path }, Directory.GetFiles(dir));
            }
            finally
            {
                Directory.Delete(dir, true);
            }
            Assert.Empty(await client.GetUserProductsAsync());
            Assert.StartsWith("Server response could not be verified", client.GetLastError());
            Assert.Null(await client.GetAccountInfoAsync());
            Assert.StartsWith("Server response could not be verified", client.GetLastError());

            // End-to-end encrypted deliveries are verified even with SetRequireSignedResponses(false).
            client.SetRequireSignedResponses(false);
            Assert.Null(await client.DownloadFileToMemoryAsync(Product, FileName));
            _out.WriteLine("file, signatures not required: " + client.GetLastError());
            Assert.StartsWith("Server response could not be verified (HTTP 200): unknown signing key", client.GetLastError());
            Assert.Empty(await client.GetProductVariablesAsync(Product));
            Assert.StartsWith("Server response could not be verified", client.GetLastError());

            // Back to trusting the test key: the same session works again.
            client.SetRequireSignedResponses(true);
            Assert.True(client.TrustResponseKeyForTestingOnly(_f.KeyId, _f.KeyHex));
            Assert.Equal(FileSha, Hex.Sha256((await client.DownloadFileToMemoryAsync(Product, FileName))!));
            await client.EndSessionAsync();
        }
    }
}
