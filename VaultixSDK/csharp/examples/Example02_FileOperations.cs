using Vaultix.SDK;

namespace Vaultix.Examples;

/// <summary>
/// Example 2: File Operations
///
/// Demonstrates how to work with files in the Vaultix system:
/// - Open end-to-end encrypted content with the content key
/// - Get file information
/// - Download files to disk or memory
/// - Stream a file in chunks
/// - Verify file integrity with hash checking
/// - Download folders as zip archives
/// </summary>
public class Example02_FileOperations
{
    private const string AppApiKey = "ap_your_app_api_key_here";
    private const string ContentKey = "vxk_your_sdk_key_here";   // App Settings -> End-to-end encryption
    private const string ProductId = "your_product_id_here";
    private const string FileName = "your_file_name_here";
    private const string FolderName = "your_folder_name_here";
    private const string Username = "your_username";
    private const string Password = "your_password";

    public static async Task Main(string[] args)
    {
        PrintBanner();

        using var client = new VaultixClient("https://vaultix.cc/api");
        client.DebugMode = true;

        client.SetApiKey(AppApiKey);
        // Opens end-to-end encrypted files, folders and variables (all new apps).
        if (!client.SetContentKey(ContentKey))
        {
            Console.WriteLine("[WARN] Set your vxk_ SDK key (App Settings -> End-to-end encryption) to open encrypted content.");
        }
        else
        {
            Console.WriteLine($"Content key fingerprint: {client.GetContentKeyFingerprint()} (compare with App Settings)");
        }

        // Authenticate first
        Console.WriteLine("Authenticating...");
        if (!await client.AuthenticateWithUsernameAsync(Username, Password))
        {
            Console.WriteLine($"[FAILED] Authentication failed: {client.GetLastError()}");
            return;
        }
        Console.WriteLine("[OK] Authentication successful!");
        Console.WriteLine();

        // 1. Get file info
        Console.WriteLine("--- Getting File Info ---");
        var fileInfo = await client.GetFileInfoAsync(ProductId, FileName);
        if (fileInfo != null)
        {
            Console.WriteLine($"  File:       {fileInfo.Name}");
            Console.WriteLine($"  ID:         {fileInfo.Id}");
            Console.WriteLine($"  Size:       {FormatFileSize(fileInfo.Size)}");
            Console.WriteLine($"  End-to-end: {(fileInfo.Enc == "zk1" ? "Yes" : "No")}");
            Console.WriteLine($"  Downloads:  {fileInfo.Downloads}");
            Console.WriteLine($"  Uploaded:   {fileInfo.UploadedAt}");
        }
        else
        {
            Console.WriteLine($"[FAILED] {client.GetLastError()}");
        }
        Console.WriteLine();

        // 2. Download file to disk (written to "<path>.vxpart", renamed after every check)
        Console.WriteLine("--- Downloading File to Disk ---");
        var outputPath = Path.Combine("./downloads", FileName);
        Console.WriteLine($"Downloading '{FileName}' to '{outputPath}'");

        var startTime = DateTime.Now;
        if (await client.DownloadFileAsync(ProductId, FileName, outputPath))
        {
            var duration = DateTime.Now - startTime;

            Console.WriteLine("[OK] File downloaded successfully!");
            Console.WriteLine($"  Time taken: {duration.TotalMilliseconds} ms");
            if (client.GetLastSignedAt() > 0)
            {
                Console.WriteLine($"  Signed at:  {DateTimeOffset.FromUnixTimeMilliseconds(client.GetLastSignedAt()):u}");
            }

            // Verify hash
            if (await client.IsValidFileHashAsync(ProductId, FileName, outputPath))
            {
                Console.WriteLine("  Hash verification: PASSED");
            }
            else
            {
                Console.WriteLine("  Hash verification: FAILED");
            }
        }
        else
        {
            Console.WriteLine($"[FAILED] Download failed: {client.GetLastError()}");
        }
        Console.WriteLine();

        // 3. Download file to memory
        Console.WriteLine("--- Downloading File to Memory ---");
        Console.WriteLine($"Downloading '{FileName}' to memory...");

        var fileData = await client.DownloadFileToMemoryAsync(ProductId, FileName);
        if (fileData != null)
        {
            Console.WriteLine("[OK] File loaded into memory!");
            Console.WriteLine($"  Size: {FormatFileSize(fileData.Length)}");
            Console.WriteLine($"  First 64 bytes (hex): {BitConverter.ToString(fileData.Take(64).ToArray()).Replace("-", " ")}");
        }
        else
        {
            Console.WriteLine($"[FAILED] Memory download failed: {client.GetLastError()}");
        }
        Console.WriteLine();

        // 4. Stream file in chunks (the callback only sees verified data)
        Console.WriteLine("--- Streaming File in Chunks ---");
        Console.WriteLine($"Streaming '{FileName}'...");

        if (await client.StreamFileAsync(ProductId, FileName, (chunk, received, total) =>
        {
            var percent = total > 0 ? (double)received / total * 100 : 0;
            Console.Write($"\r  Progress: {percent:F1}% ({received} / {total} bytes)");
        }))
        {
            Console.WriteLine();
            Console.WriteLine("[OK] Stream completed!");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine($"[FAILED] Streaming failed: {client.GetLastError()}");
        }
        Console.WriteLine();

        // 5. Download a folder as a zip archive
        Console.WriteLine("--- Folder Operations ---");
        var zipPath = Path.Combine("./downloads", $"{FolderName}.zip");
        Console.WriteLine($"Downloading folder '{FolderName}' as zip...");

        if (await client.DownloadFolderAsync(ProductId, FolderName, zipPath))
        {
            Console.WriteLine("[OK] Folder downloaded successfully!");
            Console.WriteLine($"  Saved to: {zipPath}");
        }
        else
        {
            Console.WriteLine($"[FAILED] Folder download failed: {client.GetLastError()}");
        }
        Console.WriteLine();

        // End session
        client.EndSession();

        Console.WriteLine("================================================");
        Console.WriteLine("Example completed.");
        Console.WriteLine("================================================");
    }

    private static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("================================================");
        Console.WriteLine("  Vaultix SDK - File Operations Example");
        Console.WriteLine("================================================");
        Console.WriteLine();
    }

    private static string FormatFileSize(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        int unitIndex = 0;
        double size = bytes;

        while (size >= 1024 && unitIndex < units.Length - 1)
        {
            size /= 1024;
            unitIndex++;
        }

        return $"{size:F2} {units[unitIndex]}";
    }
}
