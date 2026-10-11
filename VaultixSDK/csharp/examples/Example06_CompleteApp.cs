using Vaultix.SDK;

namespace Vaultix.Examples;

/// <summary>
/// Example 6: Complete Application Integration
/// 
/// A comprehensive example showing how to integrate the Vaultix SDK
/// into a real application with proper error handling, security,
/// and best practices.
/// </summary>
public class Example06_CompleteApp
{
    // Configuration structure
    private class AppConfig
    {
        public string ApiUrl { get; set; } = "https://vaultix.cc/api";
        public string AppApiKey { get; set; } = "ap_your_app_api_key_here";
        public string ContentKey { get; set; } = "vxk_your_sdk_key_here";   // App Settings -> End-to-end encryption
        public string ProductId { get; set; } = "your_product_id_here";
        public string FileName { get; set; } = "your_file_name_here";
        public string Username { get; set; } = "your_username";
        public string Password { get; set; } = "your_password";
        public bool DebugMode { get; set; } = true;
        public string DownloadPath { get; set; } = "./downloads";
    }
    
    public static async Task Main(string[] args)
    {
        PrintBanner();
        
        // Step 1: Load Configuration
        PrintInfo("Loading application configuration...");
        
        var config = new AppConfig();
        
        if (string.IsNullOrEmpty(config.AppApiKey) || string.IsNullOrEmpty(config.ProductId))
        {
            PrintError("Configuration is incomplete. Please set your API key and product ID.");
            return;
        }
        
        // Step 2: Initialize Client
        PrintInfo("Initializing Vaultix client...");
        
        using var client = new VaultixClient(config.ApiUrl);
        client.DebugMode = config.DebugMode;
        client.SetApiKey(config.AppApiKey);
        // Opens end-to-end encrypted files and variables (all new apps).
        if (!client.SetContentKey(config.ContentKey))
        {
            PrintError("Set your vxk_ SDK key to open encrypted content.");
        }
        
        // Enable security features
        client.SetMinTlsVersion("1.2");
        // Note: In production, you should enable certificate pinning
        // client.EnableCertificatePinning(new List<string> { "your-certificate-sha256-hash" });
        
        // Step 3: Authenticate
        PrintInfo("Authenticating user...");
        
        bool authenticated = false;
        
        // Try auto-login first
        if (await client.TryAutoLoginAsync())
        {
            PrintSuccess("Auto-login successful!");
            authenticated = true;
        }
        // Fall back to manual login
        else if (await client.AuthenticateWithUsernameAsync(config.Username, config.Password))
        {
            PrintSuccess("Manual authentication successful!");
            authenticated = true;
        }
        // Try key authentication
        else
        {
            Console.WriteLine();
            Console.Write("Enter license key (or press Enter to skip): ");
            var licenseKey = Console.ReadLine();
            
            if (!string.IsNullOrEmpty(licenseKey))
            {
                if (await client.AuthenticateWithKeyAsync(licenseKey))
                {
                    PrintSuccess("License key authentication successful!");
                    authenticated = true;
                }
            }
        }
        
        if (!authenticated)
        {
            PrintError($"Authentication failed: {client.GetLastError()}");
            return;
        }
        
        // Step 4: Check Authorization
        PrintInfo("Checking product access and subscription...");
        
        if (!CheckAuthorization(client, config.ProductId))
        {
            PrintError("Authorization check failed");
            client.EndSession();
            return;
        }
        
        PrintSuccess("User is authorized!");
        
        var subscription = await client.GetUserSubscriptionByProductAsync(config.ProductId);
        Console.WriteLine($"  Subscription: {subscription.Status}");
        Console.WriteLine($"  Downloads used: {subscription.Downloads}");
        
        // Step 5: Get Product Information
        PrintInfo("Fetching product information...");
        
        // Check product status
        var status = await client.GetProductStatusAsync(config.ProductId);
        if (status.HasStatus)
        {
            Console.WriteLine($"  Product status: {status.Name}");
            
            if (status.Name == "maintenance" || status.Name == "offline")
            {
                PrintError($"Product is currently unavailable: {status.Action}");
                client.EndSession();
                return;
            }
        }
        
        // Get product variables
        var variables = await client.GetProductVariablesAsync(config.ProductId);
        Console.WriteLine($"  Product has {variables.Count} variable(s)");
        
        // Step 6: Download a File
        PrintInfo($"Downloading: {config.FileName}");
        
        var outputPath = Path.Combine(config.DownloadPath, config.FileName);
        
        if (await DownloadWithRetryAsync(client, config.ProductId, config.FileName, outputPath))
        {
            PrintSuccess("File downloaded successfully!");
            Console.WriteLine($"  Saved to: {outputPath}");
            
            // Verify hash
            if (await client.IsValidFileHashAsync(config.ProductId, config.FileName, outputPath))
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
            PrintError("Failed to download file after 3 attempts");
        }
        
        // Step 7: Cleanup
        PrintInfo("Cleaning up...");
        client.EndSession();
        
        PrintSuccess("Application completed successfully!");
        
        Console.WriteLine();
        Console.WriteLine("================================================");
        Console.WriteLine("Thank you for using Vaultix SDK!");
        Console.WriteLine("================================================");
    }
    
    private static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("================================================");
        Console.WriteLine("  Vaultix SDK - Complete Integration Example");
        Console.WriteLine("================================================");
        Console.WriteLine();
    }
    
    private static void PrintError(string message)
    {
        Console.WriteLine();
        Console.WriteLine($"[ERROR] {message}");
    }
    
    private static void PrintSuccess(string message)
    {
        Console.WriteLine();
        Console.WriteLine($"[SUCCESS] {message}");
    }
    
    private static void PrintInfo(string message)
    {
        Console.WriteLine();
        Console.WriteLine($"[INFO] {message}");
    }
    
    private static bool CheckAuthorization(VaultixClient client, string productId)
    {
        if (!client.IsSessionValid)
        {
            PrintError("Session is not valid");
            return false;
        }
        
        if (!client.HasProductAccess(productId))
        {
            PrintError("User does not have access to this product");
            return false;
        }
        
        return true;
    }
    
    private static async Task<bool> DownloadWithRetryAsync(
        VaultixClient client,
        string productId,
        string fileName,
        string outputPath,
        int maxRetries = 3)
    {
        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            Console.WriteLine($"  Attempt {attempt}/{maxRetries}...");
            
            if (await client.DownloadFileAsync(productId, fileName, outputPath))
            {
                return true;
            }
            
            Console.WriteLine($"  Failed: {client.GetLastError()}");
            
            if (attempt < maxRetries)
            {
                Console.WriteLine("  Retrying in 2 seconds...");
                await Task.Delay(2000);
            }
        }
        
        return false;
    }
}
