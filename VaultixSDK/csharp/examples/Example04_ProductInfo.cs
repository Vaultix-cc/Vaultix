using Vaultix.SDK;

namespace Vaultix.Examples;

/// <summary>
/// Example 4: Product Variables and Status
/// 
/// Demonstrates how to:
/// - Retrieve product variables (key-value pairs)
/// - Get product status information
/// - Fetch product news/announcements
/// - Use variables for application configuration
/// </summary>
public class Example04_ProductInfo
{
    private const string AppApiKey = "ap_your_app_api_key_here";
    private const string ContentKey = "vxk_your_sdk_key_here";   // App Settings -> End-to-end encryption
    private const string ProductId = "your_product_id_here";
    private const string Username = "your_username";
    private const string Password = "your_password";
    
    public static async Task Main(string[] args)
    {
        PrintBanner();
        
        using var client = new VaultixClient("https://vaultix.cc/api");
        client.DebugMode = true;
        
        client.SetApiKey(AppApiKey);
        // Opens end-to-end encrypted variables (all new apps).
        if (!client.SetContentKey(ContentKey))
        {
            Console.WriteLine("[WARN] Set your vxk_ SDK key (App Settings -> End-to-end encryption) to open encrypted variables.");
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
        
        // 1. Get product status
        Console.WriteLine("--- Product Status ---");
        
        var statusInfo = await client.GetProductStatusAsync(ProductId);
        
        if (statusInfo.HasStatus)
        {
            PrintStatusWithColor(statusInfo);
        }
        else
        {
            Console.WriteLine("  [INFO] No status information available.");
        }
        Console.WriteLine();
        
        // 2. Get product news
        Console.WriteLine("--- Product News & Announcements ---");
        
        var newsInfo = await client.GetProductNewsAsync(ProductId);
        
        if (newsInfo.HasNews)
        {
            Console.WriteLine($"  Headline: {newsInfo.Headline}");
            Console.WriteLine("  Content:");
            
            // Word wrap content at 60 characters
            var content = newsInfo.Content;
            var words = content.Split(' ');
            var line = "";
            
            foreach (var word in words)
            {
                if (line.Length + word.Length + 1 > 60)
                {
                    Console.WriteLine($"    {line}");
                    line = word;
                }
                else
                {
                    line = string.IsNullOrEmpty(line) ? word : $"{line} {word}";
                }
            }
            if (!string.IsNullOrEmpty(line))
            {
                Console.WriteLine($"    {line}");
            }
            
            Console.WriteLine();
            Console.WriteLine($"  Updated: {newsInfo.UpdatedAt}");
        }
        else
        {
            Console.WriteLine("  [INFO] No news available at this time.");
        }
        Console.WriteLine();
        
        // 3. Get product variables
        Console.WriteLine("--- Product Variables ---");
        
        var variables = await client.GetProductVariablesAsync(ProductId);
        
        if (variables.Count == 0)
        {
            // Empty on any failure, e.g. an encrypted value without the right content key.
            var error = client.GetLastError();
            Console.WriteLine(string.IsNullOrEmpty(error) ? "  No variables defined for this product." : $"  [FAILED] {error}");
        }
        else
        {
            Console.WriteLine($"  Found {variables.Count} variable(s):");
            Console.WriteLine();
            
            // Group variables by category (prefix)
            var groupedVars = new Dictionary<string, List<KeyValuePair<string, string>>>();
            
            foreach (var variable in variables)
            {
                var key = variable.Key;
                var category = "other";
                
                if (key.Contains("VERSION", StringComparison.OrdinalIgnoreCase))
                    category = "version";
                else if (key.Contains("URL", StringComparison.OrdinalIgnoreCase) || 
                         key.Contains("LINK", StringComparison.OrdinalIgnoreCase))
                    category = "urls";
                else if (key.Contains("KEY", StringComparison.OrdinalIgnoreCase) || 
                         key.Contains("TOKEN", StringComparison.OrdinalIgnoreCase) ||
                         key.Contains("SECRET", StringComparison.OrdinalIgnoreCase))
                    category = "secrets";
                else if (key.Contains("DEBUG", StringComparison.OrdinalIgnoreCase) ||
                         key.Contains("ENABLE", StringComparison.OrdinalIgnoreCase) ||
                         key.Contains("DISABLED", StringComparison.OrdinalIgnoreCase))
                    category = "flags";
                
                if (!groupedVars.ContainsKey(category))
                    groupedVars[category] = new List<KeyValuePair<string, string>>();
                
                groupedVars[category].Add(variable);
            }
            
            // Print grouped variables
            foreach (var group in groupedVars)
            {
                Console.WriteLine($"  [{group.Key.ToUpper()}]");
                
                foreach (var variable in group.Value)
                {
                    // Mask sensitive values
                    var displayValue = variable.Value;
                    var isSensitive = variable.Key.Contains("KEY", StringComparison.OrdinalIgnoreCase) ||
                                    variable.Key.Contains("TOKEN", StringComparison.OrdinalIgnoreCase) ||
                                    variable.Key.Contains("SECRET", StringComparison.OrdinalIgnoreCase);
                    
                    if (isSensitive && displayValue.Length > 8)
                    {
                        displayValue = displayValue.Substring(0, 4) + "****" + 
                                       displayValue.Substring(displayValue.Length - 4);
                    }
                    
                    Console.WriteLine($"    {variable.Key} = {displayValue}");
                }
                Console.WriteLine();
            }
        }
        
        // 4. Use variables for application config
        Console.WriteLine("--- Using Variables for Configuration ---");
        
        foreach (var variable in variables)
        {
            if (variable.Key == "CURRENT_VERSION" || variable.Key == "version")
            {
                Console.WriteLine($"  Current version: {variable.Value}");
            }
            if (variable.Key == "MIN_VERSION" || variable.Key == "min_version")
            {
                Console.WriteLine($"  Minimum required version: {variable.Value}");
            }
            if (variable.Key == "DOWNLOAD_URL" || variable.Key == "download_url")
            {
                Console.WriteLine($"  Download URL: {variable.Value}");
            }
        }
        
        // End session
        client.EndSession();
        
        Console.WriteLine();
        Console.WriteLine("================================================");
        Console.WriteLine("Example completed.");
        Console.WriteLine("================================================");
    }
    
    private static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("================================================");
        Console.WriteLine("  Vaultix SDK - Product Variables & Status");
        Console.WriteLine("================================================");
        Console.WriteLine();
    }
    
    private static void PrintStatusWithColor(ProductStatusInfo status)
    {
        Console.WriteLine($"  Status Name:  {status.Name}");
        Console.WriteLine($"  Status Color: {status.Color}");
        Console.WriteLine($"  Status Action: {status.Action}");
        
        // Interpret the status
        Console.WriteLine();
        Console.WriteLine("  Interpretation:");
        
        if (status.Name == "online" || status.Name == "active")
        {
            Console.WriteLine("    [OK] Product is operating normally.");
        }
        else if (status.Name == "maintenance")
        {
            Console.WriteLine("    [INFO] Product is under maintenance.");
            Console.WriteLine($"    Action to take: {status.Action}");
        }
        else if (status.Name == "update")
        {
            Console.WriteLine("    [UPDATE] A new version is available!");
            Console.WriteLine($"    Action: {status.Action}");
        }
        else if (status.Name == "offline")
        {
            Console.WriteLine("    [ERROR] Product is currently offline.");
            Console.WriteLine($"    Action: {status.Action}");
        }
        else
        {
            Console.WriteLine($"    Unknown status: {status.Name}");
        }
    }
}
