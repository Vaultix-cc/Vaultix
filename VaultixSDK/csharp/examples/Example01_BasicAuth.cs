using Vaultix.SDK;

namespace Vaultix.Examples;

/// <summary>
/// Example 1: Basic Authentication
/// 
/// Demonstrates how to authenticate with the Vaultix API using two methods:
/// 1. Username/Password authentication
/// 2. License key authentication
/// </summary>
public class Example01_BasicAuth
{
    private const string AppApiKey = "ap_your_app_api_key_here";
    private const string ProductId = "your_product_id_here";
    
    public static async Task Main(string[] args)
    {
        PrintBanner();
        
        using var client = new VaultixClient("https://vaultix.cc/api");
        client.DebugMode = true;
        
        client.SetApiKey(AppApiKey);
        
        Console.WriteLine("Choose authentication method:");
        Console.WriteLine("  1. Username/Password");
        Console.WriteLine("  2. License Key");
        Console.WriteLine();
        Console.Write("Enter choice (1 or 2): ");
        
        var choice = Console.ReadLine();
        
        bool authenticated = false;
        
        if (choice == "1")
        {
            // Method 1: Username/Password Authentication
            Console.WriteLine();
            Console.WriteLine("--- Username/Password Authentication ---");
            Console.WriteLine();
            
            Console.Write("Enter username: ");
            var username = Console.ReadLine() ?? "";
            
            Console.Write("Enter password: ");
            var password = ReadPassword();
            
            Console.WriteLine();
            Console.WriteLine("Authenticating...");
            
            if (await client.AuthenticateWithUsernameAsync(username, password))
            {
                Console.WriteLine();
                Console.WriteLine("[SUCCESS] Authentication successful!");
                Console.WriteLine("  A session token has been created.");
                Console.WriteLine("  The token will expire in 7 days.");
                authenticated = true;
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine($"[FAILED] Authentication failed!");
                Console.WriteLine($"  Error: {client.GetLastError()}");
            }
        }
        else if (choice == "2")
        {
            // Method 2: License Key Authentication
            Console.WriteLine();
            Console.WriteLine("--- License Key Authentication ---");
            Console.WriteLine();
            
            Console.Write("Enter license key (format: XXXX-XXXX-XXXX-XXXX): ");
            var licenseKey = Console.ReadLine() ?? "";
            
            Console.WriteLine();
            Console.WriteLine("Authenticating...");
            
            if (await client.AuthenticateWithKeyAsync(licenseKey))
            {
                Console.WriteLine();
                Console.WriteLine("[SUCCESS] Authentication successful!");
                Console.WriteLine("  A session token has been created.");
                Console.WriteLine("  The token will expire in 7 days.");
                authenticated = true;
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine($"[FAILED] Authentication failed!");
                Console.WriteLine($"  Error: {client.GetLastError()}");
            }
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("[ERROR] Invalid choice!");
        }
        
        if (authenticated)
        {
            // Display session information
            var session = client.GetCurrentSession();
            PrintSessionInfo(session);
            
            // Check product access
            Console.WriteLine();
            Console.WriteLine("Product Access Check:");
            if (client.HasProductAccess(ProductId))
            {
                Console.WriteLine($"  [OK] You have access to product: {ProductId}");
            }
            else
            {
                Console.WriteLine("  [WARN] You don't have access to this product.");
            }
            
            // Get user's products
            Console.WriteLine();
            Console.WriteLine("Your Products:");
            var products = await client.GetUserProductsAsync();
            
            if (products.Count > 0)
            {
                foreach (var product in products)
                {
                    Console.WriteLine($"  - {product["name"]} (ID: {product["id"]})");
                }
            }
            else
            {
                Console.WriteLine("  No products found.");
            }
            
            // End the session
            Console.WriteLine();
            Console.WriteLine("Ending session...");
            client.EndSession();
            Console.WriteLine("[OK] Session ended.");
        }
        
        Console.WriteLine();
        Console.WriteLine("================================================");
        Console.WriteLine("Example completed.");
        Console.WriteLine("================================================");
    }
    
    private static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("================================================");
        Console.WriteLine("  Vaultix SDK - Basic Authentication Example");
        Console.WriteLine("================================================");
        Console.WriteLine();
    }
    
    private static void PrintSessionInfo(Session session)
    {
        Console.WriteLine();
        Console.WriteLine("  Session Information:");
        Console.WriteLine("  ----------------------------------------");
        Console.WriteLine($"    App ID:       {session.AppId}");
        Console.WriteLine($"    Session ID:   {session.SessionId}");
        Console.WriteLine($"    HWID:         {session.Hwid}");
        Console.WriteLine($"    Token Expires: {session.TokenExpiry}");
        Console.WriteLine($"    User ID:      {session.AppUser.Id}");
        Console.WriteLine($"    Username:     {session.AppUser.Username}");
        Console.WriteLine("  ----------------------------------------");
    }
    
    private static string ReadPassword()
    {
        var password = new System.Text.StringBuilder();
        ConsoleKeyInfo key;
        
        while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
        {
            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password.Remove(password.Length - 1, 1);
            }
            else if (key.Key != ConsoleKey.Backspace)
            {
                password.Append(key.KeyChar);
            }
        }
        
        Console.WriteLine();
        return password.ToString();
    }
}
