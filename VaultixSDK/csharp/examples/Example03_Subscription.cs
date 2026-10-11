using Vaultix.SDK;

namespace Vaultix.Examples;

/// <summary>
/// Example 3: Subscription Management
/// 
/// Demonstrates how to manage user subscriptions:
/// - Get subscription details for a product
/// - Check subscription status (active, paused, expired)
/// - Get subscription expiration dates
/// - View download counts
/// </summary>
public class Example03_Subscription
{
    private const string AppApiKey = "ap_your_app_api_key_here";
    private const string ProductId = "your_product_id_here";
    private const string Username = "your_username";
    private const string Password = "your_password";
    
    public static async Task Main(string[] args)
    {
        PrintBanner();
        
        using var client = new VaultixClient("https://vaultix.cc/api");
        client.DebugMode = true;
        
        client.SetApiKey(AppApiKey);
        
        // Authenticate first
        Console.WriteLine("Authenticating...");
        if (!await client.AuthenticateWithUsernameAsync(Username, Password))
        {
            Console.WriteLine($"[FAILED] Authentication failed: {client.GetLastError()}");
            return;
        }
        Console.WriteLine("[OK] Authentication successful!");
        Console.WriteLine();
        
        // 1. Get all user products
        Console.WriteLine("--- Your Products ---");
        var products = await client.GetUserProductsAsync();
        
        if (products.Count == 0)
        {
            Console.WriteLine("You don't have access to any products.");
            client.EndSession();
            return;
        }
        
        Console.WriteLine($"You have access to {products.Count} product(s):");
        Console.WriteLine();
        
        for (int i = 0; i < products.Count; i++)
        {
            var product = products[i];
            Console.WriteLine($"  {i + 1}. {product["name"]}");
            Console.WriteLine($"     ID:   {product["id"]}");
        }
        Console.WriteLine();
        
        // 2. Get subscription for a specific product
        Console.WriteLine($"--- Subscription Details for {ProductId} ---");
        
        var subscription = await client.GetUserSubscriptionByProductAsync(ProductId);
        
        if (!string.IsNullOrEmpty(subscription.SubscriptionId))
        {
            PrintSubscriptionInfo(subscription);
            
            // 3. Check subscription validity
            Console.WriteLine();
            Console.WriteLine("--- Subscription Validity Check ---");
            
            bool isValid = !subscription.IsPaused && 
                           (string.IsNullOrEmpty(subscription.ExpiresAt) || 
                            subscription.Status == "active");
            
            if (isValid)
            {
                Console.WriteLine("  [OK] Your subscription is valid!");
            }
            else
            {
                Console.WriteLine("  [WARN] Your subscription has issues:");
                
                if (subscription.IsPaused)
                {
                    Console.WriteLine("    - Subscription is paused");
                }
                if (subscription.Status == "expired")
                {
                    Console.WriteLine("    - Subscription has expired");
                }
            }
            
            // 4. Download allowance check
            Console.WriteLine();
            Console.WriteLine("--- Download Allowance ---");
            Console.WriteLine($"  Downloads used: {subscription.Downloads}");
            
            if (subscription.Downloads < 1000)
            {
                Console.WriteLine("  Downloads remaining: Unlimited (no restrictions)");
            }
            else
            {
                Console.WriteLine("  Consider monitoring your download usage.");
            }
        }
        else
        {
            var error = client.GetLastError();
            if (error.Contains("No subscription found"))
            {
                Console.WriteLine("  [INFO] No active subscription found for this product.");
                Console.WriteLine("  Please purchase or activate a subscription to access content.");
            }
            else
            {
                Console.WriteLine($"  [ERROR] Failed to retrieve subscription: {error}");
            }
        }
        
        // 5. Check access for all products
        Console.WriteLine();
        Console.WriteLine("--- Access Check for All Products ---");
        
        foreach (var product in products)
        {
            var pid = product["id"];
            bool hasAccess = client.HasProductAccess(pid);
            
            Console.Write($"  {product["name"]}: ");
            if (hasAccess)
            {
                Console.WriteLine("[OK] Has access");
            }
            else
            {
                Console.WriteLine("[NO ACCESS]");
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
        Console.WriteLine("  Vaultix SDK - Subscription Management Example");
        Console.WriteLine("================================================");
        Console.WriteLine();
    }
    
    private static void PrintSubscriptionInfo(SubscriptionInfo sub)
    {
        Console.WriteLine("  ----------------------------------------");
        Console.WriteLine($"    Subscription ID: {sub.SubscriptionId}");
        Console.WriteLine($"    User ID:         {sub.AppUserId}");
        Console.WriteLine($"    Product ID:      {sub.ProductId}");
        Console.WriteLine($"    Status:          {sub.Status}");
        Console.WriteLine($"    Expires At:      {(string.IsNullOrEmpty(sub.ExpiresAt) ? "Lifetime" : sub.ExpiresAt)}");
        Console.WriteLine($"    Is Paused:       {(sub.IsPaused ? "Yes" : "No")}");
        
        if (sub.IsPaused)
        {
            Console.WriteLine($"    Paused At:       {sub.PausedAt}");
            Console.WriteLine($"    Paused Until:     {sub.PausedUntil}");
        }
        
        Console.WriteLine($"    Downloads:       {sub.Downloads}");
        Console.WriteLine($"    Created At:      {sub.CreatedAt}");
        Console.WriteLine($"    Updated At:      {sub.UpdatedAt}");
        Console.WriteLine("  ----------------------------------------");
    }
}
