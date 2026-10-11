using Vaultix.SDK;

namespace Vaultix.Examples;

/// <summary>
/// Example 5: Auto-Login and Session Persistence
/// 
/// Demonstrates how to implement seamless re-authentication:
/// - Try auto-login with saved session token
/// - Handle token refresh automatically
/// - Properly manage logout (clear or keep token)
/// - Build user-friendly authentication flows
/// </summary>
public class Example05_AutoLogin
{
    private const string AppApiKey = "ap_your_app_api_key_here";
    private const string Username = "your_username";
    private const string Password = "your_password";
    
    public static async Task Main(string[] args)
    {
        PrintBanner();
        
        using var client = new VaultixClient("https://vaultix.cc/api");
        client.DebugMode = true;
        
        client.SetApiKey(AppApiKey);
        
        PrintAuthFlow("Starting Authentication Flow");
        
        // Step 1: Try Auto-Login First
        Console.WriteLine();
        Console.WriteLine("Step 1: Attempting auto-login...");
        Console.WriteLine("  (This uses a previously saved session token)");
        
        bool authenticated = false;
        
        if (await client.TryAutoLoginAsync())
        {
            PrintAuthFlow("Auto-login SUCCESSFUL!");
            Console.WriteLine("  Welcome back! Your session has been restored.");
            Console.WriteLine("  No need to enter credentials again.");
            authenticated = true;
        }
        else
        {
            Console.WriteLine("Auto-login not available or failed.");
            Console.WriteLine($"  Reason: {client.GetLastError()}");
            Console.WriteLine("  This is normal for first-time users.");
            
            // Step 2: Manual Authentication
            Console.WriteLine();
            Console.WriteLine("Step 2: Performing manual authentication...");
            Console.WriteLine("  (This is only needed if auto-login failed)");
            
            if (await client.AuthenticateWithUsernameAsync(Username, Password))
            {
                PrintAuthFlow("Manual authentication SUCCESSFUL!");
                Console.WriteLine("  A session token has been saved for future auto-logins.");
                Console.WriteLine("  The token will remain valid for 7 days.");
                authenticated = true;
            }
            else
            {
                PrintAuthFlow("Manual authentication FAILED!");
                Console.WriteLine($"  Error: {client.GetLastError()}");
                return;
            }
        }
        
        if (authenticated)
        {
            // Display session info
            var session = client.GetCurrentSession();
            Console.WriteLine();
            Console.WriteLine("  Session restored:");
            Console.WriteLine($"    User: {session.AppUser.Username}");
            Console.WriteLine($"    App:  {session.AppId}");
            Console.WriteLine($"    HWID: {session.Hwid}");
            Console.WriteLine($"    Token expires: {session.TokenExpiry}");
            
            // Step 3: Token Expiry Handling
            Console.WriteLine();
            Console.WriteLine("Step 3: Checking token expiry...");
            
            if (await client.IsTokenExpiredAsync())
            {
                Console.WriteLine("  Token has expired. Attempting refresh...");
                
                if (await client.RefreshTokenAsync())
                {
                    PrintAuthFlow("Token refresh SUCCESSFUL!");
                    Console.WriteLine("  A new token has been obtained.");
                }
                else
                {
                    Console.WriteLine("  Token refresh failed.");
                    Console.WriteLine("  User may need to re-authenticate manually.");
                }
            }
            else
            {
                Console.WriteLine("  Token is still valid. No refresh needed.");
            }
            
            // Step 4: Simulate application work
            Console.WriteLine();
            Console.WriteLine("Step 4: Simulating application work...");
            Console.WriteLine("  (In a real app, you would perform your operations here)");
            
            for (int i = 1; i <= 3; i++)
            {
                Console.WriteLine($"  Working... {i}/3");
                await Task.Delay(300);
            }
            
            // Step 5: Logout Options
            Console.WriteLine();
            Console.WriteLine("Step 5: Session cleanup options:");
            Console.WriteLine();
            Console.WriteLine("  Choose logout type:");
            Console.WriteLine("    1. End Session (keep auto-login)");
            Console.WriteLine("    2. Full Logout (clear auto-login)");
            Console.WriteLine();
            Console.Write("  Enter choice (1 or 2): ");
            
            var choice = Console.ReadLine();
            
            Console.WriteLine();
            
            if (choice == "1")
            {
                // Soft logout - just end the session
                client.EndSession();
                PrintAuthFlow("Session ended (soft logout).");
                Console.WriteLine("  Your auto-login token is preserved.");
                Console.WriteLine("  Next time you run the app, auto-login will work.");
            }
            else
            {
                // Full logout - clear everything
                client.ClearAutoLoginToken();
                client.EndSession();
                PrintAuthFlow("Full logout completed.");
                Console.WriteLine("  All tokens have been cleared.");
                Console.WriteLine("  Next launch will require manual authentication.");
            }
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
        Console.WriteLine("  Vaultix SDK - Auto-Login Example");
        Console.WriteLine("================================================");
        Console.WriteLine();
    }
    
    private static void PrintAuthFlow(string flow)
    {
        Console.WriteLine();
        Console.WriteLine($">>> {flow}");
    }
}
