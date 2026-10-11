package com.vaultix.examples;

import com.vaultix.sdk.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Example 5: Auto-Login and Session Persistence
 * 
 * Demonstrates how to implement seamless re-authentication:
 * - Try auto-login with saved session token
 * - Handle token refresh automatically
 * - Properly manage logout (clear or keep token)
 * - Build user-friendly authentication flows
 */
public class Example05_AutoLogin {
    
    private static final String APP_API_KEY = "ap_your_app_api_key_here";
    private static final String USERNAME = "your_username";
    private static final String PASSWORD = "your_password";
    
    public static void main(String[] args) {
        printBanner();
        
        try (VaultixClient client = new VaultixClient("https://vaultix.cc/api")) {
            client.setDebugMode(true);
            client.setApiKey(APP_API_KEY);
            
            printAuthFlow("Starting Authentication Flow");
            
            // Step 1: Try Auto-Login First
            System.out.println();
            System.out.println("Step 1: Attempting auto-login...");
            System.out.println("  (This uses a previously saved session token)");
            
            boolean authenticated = false;
            
            if (client.tryAutoLogin()) {
                printAuthFlow("Auto-login SUCCESSFUL!");
                System.out.println("  Welcome back! Your session has been restored.");
                System.out.println("  No need to enter credentials again.");
                authenticated = true;
            } else {
                System.out.println("Auto-login not available or failed.");
                System.out.println("  Reason: " + client.getLastError());
                System.out.println("  This is normal for first-time users.");
                
                // Step 2: Manual Authentication
                System.out.println();
                System.out.println("Step 2: Performing manual authentication...");
                System.out.println("  (This is only needed if auto-login failed)");
                
                if (client.authenticateWithUsername(USERNAME, PASSWORD)) {
                    printAuthFlow("Manual authentication SUCCESSFUL!");
                    System.out.println("  If the app allows auto-login, a token for future auto-logins");
                    System.out.println("  was saved on this machine (valid for 7 days).");
                    authenticated = true;
                } else {
                    printAuthFlow("Manual authentication FAILED!");
                    System.out.println("  Error: " + client.getLastError());
                    return;
                }
            }
            
            if (authenticated) {
                // Display session info
                Session session = client.getCurrentSession();
                System.out.println();
                System.out.println("  Session restored:");
                System.out.println("    User: " + session.getAppUser().getUsername());
                System.out.println("    App:  " + session.getAppId());
                System.out.println("    HWID: " + session.getHwid());
                System.out.println("    Token expires: " + session.getTokenExpiry());
                
                // Step 3: Token Expiry Handling
                System.out.println();
                System.out.println("Step 3: Checking token expiry...");
                
                if (client.isTokenExpired()) {
                    System.out.println("  Token has expired. Attempting refresh...");
                    
                    if (client.refreshToken()) {
                        printAuthFlow("Token refresh SUCCESSFUL!");
                        System.out.println("  A new token has been obtained.");
                    } else {
                        System.out.println("  Token refresh failed.");
                        System.out.println("  User may need to re-authenticate manually.");
                    }
                } else {
                    System.out.println("  Token is still valid. No refresh needed.");
                }
                
                // Step 4: Simulate application work
                System.out.println();
                System.out.println("Step 4: Simulating application work...");
                System.out.println("  (In a real app, you would perform your operations here)");
                
                for (int i = 1; i <= 3; i++) {
                    System.out.println("  Working... " + i + "/3");
                    try {
                        TimeUnit.MILLISECONDS.sleep(300);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                
                // Step 5: Logout Options
                System.out.println();
                System.out.println("Step 5: Session cleanup options:");
                System.out.println();
                System.out.println("  Choose logout type:");
                System.out.println("    1. End Session (keep auto-login)");
                System.out.println("    2. Full Logout (clear auto-login)");
                System.out.println();
                
                Scanner scanner = new Scanner(System.in);
                System.out.print("  Enter choice (1 or 2): ");
                String choice = scanner.nextLine();
                
                System.out.println();
                
                if ("1".equals(choice)) {
                    // Soft logout - just end the session
                    client.endSession();
                    printAuthFlow("Session ended (soft logout).");
                    System.out.println("  Your auto-login token is preserved.");
                    System.out.println("  Next time you run the app, auto-login will work.");
                } else {
                    // Full logout - clear everything
                    client.clearAutoLoginToken();
                    client.endSession();
                    printAuthFlow("Full logout completed.");
                    System.out.println("  All tokens have been cleared.");
                    System.out.println("  Next launch will require manual authentication.");
                }
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        System.out.println();
        System.out.println("================================================");
        System.out.println("Example completed.");
        System.out.println("================================================");
    }
    
    private static void printBanner() {
        System.out.println();
        System.out.println("================================================");
        System.out.println("  Vaultix SDK - Auto-Login Example");
        System.out.println("================================================");
        System.out.println();
    }
    
    private static void printAuthFlow(String flow) {
        System.out.println();
        System.out.println(">>> " + flow);
    }
}
