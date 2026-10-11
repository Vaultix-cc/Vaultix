package com.vaultix.examples;

import com.vaultix.sdk.*;
import java.util.*;
import java.util.Scanner;

/**
 * Example 1: Basic Authentication
 * 
 * Demonstrates how to authenticate with the Vaultix API using two methods:
 * 1. Username/Password authentication
 * 2. License key authentication
 */
public class Example01_BasicAuth {
    
    private static final String APP_API_KEY = "ap_your_app_api_key_here";
    private static final String PRODUCT_ID = "your_product_id_here";
    
    public static void main(String[] args) {
        printBanner();
        
        try (VaultixClient client = new VaultixClient("https://vaultix.cc/api")) {
            client.setDebugMode(true);
            client.setApiKey(APP_API_KEY);
            
            Scanner scanner = new Scanner(System.in);
            
            System.out.println("Choose authentication method:");
            System.out.println("  1. Username/Password");
            System.out.println("  2. License Key");
            System.out.println();
            System.out.print("Enter choice (1 or 2): ");
            
            String choice = scanner.nextLine();
            boolean authenticated = false;
            
            if ("1".equals(choice)) {
                // Method 1: Username/Password Authentication
                System.out.println();
                System.out.println("--- Username/Password Authentication ---");
                System.out.println();
                
                System.out.print("Enter username: ");
                String username = scanner.nextLine();
                
                System.out.print("Enter password: ");
                String password = scanner.nextLine();
                
                System.out.println();
                System.out.println("Authenticating...");
                
                if (client.authenticateWithUsername(username, password)) {
                    System.out.println();
                    System.out.println("[SUCCESS] Authentication successful!");
                    System.out.println("  A session token has been created.");
                    authenticated = true;
                } else {
                    System.out.println();
                    System.out.println("[FAILED] Authentication failed!");
                    System.out.println("  Error: " + client.getLastError());
                }
                
            } else if ("2".equals(choice)) {
                // Method 2: License Key Authentication
                System.out.println();
                System.out.println("--- License Key Authentication ---");
                System.out.println();
                
                System.out.print("Enter license key (format: XXXX-XXXX-XXXX-XXXX): ");
                String licenseKey = scanner.nextLine();
                
                System.out.println();
                System.out.println("Authenticating...");
                
                if (client.authenticateWithKey(licenseKey)) {
                    System.out.println();
                    System.out.println("[SUCCESS] Authentication successful!");
                    System.out.println("  A session token has been created.");
                    authenticated = true;
                } else {
                    System.out.println();
                    System.out.println("[FAILED] Authentication failed!");
                    System.out.println("  Error: " + client.getLastError());
                }
                
            } else {
                System.out.println();
                System.out.println("[ERROR] Invalid choice!");
            }
            
            if (authenticated) {
                // Display session information
                Session session = client.getCurrentSession();
                printSessionInfo(session);
                
                // Check product access
                System.out.println();
                System.out.println("Product Access Check:");
                if (client.hasProductAccess(PRODUCT_ID)) {
                    System.out.println("  [OK] You have access to product: " + PRODUCT_ID);
                } else {
                    System.out.println("  [WARN] You don't have access to this product.");
                }
                
                // Get user's products
                System.out.println();
                System.out.println("Your Products:");
                List<Map<String, String>> products = client.getUserProducts();
                
                if (!products.isEmpty()) {
                    for (Map<String, String> product : products) {
                        System.out.println("  - " + product.get("name") + " (ID: " + product.get("id") + ")");
                    }
                } else {
                    System.out.println("  No products found.");
                }
                
                // End the session
                System.out.println();
                System.out.println("Ending session...");
                client.endSession();
                System.out.println("[OK] Session ended.");
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
        System.out.println("  Vaultix SDK - Basic Authentication Example");
        System.out.println("================================================");
        System.out.println();
    }
    
    private static void printSessionInfo(Session session) {
        System.out.println();
        System.out.println("  Session Information:");
        System.out.println("  ----------------------------------------");
        System.out.println("    App ID:       " + session.getAppId());
        System.out.println("    Session ID:   " + session.getSessionId());
        System.out.println("    HWID:         " + session.getHwid());
        System.out.println("    Token Expires: " + session.getTokenExpiry());
        System.out.println("    User ID:      " + session.getAppUser().getId());
        System.out.println("    Username:     " + session.getAppUser().getUsername());
        System.out.println("  ----------------------------------------");
    }
}
