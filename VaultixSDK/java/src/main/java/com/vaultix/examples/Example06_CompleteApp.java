package com.vaultix.examples;

import com.vaultix.sdk.*;
import java.util.*;

/**
 * Example 6: Complete Application Integration
 * 
 * A comprehensive example showing how to integrate the Vaultix SDK
 * into a real application with proper error handling, security,
 * and best practices.
 */
public class Example06_CompleteApp {
    
    // Configuration
    private static final String APP_API_KEY = "ap_your_app_api_key_here";
    private static final String CONTENT_KEY = "vxk_your_sdk_key_here";  // App Settings -> End-to-end encryption
    private static final String PRODUCT_ID = "your_product_id_here";
    private static final String FILE_NAME = "your_file_name_here";
    private static final String USERNAME = "your_username";
    private static final String PASSWORD = "your_password";
    
    public static void main(String[] args) {
        printBanner();
        
        // Step 1: Load Configuration
        printInfo("Loading application configuration...");
        
        if (APP_API_KEY.isEmpty() || PRODUCT_ID.isEmpty()) {
            printError("Configuration is incomplete. Please set your API key and product ID.");
            return;
        }
        
        // Step 2: Initialize Client
        printInfo("Initializing Vaultix client...");
        
        try (VaultixClient client = new VaultixClient("https://vaultix.cc/api")) {
            client.setDebugMode(true);
            client.setApiKey(APP_API_KEY);
            // Needed for apps with end-to-end encryption (all new apps).
            if (!client.setContentKey(CONTENT_KEY)) {
                printError("Invalid content key: " + client.getLastError());
                return;
            }
            
            // Enable security features
            client.setMinTlsVersion("1.2");
            // Note: In production, you should enable certificate pinning
            // client.enableCertificatePinning(Arrays.asList("your-certificate-sha256-hash"));
            
            // Step 3: Authenticate
            printInfo("Authenticating user...");
            
            boolean authenticated = false;
            
            // Try auto-login first
            if (client.tryAutoLogin()) {
                printSuccess("Auto-login successful!");
                authenticated = true;
            }
            // Fall back to manual login
            else if (client.authenticateWithUsername(USERNAME, PASSWORD)) {
                printSuccess("Manual authentication successful!");
                authenticated = true;
            }
            // Try key authentication
            else {
                System.out.println();
                System.out.print("Enter license key (or press Enter to skip): ");
                Scanner scanner = new Scanner(System.in);
                String licenseKey = scanner.nextLine();
                
                if (!licenseKey.isEmpty()) {
                    if (client.authenticateWithKey(licenseKey)) {
                        printSuccess("License key authentication successful!");
                        authenticated = true;
                    }
                }
            }
            
            if (!authenticated) {
                printError("Authentication failed: " + client.getLastError());
                return;
            }
            
            // Step 4: Check Authorization
            printInfo("Checking product access and subscription...");
            
            if (!checkAuthorization(client, PRODUCT_ID)) {
                printError("Authorization check failed");
                client.endSession();
                return;
            }
            
            printSuccess("User is authorized!");
            
            SubscriptionInfo subscription = client.getUserSubscriptionByProduct(PRODUCT_ID);
            System.out.println("  Subscription: " + subscription.getStatus());
            System.out.println("  Downloads used: " + subscription.getDownloads());
            
            // Step 5: Get Product Information
            printInfo("Fetching product information...");
            
            // Check product status
            ProductStatusInfo status = client.getProductStatus(PRODUCT_ID);
            if (status.hasStatus()) {
                System.out.println("  Product status: " + status.getName());
                
                if ("maintenance".equals(status.getName()) || "offline".equals(status.getName())) {
                    printError("Product is currently unavailable: " + status.getAction());
                    client.endSession();
                    return;
                }
            }
            
            // Get product variables
            Map<String, String> variables = client.getProductVariables(PRODUCT_ID);
            System.out.println("  Product has " + variables.size() + " variable(s)");
            
            // Step 6: Download a File (verified before it is saved)
            printInfo("Downloading " + FILE_NAME + "...");

            String outputPath = "./downloads/" + FILE_NAME;
            if (downloadWithRetry(client, PRODUCT_ID, FILE_NAME, outputPath)) {
                printSuccess("File downloaded successfully!");
                System.out.println("  Saved to: " + outputPath);
                if (client.getLastSignedAt() > 0) {
                    System.out.println("  Signed at (Unix ms): " + client.getLastSignedAt());
                }

                // Verify hash
                if (client.isValidFileHash(PRODUCT_ID, FILE_NAME, outputPath)) {
                    System.out.println("  Hash verification: PASSED");
                } else {
                    System.out.println("  Hash verification: FAILED");
                }
            } else {
                printError("Failed to download file after 3 attempts");
            }

            // Step 7: Cleanup
            printInfo("Cleaning up...");
            client.endSession();
            
            printSuccess("Application completed successfully!");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        System.out.println();
        System.out.println("================================================");
        System.out.println("Thank you for using Vaultix SDK!");
        System.out.println("================================================");
    }
    
    private static void printBanner() {
        System.out.println();
        System.out.println("================================================");
        System.out.println("  Vaultix SDK - Complete Integration Example");
        System.out.println("================================================");
        System.out.println();
    }
    
    private static void printError(String message) {
        System.out.println();
        System.out.println("[ERROR] " + message);
    }
    
    private static void printSuccess(String message) {
        System.out.println();
        System.out.println("[SUCCESS] " + message);
    }
    
    private static void printInfo(String message) {
        System.out.println();
        System.out.println("[INFO] " + message);
    }
    
    private static boolean checkAuthorization(VaultixClient client, String productId) {
        if (!client.isSessionValid()) {
            printError("Session is not valid");
            return false;
        }
        
        if (!client.hasProductAccess(productId)) {
            printError("User does not have access to this product");
            return false;
        }
        
        return true;
    }
    
    private static boolean downloadWithRetry(
            VaultixClient client, 
            String productId, 
            String fileName, 
            String outputPath) {
        
        int maxRetries = 3;
        
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            System.out.println("  Attempt " + attempt + "/" + maxRetries + "...");
            
            if (client.downloadFile(productId, fileName, outputPath)) {
                return true;
            }
            
            System.out.println("  Failed: " + client.getLastError());
            
            if (attempt < maxRetries) {
                System.out.println("  Retrying in 2 seconds...");
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        
        return false;
    }
}
