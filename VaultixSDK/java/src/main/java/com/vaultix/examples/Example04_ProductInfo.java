package com.vaultix.examples;

import com.vaultix.sdk.*;
import java.util.*;

/**
 * Example 4: Product Variables and Status
 * 
 * Demonstrates how to:
 * - Retrieve product variables (key-value pairs)
 * - Get product status information
 * - Fetch product news/announcements
 * - Use variables for application configuration
 */
public class Example04_ProductInfo {
    
    private static final String APP_API_KEY = "ap_your_app_api_key_here";
    private static final String CONTENT_KEY = "vxk_your_sdk_key_here";  // App Settings -> End-to-end encryption
    private static final String PRODUCT_ID = "your_product_id_here";
    private static final String USERNAME = "your_username";
    private static final String PASSWORD = "your_password";
    
    public static void main(String[] args) {
        printBanner();
        
        try (VaultixClient client = new VaultixClient("https://vaultix.cc/api")) {
            client.setDebugMode(true);
            client.setApiKey(APP_API_KEY);
            // End-to-end encrypted variables are opened with the content key.
            if (!client.setContentKey(CONTENT_KEY)) {
                System.out.println("[WARN] Set your vxk_ content key (App Settings -> End-to-end encryption).");
            }
            
            // Authenticate first
            System.out.println("Authenticating...");
            if (!client.authenticateWithUsername(USERNAME, PASSWORD)) {
                System.out.println("[FAILED] Authentication failed: " + client.getLastError());
                return;
            }
            System.out.println("[OK] Authentication successful!");
            System.out.println();
            
            // 1. Get product status
            System.out.println("--- Product Status ---");
            
            ProductStatusInfo statusInfo = client.getProductStatus(PRODUCT_ID);
            
            if (statusInfo.hasStatus()) {
                printStatusWithInterpretation(statusInfo);
            } else {
                System.out.println("  [INFO] No status information available.");
            }
            System.out.println();
            
            // 2. Get product news
            System.out.println("--- Product News & Announcements ---");
            
            ProductNewsInfo newsInfo = client.getProductNews(PRODUCT_ID);
            
            if (newsInfo.hasNews()) {
                System.out.println("  Headline: " + newsInfo.getHeadline());
                System.out.println("  Content:");
                
                // Word wrap content at 60 characters
                String content = newsInfo.getContent();
                String[] words = content.split(" ");
                StringBuilder line = new StringBuilder();
                
                for (String word : words) {
                    if (line.length() + word.length() + 1 > 60) {
                        System.out.println("    " + line);
                        line = new StringBuilder(word);
                    } else {
                        if (line.length() > 0) line.append(" ");
                        line.append(word);
                    }
                }
                if (line.length() > 0) {
                    System.out.println("    " + line);
                }
                
                System.out.println();
                System.out.println("  Updated: " + newsInfo.getUpdatedAt());
            } else {
                System.out.println("  [INFO] No news available at this time.");
            }
            System.out.println();
            
            // 3. Get product variables
            System.out.println("--- Product Variables ---");
            
            Map<String, String> variables = client.getProductVariables(PRODUCT_ID);
            
            if (variables.isEmpty()) {
                System.out.println(client.getLastError().isEmpty()
                        ? "  No variables defined for this product."
                        : "  [FAILED] " + client.getLastError());
            } else {
                System.out.println("  Found " + variables.size() + " variable(s):");
                System.out.println();
                
                // Group variables by category
                Map<String, List<Map.Entry<String, String>>> groupedVars = new HashMap<>();
                
                for (Map.Entry<String, String> entry : variables.entrySet()) {
                    String key = entry.getKey();
                    String category = "other";
                    
                    if (key.toUpperCase().contains("VERSION")) {
                        category = "version";
                    } else if (key.toUpperCase().contains("URL") || key.toUpperCase().contains("LINK")) {
                        category = "urls";
                    } else if (key.toUpperCase().contains("KEY") || key.toUpperCase().contains("TOKEN") || key.toUpperCase().contains("SECRET")) {
                        category = "secrets";
                    } else if (key.toUpperCase().contains("DEBUG") || key.toUpperCase().contains("ENABLE") || key.toUpperCase().contains("DISABLED")) {
                        category = "flags";
                    }
                    
                    groupedVars.computeIfAbsent(category, k -> new ArrayList<>()).add(entry);
                }
                
                // Print grouped variables
                for (Map.Entry<String, List<Map.Entry<String, String>>> group : groupedVars.entrySet()) {
                    System.out.println("  [" + group.getKey().toUpperCase() + "]");
                    
                    for (Map.Entry<String, String> var : group.getValue()) {
                        // Mask sensitive values
                        String displayValue = var.getValue();
                        boolean isSensitive = var.getKey().toUpperCase().contains("KEY") ||
                                             var.getKey().toUpperCase().contains("TOKEN") ||
                                             var.getKey().toUpperCase().contains("SECRET");
                        
                        if (isSensitive && displayValue.length() > 8) {
                            displayValue = displayValue.substring(0, 4) + "****" + displayValue.substring(displayValue.length() - 4);
                        }
                        
                        System.out.println("    " + var.getKey() + " = " + displayValue);
                    }
                    System.out.println();
                }
            }
            
            // 4. Use variables for application config
            System.out.println("--- Using Variables for Configuration ---");
            
            for (Map.Entry<String, String> entry : variables.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                
                if (key.equalsIgnoreCase("CURRENT_VERSION") || key.equalsIgnoreCase("version")) {
                    System.out.println("  Current version: " + value);
                }
                if (key.equalsIgnoreCase("MIN_VERSION") || key.equalsIgnoreCase("min_version")) {
                    System.out.println("  Minimum required version: " + value);
                }
                if (key.equalsIgnoreCase("DOWNLOAD_URL") || key.equalsIgnoreCase("download_url")) {
                    System.out.println("  Download URL: " + value);
                }
            }
            
            // End session
            client.endSession();
            
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
        System.out.println("  Vaultix SDK - Product Variables & Status");
        System.out.println("================================================");
        System.out.println();
    }
    
    private static void printStatusWithInterpretation(ProductStatusInfo status) {
        System.out.println("  Status Name:  " + status.getName());
        System.out.println("  Status Color: " + status.getColor());
        System.out.println("  Status Action: " + status.getAction());
        
        System.out.println();
        System.out.println("  Interpretation:");
        
        String name = status.getName().toLowerCase();
        if (name.equals("online") || name.equals("active")) {
            System.out.println("    [OK] Product is operating normally.");
        } else if (name.equals("maintenance")) {
            System.out.println("    [INFO] Product is under maintenance.");
            System.out.println("    Action to take: " + status.getAction());
        } else if (name.equals("update")) {
            System.out.println("    [UPDATE] A new version is available!");
            System.out.println("    Action: " + status.getAction());
        } else if (name.equals("offline")) {
            System.out.println("    [ERROR] Product is currently offline.");
            System.out.println("    Action: " + status.getAction());
        } else {
            System.out.println("    Unknown status: " + status.getName());
        }
    }
}
