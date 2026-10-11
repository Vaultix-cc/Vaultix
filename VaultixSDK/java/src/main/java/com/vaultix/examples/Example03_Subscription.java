package com.vaultix.examples;

import com.vaultix.sdk.*;
import java.util.*;

/**
 * Example 3: Subscription Management
 * 
 * Demonstrates how to manage user subscriptions:
 * - Get subscription details for a product
 * - Check subscription status (active, paused, expired)
 * - Get subscription expiration dates
 * - View download counts
 */
public class Example03_Subscription {
    
    private static final String APP_API_KEY = "ap_your_app_api_key_here";
    private static final String PRODUCT_ID = "your_product_id_here";
    private static final String USERNAME = "your_username";
    private static final String PASSWORD = "your_password";
    
    public static void main(String[] args) {
        printBanner();
        
        try (VaultixClient client = new VaultixClient("https://vaultix.cc/api")) {
            client.setDebugMode(true);
            client.setApiKey(APP_API_KEY);
            
            // Authenticate first
            System.out.println("Authenticating...");
            if (!client.authenticateWithUsername(USERNAME, PASSWORD)) {
                System.out.println("[FAILED] Authentication failed: " + client.getLastError());
                return;
            }
            System.out.println("[OK] Authentication successful!");
            System.out.println();
            
            // 1. Get all user products
            System.out.println("--- Your Products ---");
            List<Map<String, String>> products = client.getUserProducts();
            
            if (products.isEmpty()) {
                System.out.println("You don't have access to any products.");
                client.endSession();
                return;
            }
            
            System.out.println("You have access to " + products.size() + " product(s):");
            System.out.println();
            
            for (int i = 0; i < products.size(); i++) {
                Map<String, String> product = products.get(i);
                System.out.println("  " + (i + 1) + ". " + product.get("name"));
                System.out.println("     ID:   " + product.get("id"));
            }
            System.out.println();
            
            // 2. Get subscription for a specific product
            System.out.println("--- Subscription Details for " + PRODUCT_ID + " ---");
            
            SubscriptionInfo subscription = client.getUserSubscriptionByProduct(PRODUCT_ID);
            
            if (!subscription.getSubscriptionId().isEmpty()) {
                printSubscriptionInfo(subscription);
                
                // 3. Check subscription validity
                System.out.println();
                System.out.println("--- Subscription Validity Check ---");
                
                boolean isValid = subscription.isActive();
                
                if (isValid) {
                    System.out.println("  [OK] Your subscription is valid!");
                } else {
                    System.out.println("  [WARN] Your subscription has issues:");
                    
                    if (subscription.isPaused()) {
                        System.out.println("    - Subscription is paused");
                    }
                    if ("expired".equals(subscription.getStatus())) {
                        System.out.println("    - Subscription has expired");
                    }
                }
                
                // 4. Download allowance check
                System.out.println();
                System.out.println("--- Download Allowance ---");
                System.out.println("  Downloads used: " + subscription.getDownloads());
                
                if (subscription.getDownloads() < 1000) {
                    System.out.println("  Downloads remaining: Unlimited (no restrictions)");
                } else {
                    System.out.println("  Consider monitoring your download usage.");
                }
                
            } else {
                String error = client.getLastError();
                if (error.contains("No subscription found")) {
                    System.out.println("  [INFO] No active subscription found for this product.");
                    System.out.println("  Please purchase or activate a subscription to access content.");
                } else {
                    System.out.println("  [ERROR] Failed to retrieve subscription: " + error);
                }
            }
            
            // 5. Check access for all products
            System.out.println();
            System.out.println("--- Access Check for All Products ---");
            
            for (Map<String, String> product : products) {
                String pid = product.get("id");
                boolean hasAccess = client.hasProductAccess(pid);
                
                System.out.print("  " + product.get("name") + ": ");
                if (hasAccess) {
                    System.out.println("[OK] Has access");
                } else {
                    System.out.println("[NO ACCESS]");
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
        System.out.println("  Vaultix SDK - Subscription Management Example");
        System.out.println("================================================");
        System.out.println();
    }
    
    private static void printSubscriptionInfo(SubscriptionInfo sub) {
        System.out.println("  ----------------------------------------");
        System.out.println("    Subscription ID: " + sub.getSubscriptionId());
        System.out.println("    User ID:         " + sub.getAppUserId());
        System.out.println("    Product ID:      " + sub.getProductId());
        System.out.println("    Status:          " + sub.getStatus());
        System.out.println("    Expires At:      " + (sub.getExpiresAt() == null ? "Lifetime" : sub.getExpiresAt()));
        System.out.println("    Is Paused:       " + (sub.isPaused() ? "Yes" : "No"));
        
        if (sub.isPaused()) {
            System.out.println("    Paused At:       " + sub.getPausedAt());
            System.out.println("    Paused Until:     " + sub.getPausedUntil());
        }
        
        System.out.println("    Downloads:       " + sub.getDownloads());
        System.out.println("    Created At:      " + sub.getCreatedAt());
        System.out.println("    Updated At:      " + sub.getUpdatedAt());
        System.out.println("  ----------------------------------------");
    }
}
