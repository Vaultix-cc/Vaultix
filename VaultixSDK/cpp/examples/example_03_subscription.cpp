/**
 * Example 3: Subscription Management
 * 
 * Demonstrates how to manage user subscriptions:
 * - Get subscription details for a product
 * - Check subscription status (active, paused, expired)
 * - Get subscription expiration dates
 * - View download counts
 */

#include "VaultixSDK.hpp"
#include <iostream>
#include <string>
#include <iomanip>
#include <limits>

void printBanner() {
    std::cout << "\n";
    std::cout << "================================================\n";
    std::cout << "  Vaultix SDK - Subscription Management Example\n";
    std::cout << "================================================\n";
    std::cout << "\n";
}

void printSubscriptionInfo(const Vaultix::SubscriptionInfo& sub) {
    std::cout << "  ----------------------------------------\n";
    std::cout << "    Subscription ID: " << sub.subscriptionId << "\n";
    std::cout << "    User ID:         " << sub.appUserId << "\n";
    std::cout << "    Product ID:      " << sub.productId << "\n";
    std::cout << "    Status:          " << sub.status << "\n";
    std::cout << "    Expires At:      " << (sub.expiresAt.empty() ? "Lifetime" : sub.expiresAt) << "\n";
    std::cout << "    Is Paused:       " << (sub.isPaused ? "Yes" : "No") << "\n";
    
    if (sub.isPaused) {
        std::cout << "    Paused At:       " << sub.pausedAt << "\n";
        std::cout << "    Paused Until:     " << sub.pausedUntil << "\n";
    }
    
    std::cout << "    Downloads:       " << sub.downloads << "\n";
    std::cout << "    Created At:      " << sub.createdAt << "\n";
    std::cout << "    Updated At:      " << sub.updatedAt << "\n";
    std::cout << "  ----------------------------------------\n";
}

void printStatusBadge(const std::string& status) {
    std::string badge;
    std::string color;

    if (status == "active") {
        badge = "[ACTIVE]";
        color = "\033[32m"; // Green
    } else if (status == "paused") {
        badge = "[PAUSED]";
        color = "\033[33m"; // Yellow
    } else if (status == "expired") {
        badge = "[EXPIRED]";
        color = "\033[31m"; // Red
    } else {
        badge = "[" + status + "]";
        color = "\033[0m"; // Default
    }

    std::cout << color << badge << "\033[0m";
}

int main() {
    printBanner();

    Vaultix::VaultixClient client("https://vaultix.cc/api");
    client.SetDebugMode(true);

    // IMPORTANT: Replace these with your actual values
    // =====================================================
    const std::string appApiKey = "ap_your_app_api_key_here";
    const std::string productId = "your_product_id_here";
    const std::string username = "your_username";
    const std::string password = "your_password";
    // =====================================================

    client.SetApiKey(appApiKey);

    // Authenticate first
    std::cout << "Authenticating...\n";
    if (!client.AuthenticateWithUsername(username, password)) {
        std::cout << "[FAILED] Authentication failed: " << client.GetLastError() << "\n";
        return 1;
    }
    std::cout << "[OK] Authentication successful!\n\n";

    // ===========================================
    // 1. Get all user products
    // ===========================================
    std::cout << "--- Your Products ---\n";
    auto products = client.GetUserProducts();

    if (products.empty()) {
        std::cout << "You don't have access to any products.\n";
        client.EndSession();
        return 0;
    }

    std::cout << "You have access to " << products.size() << " product(s):\n\n";

    for (size_t i = 0; i < products.size(); i++) {
        const auto& product = products[i];
        std::cout << "  " << (i + 1) << ". " << product.at("name") << "\n";
        std::cout << "     ID:   " << product.at("id") << "\n";
    }
    std::cout << "\n";

    // ===========================================
    // 2. Get subscription for a specific product
    // ===========================================
    std::cout << "--- Subscription Details for " << productId << " ---\n";

    auto subscription = client.GetUserSubscriptionByProduct(productId);

    if (!subscription.subscriptionId.empty()) {
        printSubscriptionInfo(subscription);

        // ===========================================
        // 3. Check subscription validity
        // ===========================================
        std::cout << "\n--- Subscription Validity Check ---\n";

        bool isValid = !subscription.isPaused && 
                       (subscription.expiresAt.empty() || 
                        subscription.status == "active");

        if (isValid) {
            std::cout << "  [OK] Your subscription is valid!\n";
        } else {
            std::cout << "  [WARN] Your subscription has issues:\n";
            
            if (subscription.isPaused) {
                std::cout << "    - Subscription is paused\n";
            }
            if (subscription.status == "expired") {
                std::cout << "    - Subscription has expired\n";
            }
        }

        // ===========================================
        // 4. Download allowance check
        // ===========================================
        std::cout << "\n--- Download Allowance ---\n";
        std::cout << "  Downloads used: " << subscription.downloads << "\n";
        
        if (subscription.downloads < 1000) {
            std::cout << "  Downloads remaining: Unlimited (no restrictions)\n";
        } else {
            std::cout << "  Consider monitoring your download usage.\n";
        }

    } else {
        std::string error = client.GetLastError();
        if (error.find("No subscription found") != std::string::npos) {
            std::cout << "  [INFO] No active subscription found for this product.\n";
            std::cout << "  Please purchase or activate a subscription to access content.\n";
        } else {
            std::cout << "  [ERROR] Failed to retrieve subscription: " << error << "\n";
        }
    }

    // ===========================================
    // 5. Check access for all products
    // ===========================================
    std::cout << "\n--- Access Check for All Products ---\n";

    for (const auto& product : products) {
        const std::string& pid = product.at("id");
        bool hasAccess = client.HasProductAccess(pid);
        
        std::cout << "  " << product.at("name") << ": ";
        if (hasAccess) {
            std::cout << "[OK] Has access\n";
        } else {
            std::cout << "[NO ACCESS]\n";
        }
    }

    // End session
    client.EndSession();

    std::cout << "\n================================================\n";
    std::cout << "Example completed.\n";
    std::cout << "================================================\n";

#ifdef _WIN32
    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
#endif

    return 0;
}
