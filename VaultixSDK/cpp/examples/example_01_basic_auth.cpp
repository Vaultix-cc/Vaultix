/**
 * Example 1: Basic Authentication
 * 
 * Demonstrates how to authenticate with the Vaultix API using two methods:
 * 1. Username/Password authentication
 * 2. License key authentication
 * 
 * This is typically the first step before using any other API features.
 */

#include "VaultixSDK.hpp"
#include <iostream>
#include <string>
#include <limits>

void printBanner() {
    std::cout << "\n";
    std::cout << "================================================\n";
    std::cout << "  Vaultix SDK - Basic Authentication Example\n";
    std::cout << "================================================\n";
    std::cout << "\n";
}

void printSessionInfo(const Vaultix::Session& session) {
    std::cout << "\n  Session Information:\n";
    std::cout << "  ----------------------------------------\n";
    std::cout << "    App ID:       " << session.appId << "\n";
    std::cout << "    Session ID:   " << session.sessionId << "\n";
    std::cout << "    HWID:         " << session.hwid << "\n";
    std::cout << "    Token Expires: " << session.tokenExpiry << "\n";
    std::cout << "    User ID:      " << session.appUser.id << "\n";
    std::cout << "    Username:     " << session.appUser.username << "\n";
    std::cout << "  ----------------------------------------\n";
}

int main() {
    printBanner();

    // Initialize the client with the default API URL
    Vaultix::VaultixClient client("https://vaultix.cc/api");
    client.SetDebugMode(true);

    // IMPORTANT: Replace these with your actual credentials
    // =====================================================
    const std::string appApiKey = "ap_your_app_api_key_here";
    const std::string productId = "your_product_id_here";
    // =====================================================

    // Set the application API key
    client.SetApiKey(appApiKey);

    std::cout << "Choose authentication method:\n";
    std::cout << "  1. Username/Password\n";
    std::cout << "  2. License Key\n";
    std::cout << "\nEnter choice (1 or 2): ";

    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    bool authenticated = false;

    if (choice == 1) {
        // ===========================================
        // Method 1: Username/Password Authentication
        // ===========================================
        std::cout << "\n--- Username/Password Authentication ---\n\n";

        std::string username, password;

        std::cout << "Enter username: ";
        std::getline(std::cin, username);

        std::cout << "Enter password: ";
        std::getline(std::cin, password);

        std::cout << "\nAuthenticating...\n";

        if (client.AuthenticateWithUsername(username, password)) {
            std::cout << "\n[SUCCESS] Authentication successful!\n";
            std::cout << "  A session token has been created.\n";
            std::cout << "  The token will expire in 7 days.\n";
            authenticated = true;
        } else {
            std::cout << "\n[FAILED] Authentication failed!\n";
            std::cout << "  Error: " << client.GetLastError() << "\n";
        }

    } else if (choice == 2) {
        // ===========================================
        // Method 2: License Key Authentication
        // ===========================================
        std::cout << "\n--- License Key Authentication ---\n\n";

        std::string licenseKey;

        std::cout << "Enter license key (format: XXXX-XXXX-XXXX-XXXX): ";
        std::getline(std::cin, licenseKey);

        std::cout << "\nAuthenticating...\n";

        if (client.AuthenticateWithKey(licenseKey)) {
            std::cout << "\n[SUCCESS] Authentication successful!\n";
            std::cout << "  A session token has been created.\n";
            std::cout << "  The token will expire in 7 days.\n";
            authenticated = true;
        } else {
            std::cout << "\n[FAILED] Authentication failed!\n";
            std::cout << "  Error: " << client.GetLastError() << "\n";
        }

    } else {
        std::cout << "\n[ERROR] Invalid choice!\n";
    }

    if (authenticated) {
        // Display session information
        auto session = client.GetCurrentSession();
        printSessionInfo(session);

        // Check product access
        std::cout << "\nProduct Access Check:\n";
        if (client.HasProductAccess(productId)) {
            std::cout << "  [OK] You have access to product: " << productId << "\n";
        } else {
            std::cout << "  [WARN] You don't have access to this product.\n";
        }

        // Get user's products
        std::cout << "\nYour Products:\n";
        auto products = client.GetUserProducts();
        if (!products.empty()) {
            for (const auto& product : products) {
                std::cout << "  - " << product.at("name") 
                          << " (ID: " << product.at("id") << ")\n";
            }
        } else {
            std::cout << "  No products found.\n";
        }

        // End the session
        std::cout << "\nEnding session...\n";
        client.EndSession();
        std::cout << "[OK] Session ended.\n";
    }

    std::cout << "\n================================================\n";
    std::cout << "Example completed.\n";
    std::cout << "================================================\n";

#ifdef _WIN32
    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
#endif

    return 0;
}
