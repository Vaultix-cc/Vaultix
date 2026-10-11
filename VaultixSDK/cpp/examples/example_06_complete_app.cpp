/**
 * Example 6: Complete Application Integration
 * 
 * A comprehensive example showing how to integrate the Vaultix SDK
 * into a real application with proper error handling, security,
 * and best practices.
 */

#include "VaultixSDK.hpp"
#include <chrono>
#include <thread>
#include <iostream>
#include <string>
#include <fstream>
#include <limits>

void printBanner() {
    std::cout << "\n";
    std::cout << "================================================\n";
    std::cout << "  Vaultix SDK - Complete Integration Example\n";
    std::cout << "================================================\n";
    std::cout << "\n";
}

void printError(const std::string& message) {
    std::cout << "\n[ERROR] " << message << "\n";
}

void printSuccess(const std::string& message) {
    std::cout << "\n[SUCCESS] " << message << "\n";
}

void printInfo(const std::string& message) {
    std::cout << "\n[INFO] " << message << "\n";
}

// Configuration structure
struct AppConfig {
    std::string apiUrl = "https://vaultix.cc/api";
    std::string appApiKey;
    std::string sdkKey;
    std::string productId;
    std::string username;
    std::string password;
    bool debugMode = false;
    std::string downloadPath = "./downloads";
};

// Load configuration from file (simulated)
AppConfig loadConfiguration() {
    AppConfig config;
    // In a real app, you would load these from a config file
    config.appApiKey = "ap_your_app_api_key_here";
    config.sdkKey = "vxk_your_sdk_key_here";  // App Settings -> End-to-end encryption
    config.productId = "your_product_id_here";
    config.username = "your_username";
    config.password = "your_password";
    config.debugMode = true;
    return config;
}

// Check if user is authorized
bool checkAuthorization(Vaultix::VaultixClient& client, const std::string& productId) {
    if (!client.IsSessionValid()) {
        printError("Session is not valid");
        return false;
    }

    if (!client.HasProductAccess(productId)) {
        printError("User does not have access to this product");
        return false;
    }

    auto subscription = client.GetUserSubscriptionByProduct(productId);
    
    if (subscription.subscriptionId.empty()) {
        printError("No subscription found for this product");
        return false;
    }

    if (subscription.isPaused) {
        printError("Subscription is currently paused");
        return false;
    }

    if (subscription.status == "expired") {
        printError("Subscription has expired");
        return false;
    }

    return true;
}

// Download with retry logic
bool downloadWithRetry(Vaultix::VaultixClient& client,
                        const std::string& productId,
                        const std::string& fileName,
                        const std::string& outputPath,
                        int maxRetries = 3) {
    
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        std::cout << "  Attempt " << attempt << "/" << maxRetries << "...\n";
        
        if (client.DownloadFile(productId, fileName, outputPath)) {
            return true;
        }
        
        std::cout << "  Failed: " << client.GetLastError() << "\n";
        
        if (attempt < maxRetries) {
            std::cout << "  Retrying in 2 seconds...\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    
    return false;
}

int main() {
    printBanner();

    // ===========================================
    // Step 1: Load Configuration
    // ===========================================
    printInfo("Loading application configuration...");
    
    AppConfig config = loadConfiguration();
    
    if (config.appApiKey.empty() || config.productId.empty()) {
        printError("Configuration is incomplete. Please set your API key and product ID.");
        return 1;
    }

    // ===========================================
    // Step 2: Initialize Client
    // ===========================================
    printInfo("Initializing Vaultix client...");
    
    Vaultix::VaultixClient client(config.apiUrl);
    client.SetDebugMode(config.debugMode);
    client.SetApiKey(config.appApiKey);
    // Opens end-to-end encrypted files and variables (all new apps).
    if (!client.SetContentKey(config.sdkKey)) {
        std::cerr << "Set your vxk_ SDK key to open encrypted content.\n";
    }

    // Enable security features
    client.SetMinTlsVersion("1.2");
    // Note: In production, you should enable certificate pinning
    // client.EnableCertificatePinning({"your-certificate-sha256-hash"});

    // ===========================================
    // Step 3: Authenticate
    // ===========================================
    printInfo("Authenticating user...");

    bool authenticated = false;

    // Try auto-login first
    if (client.TryAutoLogin()) {
        printSuccess("Auto-login successful!");
        authenticated = true;
    }
    // Fall back to manual login
    else if (client.AuthenticateWithUsername(config.username, config.password)) {
        printSuccess("Manual authentication successful!");
        authenticated = true;
    }
    // Try key authentication
    else {
        std::cout << "\nEnter license key (or press Enter to skip): ";
        std::string licenseKey;
        std::getline(std::cin, licenseKey);
        
        if (!licenseKey.empty()) {
            if (client.AuthenticateWithKey(licenseKey)) {
                printSuccess("License key authentication successful!");
                authenticated = true;
            }
        }
    }

    if (!authenticated) {
        printError("Authentication failed: " + client.GetLastError());
        return 1;
    }

    // ===========================================
    // Step 4: Check Authorization
    // ===========================================
    printInfo("Checking product access and subscription...");
    
    if (!checkAuthorization(client, config.productId)) {
        printError("Authorization check failed");
        client.EndSession();
        return 1;
    }

    printSuccess("User is authorized!");
    
    auto subscription = client.GetUserSubscriptionByProduct(config.productId);
    std::cout << "  Subscription: " << subscription.status << "\n";
    std::cout << "  Downloads used: " << subscription.downloads << "\n";

    // ===========================================
    // Step 5: Get Product Information
    // ===========================================
    printInfo("Fetching product information...");

    // Check product status
    Vaultix::VaultixClient::ProductStatusInfo status;
    if (client.GetProductStatus(config.productId, status) && status.hasStatus) {
        std::cout << "  Product status: " << status.name << "\n";
        
        if (status.name == "maintenance" || status.name == "offline") {
            printError("Product is currently unavailable: " + status.action);
            client.EndSession();
            return 1;
        }
    }

    // Get product variables
    auto variables = client.GetProductVariables(config.productId);
    std::cout << "  Product has " << variables.size() << " variable(s)\n";

    // ===========================================
    // Step 6: Download Files
    // ===========================================
    printInfo("Getting file list...");
    
    auto files = client.GetFileList(config.productId);
    
    if (files.empty()) {
        printInfo("No files available for this product");
    } else {
        std::cout << "  Found " << files.size() << " file(s)\n";
        
        // Download first file as example
        const auto& file = files[0];
        std::cout << "\n  Downloading: " << file.name << "\n";
        
        std::string outputPath = config.downloadPath + "/" + file.name;
        
        if (downloadWithRetry(client, config.productId, file.name, outputPath)) {
            printSuccess("File downloaded successfully!");
            std::cout << "  Saved to: " << outputPath << "\n";
            
            // Verify hash
            if (client.IsValidFileHash(config.productId, file.name, outputPath)) {
                std::cout << "  Hash verification: PASSED\n";
            } else {
                std::cout << "  Hash verification: FAILED\n";
            }
        } else {
            printError("Failed to download file after " + std::to_string(3) + " attempts");
        }
    }

    // ===========================================
    // Step 7: Cleanup
    // ===========================================
    printInfo("Cleaning up...");
    client.EndSession();
    
    printSuccess("Application completed successfully!");

    std::cout << "\n================================================\n";
    std::cout << "Thank you for using Vaultix SDK!\n";
    std::cout << "================================================\n";

#ifdef _WIN32
    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
#endif

    return 0;
}
