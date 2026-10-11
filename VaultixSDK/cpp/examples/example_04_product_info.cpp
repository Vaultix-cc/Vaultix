/**
 * Example 4: Product Variables and Status
 * 
 * Demonstrates how to:
 * - Retrieve product variables (key-value pairs)
 * - Get product status information
 * - Fetch product news/announcements
 * - Use variables for application configuration
 */

#include "VaultixSDK.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>
#include <iomanip>
#include <limits>

void printBanner() {
    std::cout << "\n";
    std::cout << "================================================\n";
    std::cout << "  Vaultix SDK - Product Variables & Status\n";
    std::cout << "================================================\n";
    std::cout << "\n";
}

void printStatusWithColor(const Vaultix::VaultixClient::ProductStatusInfo& status) {
    std::cout << "  Status Name:  " << status.name << "\n";
    std::cout << "  Status Color: " << status.color << "\n";
    std::cout << "  Status Action: " << status.action << "\n";
    
    // Interpret the status
    std::cout << "\n  Interpretation:\n";
    
    if (status.name == "online" || status.name == "active") {
        std::cout << "    [OK] Product is operating normally.\n";
    } else if (status.name == "maintenance") {
        std::cout << "    [INFO] Product is under maintenance.\n";
        std::cout << "    Action to take: " << status.action << "\n";
    } else if (status.name == "update") {
        std::cout << "    [UPDATE] A new version is available!\n";
        std::cout << "    Action: " << status.action << "\n";
    } else if (status.name == "offline") {
        std::cout << "    [ERROR] Product is currently offline.\n";
        std::cout << "    Action: " << status.action << "\n";
    } else {
        std::cout << "    Unknown status: " << status.name << "\n";
    }
}

int main() {
    printBanner();

    Vaultix::VaultixClient client("https://vaultix.cc/api");
    client.SetDebugMode(true);

    // IMPORTANT: Replace these with your actual values
    // =====================================================
    const std::string appApiKey = "ap_your_app_api_key_here";
    const std::string sdkKey = "vxk_your_sdk_key_here";  // App Settings -> End-to-end encryption
    const std::string productId = "your_product_id_here";
    const std::string username = "your_username";
    const std::string password = "your_password";
    // =====================================================

    client.SetApiKey(appApiKey);
    // Opens end-to-end encrypted files and variables (all new apps).
    if (!client.SetContentKey(sdkKey)) {
        std::cerr << "Set your vxk_ SDK key (App Settings -> End-to-end encryption) to open encrypted content.\n";
    }

    // Authenticate first
    std::cout << "Authenticating...\n";
    if (!client.AuthenticateWithUsername(username, password)) {
        std::cout << "[FAILED] Authentication failed: " << client.GetLastError() << "\n";
        return 1;
    }
    std::cout << "[OK] Authentication successful!\n\n";

    // ===========================================
    // 1. Get product status
    // ===========================================
    std::cout << "--- Product Status ---\n";
    
    Vaultix::VaultixClient::ProductStatusInfo statusInfo;
    if (client.GetProductStatus(productId, statusInfo) && statusInfo.hasStatus) {
        printStatusWithColor(statusInfo);
    } else {
        std::cout << "  [INFO] No status information available.\n";
    }
    std::cout << "\n";

    // ===========================================
    // 2. Get product news
    // ===========================================
    std::cout << "--- Product News & Announcements ---\n";
    
    Vaultix::VaultixClient::ProductNewsInfo newsInfo;
    if (client.GetProductNews(productId, newsInfo) && newsInfo.hasNews) {
        std::cout << "  Headline: " << newsInfo.headline << "\n";
        std::cout << "  Content:\n";
        
        // Word wrap content at 60 characters
        std::string content = newsInfo.content;
        const int maxWidth = 60;
        std::string line;
        
        for (size_t i = 0; i < content.length(); i++) {
            char c = content[i];
            if (c == '\n' || (int)line.length() >= maxWidth) {
                if (line.length() > 0) {
                    std::cout << "    " << line << "\n";
                    line.clear();
                }
                if (c == '\n') continue;
            }
            line += c;
        }
        if (line.length() > 0) {
            std::cout << "    " << line << "\n";
        }
        
        std::cout << "\n  Updated: " << newsInfo.updatedAt << "\n";
    } else {
        std::cout << "  [INFO] No news available at this time.\n";
    }
    std::cout << "\n";

    // ===========================================
    // 3. Get product variables
    // ===========================================
    std::cout << "--- Product Variables ---\n";
    
    auto variables = client.GetProductVariables(productId);

    if (variables.empty()) {
        std::cout << "  No variables defined for this product.\n";
    } else {
        std::cout << "  Found " << variables.size() << " variable(s):\n\n";

        // Group variables by category (prefix)
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> groupedVars;

        for (const auto& var : variables) {
            std::string key = var.first;
            std::string value = var.second;

            // Try to detect common prefixes
            std::string category = "other";
            
            if (key.find("VERSION") != std::string::npos || 
                key.find("version") != std::string::npos) {
                category = "version";
            } else if (key.find("URL") != std::string::npos || 
                       key.find("url") != std::string::npos ||
                       key.find("LINK") != std::string::npos) {
                category = "urls";
            } else if (key.find("KEY") != std::string::npos || 
                       key.find("TOKEN") != std::string::npos ||
                       key.find("SECRET") != std::string::npos) {
                category = "secrets";
            } else if (key.find("DEBUG") != std::string::npos ||
                       key.find("ENABLE") != std::string::npos ||
                       key.find("DISABLED") != std::string::npos) {
                category = "flags";
            }

            groupedVars[category].push_back(var);
        }

        // Print grouped variables
        for (const auto& group : groupedVars) {
            std::string heading = group.first;
            std::transform(heading.begin(), heading.end(), heading.begin(),
                           [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            std::cout << "  [" << heading << "]\n";
            
            for (const auto& var : group.second) {
                // Mask sensitive values
                std::string displayValue = var.second;
                std::string key = var.first;
                
                bool isSensitive = (key.find("KEY") != std::string::npos ||
                                    key.find("TOKEN") != std::string::npos ||
                                    key.find("SECRET") != std::string::npos ||
                                    key.find("PASSWORD") != std::string::npos);

                if (isSensitive && displayValue.length() > 8) {
                    displayValue = displayValue.substr(0, 4) + "****" + 
                                   displayValue.substr(displayValue.length() - 4);
                }

                std::cout << "    " << var.first << " = " << displayValue << "\n";
            }
            std::cout << "\n";
        }
    }

    // ===========================================
    // 4. Use variables for application config
    // ===========================================
    std::cout << "--- Using Variables for Configuration ---\n";

    // Example: Parse version info
    for (const auto& var : variables) {
        if (var.first == "CURRENT_VERSION" || var.first == "version") {
            std::cout << "  Current version: " << var.second << "\n";
        }
        if (var.first == "MIN_VERSION" || var.first == "min_version") {
            std::cout << "  Minimum required version: " << var.second << "\n";
        }
        if (var.first == "DOWNLOAD_URL" || var.first == "download_url") {
            std::cout << "  Download URL: " << var.second << "\n";
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
