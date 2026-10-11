/**
 * Example 5: Auto-Login and Session Persistence
 * 
 * Demonstrates how to implement seamless re-authentication:
 * - Try auto-login with saved session token
 * - Handle token refresh automatically
 * - Properly manage logout (clear or keep token)
 * - Build user-friendly authentication flows
 */

#include "VaultixSDK.hpp"
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <limits>

void printBanner() {
    std::cout << "\n";
    std::cout << "================================================\n";
    std::cout << "  Vaultix SDK - Auto-Login Example\n";
    std::cout << "================================================\n";
    std::cout << "\n";
}

void printAuthFlow(const std::string& flow) {
    std::cout << "\n>>> " << flow << "\n";
}

int main() {
    printBanner();

    Vaultix::VaultixClient client("https://vaultix.cc/api");
    client.SetDebugMode(true);

    // IMPORTANT: Replace these with your actual values
    // =====================================================
    const std::string appApiKey = "ap_your_app_api_key_here";
    const std::string username = "your_username";
    const std::string password = "your_password";
    // =====================================================

    client.SetApiKey(appApiKey);

    printAuthFlow("Starting Authentication Flow");

    // ===========================================
    // Step 1: Try Auto-Login First
    // ===========================================
    std::cout << "\nStep 1: Attempting auto-login...\n";
    std::cout << "  (This uses a previously saved session token)\n";

    bool authenticated = false;

    if (client.TryAutoLogin()) {
        printAuthFlow("Auto-login SUCCESSFUL!");
        std::cout << "  Welcome back! Your session has been restored.\n";
        std::cout << "  No need to enter credentials again.\n";
        authenticated = true;
    } else {
        std::cout << "Auto-login not available or failed.\n";
        std::cout << "  Reason: " << client.GetLastError() << "\n";
        std::cout << "  This is normal for first-time users.\n";

        // ===========================================
        // Step 2: Manual Authentication
        // ===========================================
        std::cout << "\nStep 2: Performing manual authentication...\n";
        std::cout << "  (This is only needed if auto-login failed)\n";

        if (client.AuthenticateWithUsername(username, password)) {
            printAuthFlow("Manual authentication SUCCESSFUL!");
            std::cout << "  A session token has been saved for future auto-logins.\n";
            std::cout << "  The token will remain valid for 7 days.\n";
            authenticated = true;
        } else {
            printAuthFlow("Manual authentication FAILED!");
            std::cout << "  Error: " << client.GetLastError() << "\n";
            return 1;
        }
    }

    if (authenticated) {
        // Display session info
        auto session = client.GetCurrentSession();
        std::cout << "\n  Session restored:\n";
        std::cout << "    User: " << session.appUser.username << "\n";
        std::cout << "    App:  " << session.appId << "\n";
        std::cout << "    HWID: " << session.hwid << "\n";
        std::cout << "    Token expires: " << session.tokenExpiry << "\n";

        // ===========================================
        // Step 3: Token Expiry Handling
        // ===========================================
        std::cout << "\nStep 3: Checking token expiry...\n";

        if (client.IsTokenExpired()) {
            std::cout << "  Token has expired. Attempting refresh...\n";

            if (client.RefreshToken()) {
                printAuthFlow("Token refresh SUCCESSFUL!");
                std::cout << "  A new token has been obtained.\n";
            } else {
                std::cout << "  Token refresh failed.\n";
                std::cout << "  User may need to re-authenticate manually.\n";
            }
        } else {
            std::cout << "  Token is still valid. No refresh needed.\n";
        }

        // ===========================================
        // Step 4: Simulate application work
        // ===========================================
        std::cout << "\nStep 4: Simulating application work...\n";
        std::cout << "  (In a real app, you would perform your operations here)\n";

        for (int i = 1; i <= 3; i++) {
            std::cout << "  Working... " << i << "/3\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }

        // ===========================================
        // Step 5: Logout Options
        // ===========================================
        std::cout << "\nStep 5: Session cleanup options:\n";
        std::cout << "\n  Choose logout type:\n";
        std::cout << "    1. End Session (keep auto-login)\n";
        std::cout << "    2. Full Logout (clear auto-login)\n";
        std::cout << "\n  Enter choice (1 or 2): ";

        int choice;
        std::cin >> choice;

        std::cout << "\n";

        if (choice == 1) {
            // Soft logout - just end the session
            client.EndSession();
            printAuthFlow("Session ended (soft logout).");
            std::cout << "  Your auto-login token is preserved.\n";
            std::cout << "  Next time you run the app, auto-login will work.\n";
        } else {
            // Full logout - clear everything
            client.ClearAutoLoginToken();
            client.EndSession();
            printAuthFlow("Full logout completed.");
            std::cout << "  All tokens have been cleared.\n";
            std::cout << "  Next launch will require manual authentication.\n";
        }
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
