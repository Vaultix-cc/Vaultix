/**
 * Example 2: File Operations
 * 
 * Demonstrates how to work with files in the Vaultix system:
 * - List files in a product
 * - Get file information
 * - Download files to disk or memory
 * - Stream large files in chunks
 * - Verify file integrity with hash checking
 * - Download folders as zip archives
 */

#include "VaultixSDK.hpp"
#include <iostream>
#include <string>
#include <iomanip>
#include <chrono>
#include <limits>

void printBanner() {
    std::cout << "\n";
    std::cout << "================================================\n";
    std::cout << "  Vaultix SDK - File Operations Example\n";
    std::cout << "================================================\n";
    std::cout << "\n";
}

void formatFileSize(size_t bytes, std::ostream& os) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int unitIndex = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unitIndex < 4) {
        size /= 1024.0;
        unitIndex++;
    }

    os << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
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
    // 1. List all files in a product
    // ===========================================
    std::cout << "--- Getting File List ---\n";
    auto files = client.GetFileList(productId);

    if (files.empty()) {
        std::cout << "No files found in this product.\n";
    } else {
        std::cout << "Found " << files.size() << " file(s):\n\n";

        for (const auto& file : files) {
            std::cout << "  File: " << file.name << "\n";
            std::cout << "    ID:         " << file.id << "\n";
            std::cout << "    Size:       ";
            formatFileSize(file.size, std::cout);
            std::cout << "\n";
            std::cout << "    Encrypted:  " << (file.encrypted ? "Yes" : "No") << "\n";
            std::cout << "    Downloads: " << file.downloads << "\n";
            std::cout << "    Uploaded:  " << file.uploadedAt << "\n";

            if (file.encrypted) {
                std::cout << "    Key:        [ENCRYPTED]\n";
                std::cout << "    IV:         [ENCRYPTED]\n";
            }
            std::cout << "\n";
        }
    }

    // ===========================================
    // 2. Get specific file info
    // ===========================================
    if (!files.empty()) {
        std::cout << "--- Getting Specific File Info ---\n";
        std::string targetFileName = files[0].name;
        std::cout << "Fetching info for: " << targetFileName << "\n";

        auto fileInfo = client.GetFileInfo(productId, targetFileName);
        std::cout << "  File ID:   " << fileInfo.id << "\n";
        std::cout << "  File Size: ";
        formatFileSize(fileInfo.size, std::cout);
        std::cout << "\n\n";
    }

    // ===========================================
    // 3. Download file to disk
    // ===========================================
    if (!files.empty()) {
        std::cout << "--- Downloading File to Disk ---\n";
        std::string fileToDownload = files[0].name;
        std::string outputPath = "./downloads/" + fileToDownload;

        std::cout << "Downloading '" << fileToDownload << "' to '" << outputPath << "'\n";

        auto startTime = std::chrono::steady_clock::now();

        if (client.DownloadFile(productId, fileToDownload, outputPath)) {
            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            std::cout << "[OK] File downloaded successfully!\n";
            std::cout << "  Time taken: " << duration.count() << " ms\n";

            // Verify hash
            if (client.IsValidFileHash(productId, fileToDownload, outputPath)) {
                std::cout << "  Hash verification: PASSED\n";
            } else {
                std::cout << "  Hash verification: FAILED\n";
            }
        } else {
            std::cout << "[FAILED] Download failed: " << client.GetLastError() << "\n";
        }
        std::cout << "\n";
    }

    // ===========================================
    // 4. Download file to memory
    // ===========================================
    if (!files.empty()) {
        std::cout << "--- Downloading File to Memory ---\n";
        std::string fileToDownload = files[0].name;

        std::cout << "Downloading '" << fileToDownload << "' to memory...\n";

        auto fileData = client.DownloadFileToMemory(productId, fileToDownload);

        if (!fileData.empty()) {
            std::cout << "[OK] File loaded into memory!\n";
            std::cout << "  Size: ";
            formatFileSize(fileData.size(), std::cout);
            std::cout << "\n";
            std::cout << "  First 64 bytes (hex): ";

            size_t bytesToShow = std::min(size_t(64), fileData.size());
            for (size_t i = 0; i < bytesToShow; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') 
                          << static_cast<int>(fileData[i]) << " ";
            }
            std::cout << std::dec << "\n";
        } else {
            std::cout << "[FAILED] Memory download failed: " << client.GetLastError() << "\n";
        }
        std::cout << "\n";
    }

    // ===========================================
    // 5. Stream file in chunks
    // ===========================================
    if (!files.empty() && files[0].size > 1024) {
        std::cout << "--- Streaming File in Chunks ---\n";
        std::string fileToStream = files[0].name;

        size_t totalReceived = 0;
        size_t chunkCount = 0;

        std::cout << "Streaming '" << fileToStream << "'...\n";

        if (client.StreamFile(productId, fileToStream,
            [&totalReceived, &chunkCount](const std::vector<uint8_t>& chunk, size_t received, size_t total) {
                totalReceived = received;
                chunkCount++;

                std::cout << "\r  Progress: " 
                          << std::fixed << std::setprecision(1)
                          << (static_cast<double>(received) / total * 100.0) 
                          << "% (" << chunkCount << " chunks)";
                std::cout.flush();
            })) {
            std::cout << "\n[OK] Stream completed!\n";
            std::cout << "  Total chunks: " << chunkCount << "\n";
        } else {
            std::cout << "\n[FAILED] Streaming failed: " << client.GetLastError() << "\n";
        }
        std::cout << "\n";
    }

    // ===========================================
    // 6. List and download folders
    // ===========================================
    std::cout << "--- Folder Operations ---\n";
    auto folders = client.GetFolderList(productId);

    if (folders.empty()) {
        std::cout << "No folders found in this product.\n";
    } else {
        std::cout << "Found " << folders.size() << " folder(s):\n\n";

        for (const auto& folder : folders) {
            std::cout << "  Folder: " << folder.name << "\n";
            std::cout << "    ID:         " << folder.id << "\n";
            std::cout << "    File Count: " << folder.fileCount << "\n";
            std::cout << "    Total Size: ";
            formatFileSize(folder.totalSize, std::cout);
            std::cout << "\n\n";

            // Download the first folder
            std::cout << "Downloading folder '" << folder.name << "' as zip...\n";
            std::string zipPath = "./downloads/" + folder.name + ".zip";

            if (client.DownloadFolder(productId, folder.name, zipPath)) {
                std::cout << "[OK] Folder downloaded successfully!\n";
                std::cout << "  Saved to: " << zipPath << "\n";
            } else {
                std::cout << "[FAILED] Folder download failed: " << client.GetLastError() << "\n";
            }
            std::cout << "\n";
            break; // Only download first folder for demo
        }
    }

    // End session
    client.EndSession();

    std::cout << "================================================\n";
    std::cout << "Example completed.\n";
    std::cout << "================================================\n";

#ifdef _WIN32
    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
#endif

    return 0;
}
