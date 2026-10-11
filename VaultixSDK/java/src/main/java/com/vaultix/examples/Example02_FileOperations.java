package com.vaultix.examples;

import com.vaultix.sdk.*;
import java.io.ByteArrayOutputStream;

/**
 * Example 2: File Operations
 *
 * Demonstrates how to work with files in the Vaultix system:
 * - Get file information
 * - Download files to disk or memory (end-to-end encrypted or not)
 * - Stream a verified file in chunks
 * - Verify file integrity with hash checking
 * - Download folders as zip archives
 */
public class Example02_FileOperations {

    private static final String APP_API_KEY = "ap_your_app_api_key_here";
    private static final String CONTENT_KEY = "vxk_your_sdk_key_here";  // App Settings -> End-to-end encryption
    private static final String PRODUCT_ID = "your_product_id_here";
    private static final String FILE_NAME = "your_file_name_here";
    private static final String FOLDER_NAME = "your_folder_name_here";
    private static final String USERNAME = "your_username";
    private static final String PASSWORD = "your_password";

    public static void main(String[] args) {
        printBanner();

        try (VaultixClient client = new VaultixClient("https://vaultix.cc/api")) {
            client.setDebugMode(true);
            client.setApiKey(APP_API_KEY);
            // Opens end-to-end encrypted files, folders and variables (all new apps).
            if (!client.setContentKey(CONTENT_KEY)) {
                System.out.println("[WARN] Set your vxk_ content key (App Settings -> End-to-end encryption).");
            } else {
                System.out.println("Content key fingerprint: " + client.getContentKeyFingerprint()
                        + " (compare it with App Settings)");
            }

            // Authenticate first
            System.out.println("Authenticating...");
            if (!client.authenticateWithUsername(USERNAME, PASSWORD)) {
                System.out.println("[FAILED] Authentication failed: " + client.getLastError());
                return;
            }
            System.out.println("[OK] Authentication successful!");
            System.out.println();

            // 1. File information
            System.out.println("--- File Info ---");
            FileInfo fileInfo = client.getFileInfo(PRODUCT_ID, FILE_NAME);
            if (fileInfo != null) {
                System.out.println("  File ID:   " + fileInfo.getId());
                System.out.println("  File Size: " + formatFileSize(fileInfo.getSize()));
                System.out.println("  Uploaded:  " + fileInfo.getUploadedAt());
            } else {
                System.out.println("[FAILED] " + client.getLastError());
            }
            System.out.println();

            // 2. Download to disk: written to <path>.vxpart, renamed only after every check passed
            System.out.println("--- Downloading File to Disk ---");
            String outputPath = "./downloads/" + FILE_NAME;
            if (client.downloadFile(PRODUCT_ID, FILE_NAME, outputPath)) {
                System.out.println("[OK] Saved to " + outputPath);
                if (client.getLastSignedAt() > 0) {
                    System.out.println("  Signed at (Unix ms): " + client.getLastSignedAt());
                }
                // Keyed hash with a content key, plain SHA-256 for apps without end-to-end encryption
                System.out.println("  Hash verification: "
                        + (client.isValidFileHash(PRODUCT_ID, FILE_NAME, outputPath) ? "PASSED" : "FAILED"));
            } else {
                System.out.println("[FAILED] Download failed: " + client.getLastError());
            }
            System.out.println();

            // 3. Download to memory: an empty array on failure, getLastError() is "" on success
            System.out.println("--- Downloading File to Memory ---");
            byte[] fileData = client.downloadFileToMemory(PRODUCT_ID, FILE_NAME);
            if (client.getLastError().isEmpty()) {
                System.out.println("[OK] " + formatFileSize(fileData.length) + " in memory");
                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < Math.min(16, fileData.length); i++) {
                    hex.append(String.format("%02X ", fileData[i]));
                }
                System.out.println("  First bytes (hex): " + hex);
            } else {
                System.out.println("[FAILED] Memory download failed: " + client.getLastError());
            }
            System.out.println();

            // 4. Stream: the file is verified first, then handed out in 4 KB chunks
            System.out.println("--- Streaming File ---");
            ByteArrayOutputStream streamed = new ByteArrayOutputStream();
            boolean ok = client.streamFile(PRODUCT_ID, FILE_NAME, (chunk, received, total) -> {
                streamed.write(chunk, 0, chunk.length);
            });
            System.out.println(ok ? "[OK] Streamed " + formatFileSize(streamed.size())
                                  : "[FAILED] " + client.getLastError());
            System.out.println();

            // 5. Folders arrive as zip archives
            System.out.println("--- Folder Operations ---");
            FolderInfo folder = client.getFolderInfo(PRODUCT_ID, FOLDER_NAME);
            if (folder != null) {
                System.out.println("  Folder: " + folder.getName() + " (" + folder.getFileCount() + " files)");
                String zipPath = "./downloads/" + FOLDER_NAME + ".zip";
                if (client.downloadFolder(PRODUCT_ID, FOLDER_NAME, zipPath)) {
                    System.out.println("[OK] Saved to " + zipPath);
                } else {
                    System.out.println("[FAILED] Folder download failed: " + client.getLastError());
                }
                byte[] zip = client.downloadFolderToMemory(PRODUCT_ID, FOLDER_NAME);
                if (client.getLastError().isEmpty()) {
                    System.out.println("[OK] Zip in memory: " + formatFileSize(zip.length));
                }
            } else {
                System.out.println("[FAILED] " + client.getLastError());
            }

            client.endSession();

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("================================================");
        System.out.println("Example completed.");
        System.out.println("================================================");
    }

    private static void printBanner() {
        System.out.println();
        System.out.println("================================================");
        System.out.println("  Vaultix SDK - File Operations Example");
        System.out.println("================================================");
        System.out.println();
    }

    private static String formatFileSize(long bytes) {
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int unitIndex = 0;
        double size = bytes;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return String.format("%.2f %s", size, units[unitIndex]);
    }
}
