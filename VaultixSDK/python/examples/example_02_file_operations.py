#!/usr/bin/env python3
"""
Example 2: File Operations

Demonstrates how to work with files in the Vaultix system:
- Get file information
- Download files to disk or memory (end-to-end encrypted apps need the content key)
- Stream a file in chunks
- Verify file integrity with hash checking
- Download folders as zip archives
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultix import VaultixClient


# Configuration - Replace with your actual values
APP_API_KEY = "ap_your_app_api_key_here"
SDK_KEY = "vxk_your_sdk_key_here"  # App Settings -> End-to-end encryption
PRODUCT_ID = "your_product_id_here"
FILE_NAME = "your_file_name_here"
FOLDER_NAME = "your_folder_name_here"
USERNAME = "your_username"
PASSWORD = "your_password"


def print_banner():
    print("\n" + "=" * 50)
    print("  Vaultix SDK - File Operations Example")
    print("=" * 50 + "\n")


def format_file_size(bytes_size):
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(bytes_size)

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.2f} {units[unit_index]}"


async def main():
    print_banner()

    client = VaultixClient("https://vaultix.cc/api")
    client.debug_mode = True

    client.set_api_key(APP_API_KEY)
    # Opens end-to-end encrypted files, folders and variables (all new apps).
    if not client.set_content_key(SDK_KEY):
        print("Set your vxk_ SDK key (App Settings -> End-to-end encryption) to open encrypted content.")
    else:
        print(f"Content key fingerprint: {client.get_content_key_fingerprint()} (compare with App Settings)")

    # Authenticate first
    print("Authenticating...")
    if not await client.authenticate_with_username(USERNAME, PASSWORD):
        print(f"[FAILED] Authentication failed: {client.get_last_error()}")
        return

    print("[OK] Authentication successful!\n")

    # 1. Get file info
    print("--- Getting File Info ---")
    file_info = await client.get_file_info(PRODUCT_ID, FILE_NAME)
    if file_info:
        print(f"  File ID:   {file_info.id}")
        print(f"  File Size: {format_file_size(file_info.size)}")
        print(f"  End-to-end encrypted: {'Yes' if file_info.enc == 'zk1' else 'No'}")
    else:
        print(f"  [FAILED] {client.get_last_error()}")
    print()

    # 2. Download file to disk (written to "<path>.vxpart" and renamed only after every check)
    print("--- Downloading File to Disk ---")
    output_path = f"./downloads/{FILE_NAME}"
    print(f"Downloading '{FILE_NAME}' to '{output_path}'")

    if await client.download_file(PRODUCT_ID, FILE_NAME, output_path):
        print("[OK] File downloaded successfully!")
        signed_at = client.get_last_signed_at()
        if signed_at:
            print(f"  Signed at (Unix ms): {signed_at}")

        # Verify hash
        if await client.is_valid_file_hash(PRODUCT_ID, FILE_NAME, output_path):
            print("  Hash verification: PASSED")
        else:
            print("  Hash verification: FAILED")
    else:
        print(f"[FAILED] Download failed: {client.get_last_error()}")
    print()

    # 3. Download file to memory (b"" on any failure)
    print("--- Downloading File to Memory ---")
    file_data = await client.download_file_to_memory(PRODUCT_ID, FILE_NAME)

    if file_data or not client.get_last_error():
        print("[OK] File loaded into memory!")
        print(f"  Size: {format_file_size(len(file_data))}")
        print(f"  First 64 bytes (hex): {file_data[:64].hex()}")
    else:
        print(f"[FAILED] Memory download failed: {client.get_last_error()}")
    print()

    # 4. Stream file in chunks (verified in full before the first chunk)
    print("--- Streaming File in Chunks ---")

    def progress_callback(chunk, received, total):
        percent = (received / total * 100) if total > 0 else 0
        print(f"\r  Progress: {percent:.1f}% ({received} / {total} bytes)", end="")

    if await client.stream_file(PRODUCT_ID, FILE_NAME, progress_callback):
        print()
        print("[OK] Stream completed!")
    else:
        print()
        print(f"[FAILED] Streaming failed: {client.get_last_error()}")
    print()

    # 5. Download a folder as a zip archive
    print("--- Folder Operations ---")
    zip_path = f"./downloads/{FOLDER_NAME}.zip"
    print(f"Downloading folder '{FOLDER_NAME}' as zip...")

    if await client.download_folder(PRODUCT_ID, FOLDER_NAME, zip_path):
        print("[OK] Folder downloaded successfully!")
        print(f"  Saved to: {zip_path}")
    else:
        print(f"[FAILED] Folder download failed: {client.get_last_error()}")
    print()

    # End session
    client.end_session()

    print("=" * 50)
    print("Example completed.")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
