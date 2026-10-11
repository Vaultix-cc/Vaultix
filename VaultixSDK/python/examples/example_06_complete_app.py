#!/usr/bin/env python3
"""
Example 6: Complete Application Integration

A comprehensive example showing how to integrate the Vaultix SDK
into a real application with proper error handling, security,
and best practices.
"""

import asyncio
import sys
import os
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultix import VaultixClient


# Configuration structure
@dataclass
class AppConfig:
    api_url: str = "https://vaultix.cc/api"
    app_api_key: str = "ap_your_app_api_key_here"
    sdk_key: str = "vxk_your_sdk_key_here"  # App Settings -> End-to-end encryption
    product_id: str = "your_product_id_here"
    file_name: str = "your_file_name_here"
    username: str = "your_username"
    password: str = "your_password"
    debug_mode: bool = True
    download_path: str = "./downloads"


def print_banner():
    print("\n" + "=" * 50)
    print("  Vaultix SDK - Complete Integration Example")
    print("=" * 50 + "\n")


def print_error(message):
    print(f"\n[ERROR] {message}")


def print_success(message):
    print(f"\n[SUCCESS] {message}")


def print_info(message):
    print(f"\n[INFO] {message}")


async def check_authorization(client, product_id):
    """Check if user is authorized"""
    if not client.is_session_valid:
        print_error("Session is not valid")
        return False
    
    if not client.has_product_access(product_id):
        print_error("User does not have access to this product")
        return False
    
    return True


async def download_with_retry(client, product_id, file_name, output_path, max_retries=3):
    """Download with retry logic"""
    for attempt in range(1, max_retries + 1):
        print(f"  Attempt {attempt}/{max_retries}...")
        
        if await client.download_file(product_id, file_name, output_path):
            return True
        
        print(f"  Failed: {client.get_last_error()}")
        
        if attempt < max_retries:
            print("  Retrying in 2 seconds...")
            await asyncio.sleep(2)
    
    return False


async def main():
    print_banner()
    
    # Step 1: Load Configuration
    print_info("Loading application configuration...")
    
    config = AppConfig()
    
    if not config.app_api_key or not config.product_id:
        print_error("Configuration is incomplete. Please set your API key and product ID.")
        return
    
    # Step 2: Initialize Client
    print_info("Initializing Vaultix client...")
    
    client = VaultixClient(config.api_url)
    client.debug_mode = config.debug_mode
    client.set_api_key(config.app_api_key)
    # Opens end-to-end encrypted files and variables (all new apps).
    if not client.set_content_key(config.sdk_key):
        print("Set your vxk_ SDK key to open encrypted content.")
    
    # Enable security features
    client.set_min_tls_version("1.2")
    # Note: In production, you should enable certificate pinning
    # client.enable_certificate_pinning(["your-certificate-sha256-hash"])
    
    # Step 3: Authenticate
    print_info("Authenticating user...")
    
    authenticated = False
    
    # Try auto-login first
    if await client.try_auto_login():
        print_success("Auto-login successful!")
        authenticated = True
    # Fall back to manual login
    elif await client.authenticate_with_username(config.username, config.password):
        print_success("Manual authentication successful!")
        authenticated = True
    # Try key authentication
    else:
        print("\nEnter license key (or press Enter to skip): ", end="")
        license_key = input()
        
        if license_key:
            if await client.authenticate_with_key(license_key):
                print_success("License key authentication successful!")
                authenticated = True
    
    if not authenticated:
        print_error(f"Authentication failed: {client.get_last_error()}")
        return
    
    # Step 4: Check Authorization
    print_info("Checking product access and subscription...")
    
    if not await check_authorization(client, config.product_id):
        print_error("Authorization check failed")
        client.end_session()
        return
    
    print_success("User is authorized!")
    
    subscription = await client.get_user_subscription_by_product(config.product_id)
    print(f"  Subscription: {subscription.status}")
    print(f"  Downloads used: {subscription.downloads}")
    
    # Step 5: Get Product Information
    print_info("Fetching product information...")
    
    # Check product status
    status = await client.get_product_status(config.product_id)
    if status.has_status:
        print(f"  Product status: {status.name}")
        
        if status.name in ("maintenance", "offline"):
            print_error(f"Product is currently unavailable: {status.action}")
            client.end_session()
            return
    
    # Get product variables (end-to-end encrypted values are opened with the content key)
    variables = await client.get_product_variables(config.product_id)
    if variables or not client.get_last_error():
        print(f"  Product has {len(variables)} variable(s)")
    else:
        print_error(f"Could not read the product variables: {client.get_last_error()}")
    
    # Step 6: Download a File
    print(f"\n  Downloading: {config.file_name}")
    
    output_path = f"{config.download_path}/{config.file_name}"
    
    if await download_with_retry(client, config.product_id, config.file_name, output_path):
        print_success("File downloaded successfully!")
        print(f"  Saved to: {output_path}")
        if client.get_last_signed_at():
            print(f"  Signed at (Unix ms): {client.get_last_signed_at()}")
        
        # Verify hash
        if await client.is_valid_file_hash(config.product_id, config.file_name, output_path):
            print("  Hash verification: PASSED")
        else:
            print("  Hash verification: FAILED")
    else:
        print_error("Failed to download file after 3 attempts")
    
    # Step 7: Cleanup
    print_info("Cleaning up...")
    client.end_session()
    
    print_success("Application completed successfully!")
    
    print("\n" + "=" * 50)
    print("Thank you for using Vaultix SDK!")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
