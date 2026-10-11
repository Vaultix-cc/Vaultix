#!/usr/bin/env python3
"""
Example 1: Basic Authentication

Demonstrates how to authenticate with the Vaultix API using two methods:
1. Username/Password authentication
2. License key authentication
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultix import VaultixClient


# Configuration - Replace with your actual values
APP_API_KEY = "ap_your_app_api_key_here"
PRODUCT_ID = "your_product_id_here"


def print_banner():
    print("\n" + "=" * 50)
    print("  Vaultix SDK - Basic Authentication Example")
    print("=" * 50 + "\n")


def print_session_info(session):
    print("\n  Session Information:")
    print("  " + "-" * 38)
    print(f"    App ID:       {session.app_id}")
    print(f"    Session ID:   {session.session_id}")
    print(f"    HWID:         {session.hwid}")
    print(f"    Token Expires: {session.token_expiry}")
    print(f"    User ID:      {session.app_user.id}")
    print(f"    Username:     {session.app_user.username}")
    print("  " + "-" * 38)


async def main():
    print_banner()
    
    # Initialize client
    client = VaultixClient("https://vaultix.cc/api")
    client.debug_mode = True
    
    client.set_api_key(APP_API_KEY)
    
    print("Choose authentication method:")
    print("  1. Username/Password")
    print("  2. License Key")
    print()
    choice = input("Enter choice (1 or 2): ")
    
    authenticated = False
    
    if choice == "1":
        # Method 1: Username/Password Authentication
        print("\n--- Username/Password Authentication ---\n")
        
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        print("\nAuthenticating...\n")
        
        if await client.authenticate_with_username(username, password):
            print("[SUCCESS] Authentication successful!")
            print("  A session token has been created.")
            print("  The token will expire in 7 days.")
            authenticated = True
        else:
            print(f"[FAILED] Authentication failed!")
            print(f"  Error: {client.get_last_error()}")
    
    elif choice == "2":
        # Method 2: License Key Authentication
        print("\n--- License Key Authentication ---\n")
        
        license_key = input("Enter license key (format: XXXX-XXXX-XXXX-XXXX): ")
        
        print("\nAuthenticating...\n")
        
        if await client.authenticate_with_key(license_key):
            print("[SUCCESS] Authentication successful!")
            print("  A session token has been created.")
            print("  The token will expire in 7 days.")
            authenticated = True
        else:
            print(f"[FAILED] Authentication failed!")
            print(f"  Error: {client.get_last_error()}")
    
    else:
        print("\n[ERROR] Invalid choice!")
    
    if authenticated:
        # Display session information
        session = client.get_current_session()
        print_session_info(session)
        
        # Check product access
        print("\nProduct Access Check:")
        if client.has_product_access(PRODUCT_ID):
            print(f"  [OK] You have access to product: {PRODUCT_ID}")
        else:
            print("  [WARN] You don't have access to this product.")
        
        # Get user's products
        print("\nYour Products:")
        products = await client.get_user_products()
        
        if products:
            for product in products:
                print(f"  - {product['name']} (ID: {product['id']})")
        else:
            print("  No products found.")
        
        # End the session
        print("\nEnding session...")
        client.end_session()
        print("[OK] Session ended.")
    
    print("\n" + "=" * 50)
    print("Example completed.")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
