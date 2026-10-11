#!/usr/bin/env python3
"""
Example 4: Product Variables and Status

Demonstrates how to:
- Retrieve product variables (key-value pairs)
- Get product status information
- Fetch product news/announcements
- Use variables for application configuration
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
USERNAME = "your_username"
PASSWORD = "your_password"


def print_banner():
    print("\n" + "=" * 50)
    print("  Vaultix SDK - Product Variables & Status")
    print("=" * 50 + "\n")


def print_status_with_color(status):
    print(f"  Status Name:  {status.name}")
    print(f"  Status Color: {status.color}")
    print(f"  Status Action: {status.action}")
    
    # Interpret the status
    print("\n  Interpretation:")
    
    if status.name in ("online", "active"):
        print("    [OK] Product is operating normally.")
    elif status.name == "maintenance":
        print("    [INFO] Product is under maintenance.")
        print(f"    Action to take: {status.action}")
    elif status.name == "update":
        print("    [UPDATE] A new version is available!")
        print(f"    Action: {status.action}")
    elif status.name == "offline":
        print("    [ERROR] Product is currently offline.")
        print(f"    Action: {status.action}")
    else:
        print(f"    Unknown status: {status.name}")


async def main():
    print_banner()
    
    client = VaultixClient("https://vaultix.cc/api")
    client.debug_mode = True
    
    client.set_api_key(APP_API_KEY)
    # Opens end-to-end encrypted variables (all new apps).
    if not client.set_content_key(SDK_KEY):
        print("Set your vxk_ SDK key (App Settings -> End-to-end encryption) to open encrypted variables.")
    
    # Authenticate first
    print("Authenticating...")
    if not await client.authenticate_with_username(USERNAME, PASSWORD):
        print(f"[FAILED] Authentication failed: {client.get_last_error()}")
        return
    
    print("[OK] Authentication successful!\n")
    
    # 1. Get product status
    print("--- Product Status ---")
    
    status_info = await client.get_product_status(PRODUCT_ID)
    
    if status_info.has_status:
        print_status_with_color(status_info)
    else:
        print("  [INFO] No status information available.")
    print()
    
    # 2. Get product news
    print("--- Product News & Announcements ---")
    
    news_info = await client.get_product_news(PRODUCT_ID)
    
    if news_info.has_news:
        print(f"  Headline: {news_info.headline}")
        print("  Content:")
        
        # Word wrap content at 60 characters
        content = news_info.content
        words = content.split()
        line = ""
        
        for word in words:
            if len(line) + len(word) + 1 > 60:
                print(f"    {line}")
                line = word
            else:
                line = f"{line} {word}" if line else word
        
        if line:
            print(f"    {line}")
        
        print(f"\n  Updated: {news_info.updated_at}")
    else:
        print("  [INFO] No news available at this time.")
    print()
    
    # 3. Get product variables
    print("--- Product Variables ---")
    
    variables = await client.get_product_variables(PRODUCT_ID)
    
    if not variables:
        if client.get_last_error():
            print(f"  [FAILED] {client.get_last_error()}")
        else:
            print("  No variables defined for this product.")
    else:
        print(f"  Found {len(variables)} variable(s):\n")
        
        # Group variables by category (prefix)
        grouped_vars = {}
        
        for key, value in variables.items():
            category = "other"
            
            if "VERSION" in key.upper():
                category = "version"
            elif any(x in key.upper() for x in ["URL", "LINK"]):
                category = "urls"
            elif any(x in key.upper() for x in ["KEY", "TOKEN", "SECRET"]):
                category = "secrets"
            elif any(x in key.upper() for x in ["DEBUG", "ENABLE", "DISABLED"]):
                category = "flags"
            
            if category not in grouped_vars:
                grouped_vars[category] = []
            
            grouped_vars[category].append((key, value))
        
        # Print grouped variables
        for category, vars_list in grouped_vars.items():
            print(f"  [{category.upper()}]")
            
            for key, value in vars_list:
                # Mask sensitive values
                display_value = value
                is_sensitive = any(x in key.upper() for x in ["KEY", "TOKEN", "SECRET", "PASSWORD"])
                
                if is_sensitive and len(display_value) > 8:
                    display_value = f"{display_value[:4]}****{display_value[-4:]}"
                
                print(f"    {key} = {display_value}")
            print()
    
    # 4. Use variables for application config
    print("--- Using Variables for Configuration ---")
    
    for key, value in variables.items():
        if key in ("CURRENT_VERSION", "version"):
            print(f"  Current version: {value}")
        if key in ("MIN_VERSION", "min_version"):
            print(f"  Minimum required version: {value}")
        if key in ("DOWNLOAD_URL", "download_url"):
            print(f"  Download URL: {value}")
    
    # End session
    client.end_session()
    
    print("\n" + "=" * 50)
    print("Example completed.")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
