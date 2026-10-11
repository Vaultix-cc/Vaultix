#!/usr/bin/env python3
"""
Example 3: Subscription Management

Demonstrates how to manage user subscriptions:
- Get subscription details for a product
- Check subscription status (active, paused, expired)
- Get subscription expiration dates
- View download counts
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultix import VaultixClient


# Configuration - Replace with your actual values
APP_API_KEY = "ap_your_app_api_key_here"
PRODUCT_ID = "your_product_id_here"
USERNAME = "your_username"
PASSWORD = "your_password"


def print_banner():
    print("\n" + "=" * 50)
    print("  Vaultix SDK - Subscription Management Example")
    print("=" * 50 + "\n")


def print_subscription_info(subscription):
    print("  " + "-" * 38)
    print(f"    Subscription ID: {subscription.subscription_id}")
    print(f"    User ID:         {subscription.app_user_id}")
    print(f"    Product ID:      {subscription.product_id}")
    print(f"    Status:          {subscription.status}")
    print(f"    Expires At:      {subscription.expires_at or 'Lifetime'}")
    print(f"    Is Paused:       {'Yes' if subscription.is_paused else 'No'}")
    
    if subscription.is_paused:
        print(f"    Paused At:       {subscription.paused_at}")
        print(f"    Paused Until:     {subscription.paused_until}")
    
    print(f"    Downloads:       {subscription.downloads}")
    print(f"    Created At:      {subscription.created_at}")
    print(f"    Updated At:      {subscription.updated_at}")
    print("  " + "-" * 38)


async def main():
    print_banner()
    
    client = VaultixClient("https://vaultix.cc/api")
    client.debug_mode = True
    
    client.set_api_key(APP_API_KEY)
    
    # Authenticate first
    print("Authenticating...")
    if not await client.authenticate_with_username(USERNAME, PASSWORD):
        print(f"[FAILED] Authentication failed: {client.get_last_error()}")
        return
    
    print("[OK] Authentication successful!\n")
    
    # 1. Get all user products
    print("--- Your Products ---")
    products = await client.get_user_products()
    
    if not products:
        print("You don't have access to any products.")
        client.end_session()
        return
    
    print(f"You have access to {len(products)} product(s):\n")
    
    for i, product in enumerate(products, 1):
        print(f"  {i}. {product['name']}")
        print(f"     ID:   {product['id']}")
    print()
    
    # 2. Get subscription for a specific product
    print(f"--- Subscription Details for {PRODUCT_ID} ---")
    
    subscription = await client.get_user_subscription_by_product(PRODUCT_ID)
    
    if subscription.subscription_id:
        print_subscription_info(subscription)
        
        # 3. Check subscription validity
        print("\n--- Subscription Validity Check ---")
        
        is_valid = subscription.is_active
        
        if is_valid:
            print("  [OK] Your subscription is valid!")
        else:
            print("  [WARN] Your subscription has issues:")
            
            if subscription.is_paused:
                print("    - Subscription is paused")
            if subscription.status == "expired":
                print("    - Subscription has expired")
        
        # 4. Download allowance check
        print("\n--- Download Allowance ---")
        print(f"  Downloads used: {subscription.downloads}")
        
        if subscription.downloads < 1000:
            print("  Downloads remaining: Unlimited (no restrictions)")
        else:
            print("  Consider monitoring your download usage.")
    
    else:
        error = client.get_last_error()
        if "No subscription found" in error:
            print("  [INFO] No active subscription found for this product.")
            print("  Please purchase or activate a subscription to access content.")
        else:
            print(f"  [ERROR] Failed to retrieve subscription: {error}")
    
    # 5. Check access for all products
    print("\n--- Access Check for All Products ---")
    
    for product in products:
        pid = product['id']
        has_access = client.has_product_access(pid)
        
        print(f"  {product['name']}: ", end="")
        if has_access:
            print("[OK] Has access")
        else:
            print("[NO ACCESS]")
    
    # End session
    client.end_session()
    
    print("\n" + "=" * 50)
    print("Example completed.")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
