#!/usr/bin/env python3
"""
Example 5: Auto-Login and Session Persistence

Demonstrates how to implement seamless re-authentication:
- Try auto-login with saved session token
- Handle token refresh automatically
- Properly manage logout (clear or keep token)
- Build user-friendly authentication flows
"""

import asyncio
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vaultix import VaultixClient


# Configuration - Replace with your actual values
APP_API_KEY = "ap_your_app_api_key_here"
USERNAME = "your_username"
PASSWORD = "your_password"


def print_banner():
    print("\n" + "=" * 50)
    print("  Vaultix SDK - Auto-Login Example")
    print("=" * 50 + "\n")


def print_auth_flow(flow):
    print(f"\n>>> {flow}")


async def main():
    print_banner()
    
    client = VaultixClient("https://vaultix.cc/api")
    client.debug_mode = True
    
    client.set_api_key(APP_API_KEY)
    
    print_auth_flow("Starting Authentication Flow")
    
    # Step 1: Try Auto-Login First
    print("\nStep 1: Attempting auto-login...")
    print("  (This uses a previously saved session token)")
    
    authenticated = False
    
    if await client.try_auto_login():
        print_auth_flow("Auto-login SUCCESSFUL!")
        print("  Welcome back! Your session has been restored.")
        print("  No need to enter credentials again.")
        authenticated = True
    else:
        print("Auto-login not available or failed.")
        print(f"  Reason: {client.get_last_error()}")
        print("  This is normal for first-time users.")
        
        # Step 2: Manual Authentication
        print("\nStep 2: Performing manual authentication...")
        print("  (This is only needed if auto-login failed)")
        
        if await client.authenticate_with_username(USERNAME, PASSWORD):
            print_auth_flow("Manual authentication SUCCESSFUL!")
            print("  A session token has been saved for future auto-logins.")
            print("  The token will remain valid for 7 days.")
            authenticated = True
        else:
            print_auth_flow("Manual authentication FAILED!")
            print(f"  Error: {client.get_last_error()}")
            return
    
    if authenticated:
        # Display session info
        session = client.get_current_session()
        print("\n  Session restored:")
        print(f"    User: {session.app_user.username}")
        print(f"    App:  {session.app_id}")
        print(f"    HWID: {session.hwid}")
        print(f"    Token expires: {session.token_expiry}")
        
        # Step 3: Token Expiry Handling
        print("\nStep 3: Checking token expiry...")
        
        if await client.is_token_expired():
            print("  Token has expired. Attempting refresh...")
            
            if await client.refresh_token():
                print_auth_flow("Token refresh SUCCESSFUL!")
                print("  A new token has been obtained.")
            else:
                print("  Token refresh failed.")
                print("  User may need to re-authenticate manually.")
        else:
            print("  Token is still valid. No refresh needed.")
        
        # Step 4: Simulate application work
        print("\nStep 4: Simulating application work...")
        print("  (In a real app, you would perform your operations here)")
        
        for i in range(1, 4):
            print(f"  Working... {i}/3")
            await asyncio.sleep(0.3)
        
        # Step 5: Logout Options
        print("\nStep 5: Session cleanup options:\n")
        print("  Choose logout type:")
        print("    1. End Session (keep auto-login)")
        print("    2. Full Logout (clear auto-login)")
        print()
        choice = input("  Enter choice (1 or 2): ")
        
        print()
        
        if choice == "1":
            # Soft logout - just end the session
            client.end_session()
            print_auth_flow("Session ended (soft logout).")
            print("  Your auto-login token is preserved.")
            print("  Next time you run the app, auto-login will work.")
        else:
            # Full logout - clear everything
            client.clear_auto_login_token()
            client.end_session()
            print_auth_flow("Full logout completed.")
            print("  All tokens have been cleared.")
            print("  Next launch will require manual authentication.")
    
    print("\n" + "=" * 50)
    print("Example completed.")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
