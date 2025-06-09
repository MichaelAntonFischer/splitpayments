#!/usr/bin/env python3
"""
Backfill script for LNbits v1.1.0 compatibility
- Updates all missing usernames to use LNbits user IDs (truncated to 20 chars)
- Activates splitpayments and lnurlp extensions for existing users

Usage: python backfill_users.py
"""

import asyncio
import os
import sys
import httpx
import argparse
from loguru import logger
from typing import List, Dict, Any

# Import required functions from bringin module
from bringin import get_auth_headers, enable_user_extensions

async def get_all_users(admin_key: str) -> List[Dict[str, Any]]:
    """Get all users from LNbits instance"""
    base_url = "https://bringin.opago-pay.com"
    headers = await get_auth_headers(admin_key, base_url)
    
    async with httpx.AsyncClient() as client:
        users_response = await client.get(f"{base_url}/users/api/v1/user", headers=headers)
        users_response.raise_for_status()
        users_data = users_response.json().get("data", users_response.json())
        return users_data

async def get_user_wallets(user_id: str, admin_key: str) -> List[Dict[str, Any]]:
    """Get wallets for a specific user"""
    base_url = "https://bringin.opago-pay.com"
    headers = await get_auth_headers(admin_key, base_url)
    
    async with httpx.AsyncClient() as client:
        wallets_response = await client.get(f"{base_url}/users/api/v1/user/{user_id}/wallet", headers=headers)
        wallets_response.raise_for_status()
        return wallets_response.json()

async def update_user_username(user_id: str, username: str, email: str, user_config: Dict, admin_key: str) -> bool:
    """Update a user's username"""
    base_url = "https://bringin.opago-pay.com"
    headers = await get_auth_headers(admin_key, base_url)
    
    user_update_data = {
        "id": user_id,
        "username": username,
        "email": email,
        "user_config": user_config
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.put(
                f"{base_url}/users/api/v1/user/{user_id}", 
                headers=headers, 
                json=user_update_data
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to update username for user {user_id}: {str(e)}")
            return False

async def backfill_users():
    """Main backfill function"""
    # Get admin key from environment
    admin_key = os.environ.get('OPAGO_KEY')
    if not admin_key:
        logger.error("OPAGO_KEY environment variable is required")
        sys.exit(1)
    
    logger.info("Starting user backfill process...")
    
    try:
        # Get all users
        logger.info("Fetching all users...")
        users = await get_all_users(admin_key)
        logger.info(f"Found {len(users)} users")
        
        users_updated = 0
        users_skipped = 0
        extensions_activated = 0
        extension_failures = 0
        
        for user in users:
            user_id = user.get("id")
            email = user.get("email", "")
            current_username = user.get("username", "")
            user_config = user.get("config", {})
            
            logger.info(f"\nProcessing user: {user_id}")
            logger.info(f"  Email: {email}")
            logger.info(f"  Current username: '{current_username}'")
            
            # Check if username needs updating
            expected_username = user_id[:20] if user_id else ""
            needs_username_update = False
            
            if not current_username:
                logger.info("  → Username is missing")
                needs_username_update = True
            elif current_username != expected_username:
                logger.info(f"  → Username doesn't match user ID: '{current_username}' vs '{expected_username}'")
                needs_username_update = True
            elif len(current_username) > 20:
                logger.info(f"  → Username too long ({len(current_username)} > 20 chars)")
                needs_username_update = True
            else:
                logger.info("  → Username is correct")
            
            # Update username if needed
            if needs_username_update:
                logger.info(f"  → Updating username to: '{expected_username}'")
                success = await update_user_username(user_id, expected_username, email, user_config, admin_key)
                if success:
                    logger.info("  ✅ Username updated successfully")
                    users_updated += 1
                else:
                    logger.error("  ❌ Failed to update username")
                    users_skipped += 1
                    continue
            else:
                users_skipped += 1
            
            # Get user's wallets to get admin key for extension enabling (user-level)
            try:
                wallets = await get_user_wallets(user_id, admin_key)
                if wallets:
                    # Use the first wallet's admin key
                    wallet_admin_key = wallets[0].get("adminkey")
                    if wallet_admin_key:
                        logger.info("  → Enabling extensions (splitpayments, lnurlp) for user...")
                        await enable_user_extensions(user_id, ["splitpayments", "lnurlp"], wallet_admin_key)
                        logger.info("  ✅ Extensions enabled successfully")
                        extensions_activated += 1
                    else:
                        logger.warning("  ⚠️ No wallet admin key found, skipping extension enabling")
                        extension_failures += 1
                else:
                    logger.warning("  ⚠️ No wallets found for user, skipping extension enabling")
                    extension_failures += 1
            except Exception as e:
                logger.error(f"  ❌ Failed to enable extensions: {str(e)}")
                extension_failures += 1
        
        # Summary
        logger.info(f"\n{'='*60}")
        logger.info("BACKFILL SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total users processed: {len(users)}")
        logger.info(f"Usernames updated: {users_updated}")
        logger.info(f"Users skipped (already correct): {users_skipped}")
        logger.info(f"Extensions enabled for users: {extensions_activated}")
        logger.info(f"Extension enabling failures: {extension_failures}")
        logger.info(f"{'='*60}")
        
        if users_updated > 0 or extensions_activated > 0:
            logger.info("✅ Backfill completed successfully!")
        else:
            logger.info("ℹ️ No changes were needed")
            
    except Exception as e:
        logger.error(f"❌ Backfill failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Set up logging
    logger.remove()  # Remove default handler
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
        level="INFO"
    )
    
    # Run the backfill
    asyncio.run(backfill_users()) 