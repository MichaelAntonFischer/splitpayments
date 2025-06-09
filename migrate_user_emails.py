#!/usr/bin/env python3
"""
Migration script to update LNbits user email fields with their bringin lightning addresses.

This script:
1. Gets the bringin audit data to find user_id -> lightning_address mappings
2. Updates each LNbits user's email field to match their bringin lightning address
"""

import requests
import json
import os
from typing import Dict, List, Any
import argparse
import hashlib
import hmac
import base64
import time

class UserEmailMigrator:
    def __init__(self):
        self.base_url = "https://bringin.opago-pay.com/splitpayments/api/v1"
        self.lnbits_base_url = "https://bringin.opago-pay.com"
        self.api_prefix = "/splitpayments/api/v1"
        
        # Load secrets
        self.hmac_secret = self._load_secret("bringin/secret", "BRINGIN_SECRET")
        self.api_key = self._load_secret("opago/key", "OPAGO_KEY")
        
        # Get OAuth token for LNbits API
        self.oauth_token = self._get_oauth_token()
    
    def _load_secret(self, pass_path: str, env_var: str) -> str:
        """Load secret from environment variable (pass not available in container)."""
        # In container, load directly from environment variables
        secret = os.getenv(env_var, "")
        if secret:
            # Only strip whitespace, NOT quotes (quotes are part of the secret for BRINGIN_SECRET)
            # OAuth credentials need quote stripping, but HMAC secret does not
            if env_var in ["OPAGO_USER", "OPAGO_PWD"]:
                secret = secret.strip().strip('"').strip("'")
            else:
                secret = secret.strip()  # Only strip whitespace
        return secret
    
    def _get_oauth_token(self) -> str:
        """Get OAuth token for LNbits API - copied from working bringin.py implementation."""
        try:
            username = self._load_secret("opago/user", "OPAGO_USER")
            password = self._load_secret("opago/pwd", "OPAGO_PWD")
            
            if not username or not password:
                print(f"OAuth credentials missing - user: {'✅' if username else '❌'}, pwd: {'✅' if password else '❌'}")
                return ""
            
            auth_endpoint = f"{self.lnbits_base_url}/api/v1/auth"
            
            # Try username/password first (as in bringin.py)
            auth_data = {
                "username": username,
                "password": password
            }
            
            response = requests.post(
                auth_endpoint,
                json=auth_data,  # Use JSON, not form data
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                auth_result = response.json()
                token = auth_result.get("access_token")
                if token:
                    print(f"OAuth token obtained with username: ✅")
                    return token
                else:
                    print("Authentication succeeded but no access_token in response")
            else:
                print(f"Username/password auth failed: {response.status_code}")
            
            # Try email/password fallback (as in bringin.py)
            alt_auth_data = {
                "email": username,
                "password": password
            }
            
            alt_response = requests.post(
                auth_endpoint,
                json=alt_auth_data,
                headers={"Content-Type": "application/json"}
            )
            
            if alt_response.status_code == 200:
                alt_result = alt_response.json()
                token = alt_result.get("access_token")
                if token:
                    print(f"OAuth token obtained with email: ✅")
                    return token
            
            print(f"Both auth methods failed. Username: {response.status_code}, Email: {alt_response.status_code}")
            return ""
        except Exception as e:
            print(f"Error getting OAuth token: {e}")
            return ""
    
    def generate_hmac_authorization(self, method: str, path: str, body: Dict[str, Any] = None, timestamp: int = None) -> str:
        """Generate HMAC authorization header - copied from working bringin.py implementation."""
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        
        if body is None:
            body = {}
        
        # Use exact same logic as bringin.py
        body_string = json.dumps(body, separators=(',', ':'), sort_keys=True) if body else '{}'
        body_bytes = body_string.encode('utf-8')
        request_content_hex_string = hashlib.md5(body_bytes).hexdigest()
        
        signature_raw_data = str(timestamp) + method + path + request_content_hex_string
        
        # Use secret directly as string like bringin.py does (not base64 decoded)
        signature = hmac.new(self.hmac_secret.encode(), signature_raw_data.encode(), hashlib.sha256).hexdigest()
        
        return f"HMAC {timestamp}:{signature}"
        
    def get_bringin_audit_data(self) -> List[Dict[str, Any]]:
        """Get bringin audit data with user mappings."""
        print("Fetching bringin audit data...")
        
        url = f"{self.base_url}/bringin_audit"
        params = {"include_transactions": "false"}  # We don't need transaction details
        
        # Generate HMAC authorization
        hmac_auth = self.generate_hmac_authorization("GET", f"{self.api_prefix}/bringin_audit")
        headers = {
            'Authorization': hmac_auth,
            'X-Api-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(url, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                print(f"Successfully fetched audit data with {len(data)} users")
                return data
            else:
                print(f"Error fetching bringin audit: {response.status_code}")
                print(response.text)
                return []
        except Exception as e:
            print(f"Exception fetching audit data: {e}")
            return []

    def get_splitpayments_targets_for_user(self, user_data: Dict[str, Any]) -> List[str]:
        """Get splitpayments targets (lightning addresses) for a specific user's wallet."""
        user_id = user_data.get("user_id")
        wallet_id = user_data.get("wallet_id")
        admin_key = user_data.get("admin_key")
        
        if not user_id or not wallet_id or not admin_key:
            print(f"Missing required data for user: user_id={user_id}, wallet_id={wallet_id}, admin_key={'✅' if admin_key else '❌'}")
            return []
        
        try:
            # Query splitpayments targets using the wallet admin key directly from audit data
            targets_url = f"{self.lnbits_base_url}/splitpayments/api/v1/targets"
            targets_headers = {
                "X-Api-Key": admin_key,
                "Content-Type": "application/json"
            }
            
            targets_response = requests.get(targets_url, headers=targets_headers)
            
            if targets_response.status_code != 200:
                print(f"Failed to get splitpayments targets for wallet {wallet_id}: {targets_response.status_code}")
                if targets_response.status_code == 401:
                    print(f"Authentication failed - admin key might be invalid for wallet {wallet_id}")
                return []
            
            targets_data = targets_response.json()
            
            # Extract lightning addresses from targets
            lightning_addresses = []
            for target in targets_data:
                wallet_field = target.get("wallet", "")
                if "@" in wallet_field and "bringin.xyz" in wallet_field:
                    lightning_addresses.append(wallet_field)
            
            print(f"Found {len(lightning_addresses)} targets for user {user_id}: {lightning_addresses}")
            return lightning_addresses
            
        except Exception as e:
            print(f"Error getting splitpayments targets for user {user_id}: {e}")
            return []

    def get_wallet_admin_key(self, user_id: str, wallet_id: str) -> str:
        """Get admin key for a specific wallet."""
        try:
            if not self.oauth_token:
                print("No OAuth token available")
                return ""
            
            headers = {
                "Authorization": f"Bearer {self.oauth_token}",
                "Content-Type": "application/json"
            }
            
            # Get wallet details for the specific user
            url = f"{self.lnbits_base_url}/users/api/v1/user/{user_id}/wallet"
            response = requests.get(url, headers=headers)
            
            if response.status_code != 200:
                print(f"Failed to get wallet details for user {user_id}: {response.status_code}")
                return ""
            
            wallets = response.json()
            
            # Find the specific wallet and get its admin key
            for wallet in wallets:
                if wallet.get("id") == wallet_id:
                    admin_key = wallet.get("adminkey")
                    if admin_key:
                        return admin_key
                    else:
                        print(f"No admin key found in wallet {wallet_id}")
                        return ""
            
            print(f"Wallet {wallet_id} not found for user {user_id}")
            return ""
            
        except Exception as e:
            print(f"Error getting admin key for user {user_id}, wallet {wallet_id}: {e}")
            return ""

    def get_user_lightning_address_mapping(self) -> Dict[str, str]:
        """Get mapping of user_id -> lightning_address from splitpayments target configurations."""
        audit_data = self.get_bringin_audit_data()
        
        user_mappings = {}
        
        print("Checking splitpayments targets for each user...")
        
        for user_data in audit_data:
            user_id = user_data.get("user_id")
            wallet_id = user_data.get("wallet_id")
            
            if user_id and wallet_id:
                # Get admin key for this wallet
                admin_key = self.get_wallet_admin_key(user_id, wallet_id)
                if admin_key:
                    # Add admin key to user data
                    user_data_with_key = {**user_data, "admin_key": admin_key}
                    
                    # Get splitpayments targets for this user's wallet
                    targets = self.get_splitpayments_targets_for_user(user_data_with_key)
                    
                    # Use the first lightning address found in targets
                    if targets:
                        lightning_address = targets[0]  # Take first valid address
                        user_mappings[user_id] = lightning_address
                        print(f"Found mapping from splitpayments: {user_id} -> {lightning_address}")
                    else:
                        print(f"No splitpayments targets found for user {user_id}")
                else:
                    print(f"Could not get admin key for user {user_id}, wallet {wallet_id}")
            else:
                print(f"Missing user_id or wallet_id for user data: {user_data}")
        
        print(f"Total mappings found from splitpayments: {len(user_mappings)}")
        return user_mappings

    def get_user_details(self, user_id: str) -> Dict[str, Any]:
        """Get current user details before updating."""
        try:
            headers = {
                "Authorization": f"Bearer {self.oauth_token}",
                "Content-Type": "application/json"
            }
            
            url = f"{self.lnbits_base_url}/users/api/v1/user/{user_id}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to get user details for {user_id}: {response.status_code}")
                return {}
        except Exception as e:
            print(f"Error getting user details for {user_id}: {e}")
            return {}

    def update_lnbits_user_email(self, user_id: str, lightning_address: str) -> bool:
        """Update a LNbits user's email field."""
        print(f"Updating user {user_id} email to {lightning_address}")
        
        if not self.oauth_token:
            print("No OAuth token available")
            return False
        
        # First get current user details to preserve other fields
        current_user = self.get_user_details(user_id)
        if not current_user:
            print(f"Could not get current user details for {user_id}")
            return False
        
        headers = {
            "Authorization": f"Bearer {self.oauth_token}",
            "Content-Type": "application/json"
        }
        
        url = f"{self.lnbits_base_url}/users/api/v1/user/{user_id}"
        
        # Use current user data and only update email field
        data = {
            "id": user_id,  # Add user ID to match URL path
            "username": current_user.get("username", ""),
            "email": lightning_address,  # Update this field
            "user_config": current_user.get("config", {})
        }
        
        try:
            response = requests.put(url, json=data, headers=headers)
            if response.status_code == 200:
                print(f"✅ Successfully updated {user_id} -> {lightning_address}")
                return True
            else:
                print(f"❌ Failed to update {user_id}: {response.status_code}")
                print(response.text)
                # Try alternative approach if the first fails
                return self.update_user_alternative_method(user_id, lightning_address, current_user)
        except Exception as e:
            print(f"❌ Exception updating {user_id}: {e}")
            return False
    
    def update_user_alternative_method(self, user_id: str, lightning_address: str, current_user: Dict[str, Any]) -> bool:
        """Try alternative user update method."""
        print(f"Trying alternative update method for {user_id}")
        
        headers = {
            "Authorization": f"Bearer {self.oauth_token}",
            "Content-Type": "application/json"
        }
        
        url = f"{self.lnbits_base_url}/users/api/v1/user/{user_id}"
        
        # Try with minimal required fields
        data = {
            "id": user_id,  # Add user ID to match URL path
            "email": lightning_address
        }
        
        # Add username if available
        if current_user.get("username"):
            data["username"] = current_user["username"]
        
        try:
            response = requests.put(url, json=data, headers=headers)
            if response.status_code == 200:
                print(f"✅ Successfully updated {user_id} -> {lightning_address} (alternative method)")
                return True
            else:
                print(f"❌ Alternative method also failed for {user_id}: {response.status_code}")
                print(response.text)
                return False
        except Exception as e:
            print(f"❌ Exception in alternative method for {user_id}: {e}")
            return False

    def migrate_all_users(self, dry_run: bool = True):
        """Migrate all users from bringin audit data."""
        print("Starting user email migration...")
        
        # Get user mappings
        user_mappings = self.get_user_lightning_address_mapping()
        
        if not user_mappings:
            print("No user mappings found! Check the bringin audit data structure.")
            return
        
        print(f"Found {len(user_mappings)} users to migrate")
        
        if dry_run:
            print("\n=== DRY RUN MODE ===")
            for user_id, lightning_address in user_mappings.items():
                print(f"Would update: {user_id} -> {lightning_address}")
            print("\nRun with --execute to perform actual migration")
            return
        
        # Perform actual migration
        success_count = 0
        for user_id, lightning_address in user_mappings.items():
            if self.update_lnbits_user_email(user_id, lightning_address):
                success_count += 1
        
        print(f"\nMigration complete: {success_count}/{len(user_mappings)} users updated")

def main():
    parser = argparse.ArgumentParser(description="Migrate LNbits user emails from bringin audit data")
    parser.add_argument("--execute", action="store_true", help="Actually perform the migration (default is dry run)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    migrator = UserEmailMigrator()
    
    try:
        migrator.migrate_all_users(dry_run=not args.execute)
    except Exception as e:
        print(f"Migration failed: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main()) 