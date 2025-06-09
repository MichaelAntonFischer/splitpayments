import asyncio
import os
import httpx
import time
import json
import hmac
import hashlib
from loguru import logger
from fastapi import HTTPException
from typing import List
from .crud import set_targets, get_targets
from .models import Target

API_BASE_URL = 'https://api.bringin.xyz'
BRINGIN_ENDPOINT_KEY = '/api/v0/application/api-key'
BRINGIN_ENDPOINT_OFFRAMP = '/api/v0/offramp/order'

# OAuth Token cache to avoid repeated authentication
_oauth_token_cache = None
_oauth_token_expiry = 0

async def get_oauth_token(admin_key: str, base_url: str = "https://bringin.opago-pay.com") -> str:
    """
    Get OAuth Bearer token for LNbits v1.1.0 authentication.
    Uses superuser username/password authentication with token caching.
    """
    global _oauth_token_cache, _oauth_token_expiry
    
    # Check if we have a valid cached token
    current_time = time.time()
    if _oauth_token_cache and current_time < _oauth_token_expiry:
        return _oauth_token_cache
    
    # Get superuser credentials from environment
    opago_user = os.environ.get('OPAGO_USER')
    opago_pwd = os.environ.get('OPAGO_PWD')
    
    # Strip quotes from environment variables (common issue with Docker compose)
    if opago_user:
        opago_user = opago_user.strip('"\'')
    if opago_pwd:
        opago_pwd = opago_pwd.strip('"\'')
    
    if not opago_user or not opago_pwd:
        logger.error("OPAGO_USER and OPAGO_PWD environment variables are required for LNbits v1.1.0 authentication")
        # Fallback to admin key as Bearer token
        return admin_key
    
    # Authenticate with LNbits OAuth system using username/password
    auth_endpoint = f"{base_url}/api/v1/auth"
    
    try:
        async with httpx.AsyncClient() as client:
            # Authenticate using superuser username and password
            auth_data = {
                "username": opago_user,
                "password": opago_pwd
            }
            
            response = await client.post(auth_endpoint, json=auth_data)
            
            if response.status_code == 200:
                auth_result = response.json()
                token = auth_result.get("access_token")
                
                if token:
                    # Cache the token for 50 minutes (assuming 1-hour expiry)
                    _oauth_token_cache = token
                    _oauth_token_expiry = current_time + 3000  # 50 minutes
                    logger.info("Successfully obtained OAuth token using username/password")
                    return token
                else:
                    logger.warning("Authentication succeeded but no access_token in response")
            else:
                logger.error(f"OAuth authentication failed with status {response.status_code}: {response.text}")
            
            # If username/password auth fails, try with alternative credentials format
            alt_auth_data = {
                "email": opago_user,
                "password": opago_pwd
            }
            
            alt_response = await client.post(auth_endpoint, json=alt_auth_data)
            
            if alt_response.status_code == 200:
                alt_result = alt_response.json()
                token = alt_result.get("access_token")
                
                if token:
                    _oauth_token_cache = token
                    _oauth_token_expiry = current_time + 3000  # 50 minutes
                    logger.info("Successfully obtained OAuth token using email/password")
                    return token
            
            # If all OAuth methods fail, fallback to admin key as Bearer token
            logger.warning("OAuth authentication failed, using admin key as Bearer token fallback")
            return admin_key
            
    except Exception as e:
        logger.error(f"OAuth authentication error: {str(e)}")
        # Fallback to using admin key as Bearer token
        return admin_key

async def get_auth_headers(admin_key: str, base_url: str = "https://bringin.opago-pay.com") -> dict:
    """
    Get authentication headers for LNbits v1.1.0 API calls.
    Returns Bearer token headers instead of deprecated X-Api-Key.
    """
    try:
        # Try OAuth first
        token = await get_oauth_token(admin_key, base_url)
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    except Exception as e:
        logger.error(f"Failed to get OAuth token: {str(e)}")
        # Fallback to admin key as Bearer (for compatibility)
        return {
            "Authorization": f"Bearer {admin_key}",
            "Content-Type": "application/json"
        }

async def offramp(lightning_address, amount_sats):
    # Example placeholders - replace with actual values or logic to obtain them
    ip_address = await fetch_public_ip()

    user_api_key = await fetch_users_api_key(os.environ['BRINGIN_KEY'].strip('"'), os.environ['BRINGIN_SECRET'].strip('"'), lightning_address)
    if user_api_key:
        result = await create_offramp_order(user_api_key, lightning_address, amount_sats, ip_address)
        logger.info(f"Create offramp order returned: {result}")
        return result


# Function to generate HMAC authorization header
def generate_hmac_authorization(secret, method, path, body, timestamp=None):
    # Use the provided timestamp or generate a new one if not provided
    if timestamp is None:
        timestamp = str(int(time.time() * 1000))
    else:
        timestamp = str(timestamp)  # Ensure timestamp is a string even if it's provided as an integer

    logger.info(f"Secret: {secret}")
    body_string = json.dumps(body, separators=(',', ':'), sort_keys=True) if body else '{}'
    logger.info(f"Body string: {body_string}")
    
    # Convert the body string to bytes and log the hexadecimal representation
    body_bytes = body_string.encode('utf-8')
    hex_representation = body_bytes.hex()
    logger.info(f"Bytes for Hashing (Hex): {hex_representation}")

    md5_hasher = hashlib.md5()
    md5_hasher.update(body_bytes)
    request_content_hex_string = md5_hasher.hexdigest()
    logger.info(f"MD5 Hash: {request_content_hex_string}")

    signature_raw_data = timestamp + method + path + request_content_hex_string
    logger.info(f"Raw Data for HMAC: {signature_raw_data}")

    signature = hmac.new(secret.encode(), signature_raw_data.encode(), hashlib.sha256).hexdigest()
    return f"HMAC {timestamp}:{signature}"

# Function to fetch the host's public IP address
async def fetch_public_ip():
    async with httpx.AsyncClient() as client:
        response = await client.get("https://api.ipify.org?format=json")
        if response.status_code == 200:
            return response.json()["ip"]
        else:
            raise Exception("Failed to fetch public IP address")

async def fetch_users_api_key(api_key, secret_key, lightning_address):
    body = {
        "lightningAddress": lightning_address
    }
    headers = {
        'authorization': generate_hmac_authorization(secret_key, "POST", BRINGIN_ENDPOINT_KEY, body),
        'api-key': api_key,
        'Content-Type': 'application/json',
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(API_BASE_URL + BRINGIN_ENDPOINT_KEY, json=body, headers=headers)
        if response.status_code == 200:
            response_data = response.json()  # Parse the JSON response
            user_api_key = response_data.get("apikey")  # Extract the API key
            if user_api_key:
                print("Success fetching user's API key:", user_api_key)
                return user_api_key
            else:
                print("API key not found in the response.")
                return None
        else:
            print("Failed to fetch user's API key:", response.status_code, response.text)
            return None


async def create_offramp_order(user_api_key, lightning_address, amount_sats, ip_address, label="OPAGO offramp ", payment_method="LIGHTNING", source_id=None): 
    body = {
        "sourceAmount": str(amount_sats), 
        "ipAddress": ip_address,
        "paymentMethod": payment_method
    }
    # Include sourceId if provided
    if source_id:
        body["sourceId"] = source_id

    headers = {
        'api-key': user_api_key,
        'Content-Type': 'application/json',
    }
    print(f"Headers: {headers}")
    print(f"Body: {json.dumps(body, indent=4)}")
    async with httpx.AsyncClient() as client:
        response = await client.post(API_BASE_URL + BRINGIN_ENDPOINT_OFFRAMP, json=body, headers=headers)
        if response.status_code == 200:
            response_data = response.json()  # Parse the JSON response
            invoice = response_data.get("invoice")  # Extract the invoice text
            if invoice:
                print("Offramp order created successfully. Invoice:", invoice)
                return invoice  # Return the invoice text
            else:
                print("Invoice not found in the response.")
                return None
        else:
            print("Failed to create offramp order. Error code:", response.status_code, "Response:", response.text)
            return response.status_code  # Return the error code

async def create_bringin_user(admin_id: str, user_name: str, wallet_name: str, lnaddress: str):
    url = "https://bringin.opago-pay.com/users/api/v1/user"
    headers = await get_auth_headers(os.environ['OPAGO_KEY'])
    # LNbits 1.1.0 - Don't specify 'id' field, let the system generate it
    data = {
        "username": user_name,
        "email": lnaddress,
        "password": os.environ.get('DEFAULT_USER_PASSWORD', "changeme123"),
        "password_repeat": os.environ.get('DEFAULT_USER_PASSWORD', "changeme123")
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=data)
            response.raise_for_status()
            response_data = response.json()
            # Now create wallet for user
            user_id = response_data["id"] if "id" in response_data else response_data.get("user_id")
            wallet_url = f"https://bringin.opago-pay.com/users/api/v1/user/{user_id}/wallet"
            wallet_data = {"name": wallet_name}
            wallet_resp = await client.post(wallet_url, headers=headers, json=wallet_data)
            wallet_resp.raise_for_status()
            wallet_info = wallet_resp.json()
            response_data["wallets"] = [wallet_info]
            return response_data
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def activate_extensions(user_id: str, extensions: List[str]):
    # LNbits v1.1.0: Enable extension for user (if possible)
    # This is not a direct replacement, but we can try enabling for the user
    headers = await get_auth_headers(os.environ['OPAGO_KEY'])
    async with httpx.AsyncClient() as client:
        for ext_id in extensions:
            url = f"https://bringin.opago-pay.com/api/v1/extension/{ext_id}/enable"
            # The API expects a PUT, and may require wallet/user context
            try:
                await client.put(url, headers=headers)
            except Exception as e:
                logger.warning(f"Could not enable extension {ext_id}: {e}")
    return {"extensions": "updated"}

async def delete_user(user_id: str):
    admin_key = os.environ["OPAGO_KEY"]
    headers = await get_auth_headers(admin_key)
    url = f"https://bringin.opago-pay.com/users/api/v1/user/{user_id}"
    async with httpx.AsyncClient() as client:
        response = await client.delete(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to delete user: {response.text}")

async def create_lnurlp_link(lightning_address: str, admin_key: str, bringin_max: int = None, bringin_min: int = None):
    url = "https://bringin.opago-pay.com/lnurlp/api/v1/links"
    headers = await get_auth_headers(admin_key)
    username = lightning_address.split("@")[0]
    
    if bringin_max is None:
        bringin_max = int(os.environ.get("BRINGIN_MAX", 0))
    if bringin_min is None:
        bringin_min = int(os.environ.get("BRINGIN_MIN", 0))
    
    data = {
        "description": "Offramp via Bringin",
        "max": bringin_max,
        "min": 1,
        "comment_chars": 210,
        "username": username
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=data)
            response.raise_for_status()
            response_data = response.json()
            return response_data["lnurl"]
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 409:
            detail = e.response.json().get('detail', 'Username already exists. Try a different one.')
            raise HTTPException(status_code=409, detail=detail)
        else:
            raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
async def delete_lnurlp_link(pay_id: str, admin_key: str):
    headers = await get_auth_headers(admin_key)
    url = f"https://bringin.opago-pay.com/lnurlp/api/v1/links/{pay_id}"
    async with httpx.AsyncClient() as client:
        response = await client.delete(url, headers=headers)
        if response.status_code != 204:
            raise Exception(f"Failed to delete LNURLp link: {response.text}")


async def get_bringin_audit_data(admin_key: str, include_transactions: bool = False, lnaddress: str = None):
    base_url = "https://bringin.opago-pay.com"
    headers = await get_auth_headers(admin_key, base_url)
    
    async with httpx.AsyncClient() as client:
        users_response = await client.get(f"{base_url}/users/api/v1/user", headers=headers)
        users_response.raise_for_status()
        users_data = users_response.json().get("data", users_response.json())
        if lnaddress:
            if "@" not in lnaddress:
                full_address = f"{lnaddress}@bringin.xyz"
            else:
                full_address = lnaddress
            users_data = [user for user in users_data if user["email"] == full_address]
            if not users_data:
                return []
        audit_data = []
        for user in users_data:
            user_id = user["id"]
            wallets_response = await client.get(f"{base_url}/users/api/v1/user/{user_id}/wallet", headers=headers)
            wallets_response.raise_for_status()
            wallets_data = wallets_response.json()
            for wallet in wallets_data:
                wallet_id = wallet["id"]
                # In LNbits v1.1.0, wallet balance is already in the wallet data
                # No need for separate API call to get balance
                wallet_data = {
                    "user_id": user_id,
                    "user_email": user["email"],
                    "wallet_id": wallet_id,
                    "wallet_balance": wallet.get("balance_msat", 0) // 1000
                }
                if include_transactions:
                    # Use the wallet's admin key for payments API instead of superuser OAuth
                    wallet_admin_key = wallet.get("adminkey")
                    if wallet_admin_key:
                        # Create headers with wallet's admin key instead of OAuth
                        wallet_headers = {"X-Api-Key": wallet_admin_key}
                        tx_response = await client.get(f"{base_url}/api/v1/payments", headers=wallet_headers)
                        tx_response.raise_for_status()
                        wallet_data["transactions"] = tx_response.json()
                    else:
                        wallet_data["transactions"] = []
                audit_data.append(wallet_data)
        return audit_data
    
async def add_bringin_user(lightning_address: str, admin_key: str):
    base_url = "https://bringin.opago-pay.com"
    headers = await get_auth_headers(admin_key, base_url)
    
    async with httpx.AsyncClient() as client:
        users_response = await client.get(f"{base_url}/users/api/v1/user", headers=headers)
        users_response.raise_for_status()
        users_data = users_response.json().get("data", users_response.json())
        for user in users_data:
            if user["email"] == lightning_address:
                raise HTTPException(status_code=409, detail="Lightning address already exists")
        admin_id = os.environ['OPAGO_ID']
        user_name = lightning_address.split("@")[0]
        wallet_name = "Offramp"
        user_id = None
        lnurl = None
        try:
            logger.info("Creating Bringin user")
            user_data = await create_bringin_user(admin_id, user_name, wallet_name, lightning_address)
            user_id = user_data["id"]
            invoice_key = user_data["wallets"][0]["inkey"]
            admin_key = user_data["wallets"][0]["adminkey"]
            wallet_id = user_data["wallets"][0]["id"]
            logger.info(f"User created with ID: {user_id}, Invoice Key: {invoice_key}, Admin Key: {admin_key}, Wallet ID: {wallet_id}")
            logger.info("Activating extensions for the user")
            await activate_extensions(user_id, ["splitpayments", "lnurlp"])
            logger.info("Extensions activated")
            logger.info("Creating LNURLp link")
            lnurl = await create_lnurlp_link(lightning_address, admin_key)
            logger.info(f"LNURLp link created: {lnurl}")
            logger.info("Setting targets for the wallet")
            target = Target(source=wallet_id, wallet=lightning_address, percent=100, alias="Offramp Order")
            await set_targets(wallet_id, [target])
            logger.info("Targets set")
            return {"lnurl": lnurl}
        except Exception as e:
            logger.error(f"Error during setup: {str(e)}")
            if isinstance(e, HTTPException):
                raise e
            else:
                raise HTTPException(status_code=500, detail=str(e))
    
async def update_bringin_user(old_lightning_address: str, new_lightning_address: str, admin_key: str):
    base_url = "https://bringin.opago-pay.com"
    headers = await get_auth_headers(admin_key, base_url)
    
    async with httpx.AsyncClient() as client:
        # Get all users to check for conflicts and find the target user
        users_response = await client.get(f"{base_url}/users/api/v1/user", headers=headers)
        users_response.raise_for_status()
        users_data = users_response.json().get("data", users_response.json())
        
        # Check if new lightning address already exists
        for user in users_data:
            if user["email"] == new_lightning_address:
                raise HTTPException(status_code=409, detail="Lightning address already exists")
        
        # Find the user with the old lightning address
        target_user = None
        for user in users_data:
            if user["email"] == old_lightning_address:
                target_user = user
                break
        
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_id = target_user["id"]
        
        # Get user's wallets
        wallets_response = await client.get(f"{base_url}/users/api/v1/user/{user_id}/wallet", headers=headers)
        wallets_response.raise_for_status()
        wallets_data = wallets_response.json()
        
        # Find the main wallet
        wallet_id = None
        wallet_admin_key = None
        for wallet in wallets_data:
            if wallet["user"] == user_id:
                wallet_id = wallet["id"]
                wallet_admin_key = wallet["adminkey"]
                break
        
        if not wallet_id:
            raise HTTPException(status_code=404, detail="Wallet not found")
        
        # Step 1: Update user's email field in LNbits (applying migration learnings)
        user_update_data = {
            "id": user_id,  # Required field - must match URL path
            "username": target_user.get("username", ""),
            "email": new_lightning_address,  # Update this field
            "user_config": target_user.get("config", {})
        }
        
        user_update_response = await client.put(
            f"{base_url}/users/api/v1/user/{user_id}", 
            headers=headers, 
            json=user_update_data
        )
        user_update_response.raise_for_status()
        logger.info(f"✅ Updated user {user_id} email: {old_lightning_address} -> {new_lightning_address}")
        
        # Step 2: Update LNURLP link
        # Delete old LNURLP link
        old_lnurl_response = await client.get(f"{base_url}/lnurlp/api/v1/links?wallet={wallet_id}", headers=headers)
        old_lnurl_response.raise_for_status()
        old_lnurl_data = old_lnurl_response.json()
        if old_lnurl_data:
            old_lnurl_id = old_lnurl_data[0]["id"]
            await delete_lnurlp_link(old_lnurl_id, wallet_admin_key)
            logger.info(f"✅ Deleted old LNURLP link: {old_lnurl_id}")
        
        # Create new LNURLP link
        new_lnurl = await create_lnurlp_link(new_lightning_address, wallet_admin_key)
        logger.info(f"✅ Created new LNURLP link: {new_lnurl}")
        
        # Step 3: Update split targets (replace old lightning address with new one)
        # get_targets, set_targets and Target are already imported at the top
        
        # Get current targets
        current_targets = await get_targets(wallet_id)
        
        # Update targets that reference the old lightning address
        updated_targets = []
        for target in current_targets:
            if target.wallet == old_lightning_address:
                # Update target to use new lightning address
                updated_target = Target(
                    id=target.id,
                    source=target.source,
                    wallet=new_lightning_address,  # Update this field
                    percent=target.percent,
                    alias=target.alias
                )
                updated_targets.append(updated_target)
                logger.info(f"✅ Updated split target: {old_lightning_address} -> {new_lightning_address}")
            else:
                # Keep existing target unchanged
                updated_targets.append(target)
        
        # Save updated targets
        await set_targets(wallet_id, updated_targets)
        
        return {
            "lnurl": new_lnurl,
            "user_id": user_id,
            "old_address": old_lightning_address,
            "new_address": new_lightning_address,
            "updates": {
                "user_email": "updated",
                "lnurlp_link": "updated",
                "split_targets": "updated"
            }
        }
    
async def cleanup_resources(lnurl, user_id, admin_key):
    base_url = "https://bringin.opago-pay.com"
    try:
        if lnurl:
            # Fetch the list of payment links using the admin key
            headers = await get_auth_headers(admin_key, base_url)
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{base_url}/lnurlp/api/v1/links", headers=headers)
                response.raise_for_status()
                pay_links = response.json()

            # Find the payment link ID matching the provided lnurl
            pay_id = None
            for link in pay_links:
                if link["lnurl"] == lnurl:
                    pay_id = link["id"]
                    break

            if pay_id:
                logger.info(f"Deleting LNURLp link: {pay_id}")
                await delete_lnurlp_link(pay_id, admin_key)
                logger.info("LNURLp link deleted")
            else:
                logger.warning(f"No matching payment link found for lnurl: {lnurl}")
    except Exception as cleanup_error:
        logger.error(f"Error during LNURLp link cleanup: {str(cleanup_error)}")

    try:
        if user_id:
            logger.info(f"Deleting user: {user_id}")
            await delete_user(user_id)
            logger.info("User deleted")
    except Exception as cleanup_error:
        logger.error(f"Error during user cleanup: {str(cleanup_error)}")
