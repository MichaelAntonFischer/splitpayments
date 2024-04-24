
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

API_BASE_URL = 'https://api.bringin.xyz'
BRINGIN_ENDPOINT_KEY = '/api/v0/application/api-key'
BRINGIN_ENDPOINT_OFFRAMP = '/api/v0/offramp/order'

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
    body_string = json.dumps(body, separators=(',', ':')) if body else '{}'
    md5_hasher = hashlib.md5()
    md5_hasher.update(body_string.encode())
    request_content_hex_string = md5_hasher.hexdigest()
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
        "label": label + lightning_address,  
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
    url = "https://bringin.opago-pay.com/usermanager/api/v1/users"
    headers = {
        "X-Api-Key": os.environ['OPAGO_KEY'],
        "Content-type": "application/json"
    }
    data = {
        "admin_id": admin_id,
        "user_name": user_name,
        "wallet_name": wallet_name,
        "email": lnaddress
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=data)
            response.raise_for_status()
            response_data = response.json()
            return response_data
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
async def activate_extensions(user_id: str, extensions: List[str]):
    url = "https://bringin.opago-pay.com/usermanager/api/v1/extensions"
    headers = {
        "X-Api-Key": os.environ['OPAGO_KEY'],
        "Content-type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            for extension in extensions:
                params = {
                    "extension": extension,
                    "userid": user_id,
                    "active": "true"
                }
                response = await client.post(url, headers=headers, params=params)
                response.raise_for_status()
            return {"extensions": "updated"}
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def create_lnurlp_link(lightning_address: str, admin_key: str, bringin_max: int = None, bringin_min: int = None):
    url = "https://bringin.opago-pay.com/lnurlp/api/v1/links"
    headers = {
        "X-Api-Key": admin_key,
        "Content-type": "application/json"
    }
    username = lightning_address.split("@")[0]
    
    if bringin_max is None:
        bringin_max = int(os.environ.get("BRINGIN_MAX", 0))
    if bringin_min is None:
        bringin_min = int(os.environ.get("BRINGIN_MIN", 0))
    
    data = {
        "description": "Offramp via Bringin",
        "max": bringin_max,
        "min": bringin_min,
        "comment_chars": 210,
        "username": username
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=data)
            response.raise_for_status()
            response_data = response.json()
            return response_data["lnurl"]
    except Exception as e:
        if "Username already exists" in str(e):
            raise HTTPException(status_code=409, detail="Username already exists. Try a different one.")
        else:
            raise HTTPException(status_code=500, detail=str(e))
    
async def delete_user(user_id: str):
    admin_key = os.environ["OPAGO_KEY"]
    headers = {"X-Api-Key": admin_key}
    url = f"https://bringin.opago-pay.com/usermanager/api/v1/users/{user_id}"
    async with httpx.AsyncClient() as client:
        response = await client.delete(url, headers=headers)
        if response.status_code != 204:
            raise Exception(f"Failed to delete user: {response.text}")
        
async def delete_lnurlp_link(pay_id: str, admin_key: str):
    headers = {"X-Api-Key": admin_key}
    url = f"https://bringin.opago-pay.com/lnurlp/api/v1/links/{pay_id}"
    async with httpx.AsyncClient() as client:
        response = await client.delete(url, headers=headers)
        if response.status_code != 204:
            raise Exception(f"Failed to delete LNURLp link: {response.text}")


