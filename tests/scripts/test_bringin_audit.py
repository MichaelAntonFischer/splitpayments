#!/usr/bin/env python3

import os
import json
import time
import hmac
import hashlib
import httpx
import argparse
from loguru import logger

def generate_hmac_authorization(secret, method, path, body, timestamp=None):
    # Use the provided timestamp or generate a new one if not provided
    if timestamp is None:
        timestamp = str(int(time.time() * 1000))
    else:
        timestamp = str(timestamp)  # Ensure timestamp is a string even if it's provided as an integer

    # Add quotes to match server's format
    secret = f'"{secret}"'
    logger.info(f"Secret (raw): {secret}")
    logger.info(f"Secret length: {len(secret)}")
    logger.info(f"Secret bytes (hex): {secret.encode().hex()}")
    
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
    logger.info(f"Raw Data bytes (hex): {signature_raw_data.encode().hex()}")

    signature = hmac.new(secret.encode(), signature_raw_data.encode(), hashlib.sha256).hexdigest()
    return f"HMAC {timestamp}:{signature}"

async def test_bringin_audit(username=None, include_transactions=False):
    # Check environment variables
    if not os.environ.get('OPAGO_KEY') or not os.environ.get('BRINGIN_SECRET'):
        logger.error("Error: OPAGO_KEY and BRINGIN_SECRET environment variables must be set")
        return

    # Configuration
    base_url = "https://bringin.opago-pay.com"
    base_path = "/splitpayments/api/v1/bringin_audit"  # Base path for HMAC calculation

    # Build query parameters for the request URL
    params = []
    if username:
        params.append(f"lnaddress={username}")
    if include_transactions:
        params.append("include_transactions=true")
    
    # Full URL for the request
    request_url = f"{base_url}{base_path}"
    if params:
        request_url = f"{request_url}?{'&'.join(params)}"

    print("\n\033[32mTesting Bringin audit endpoint\033[0m")
    print(f"\033[32mUsername: {username if username else 'all users'}\033[0m")
    print(f"\033[32mInclude transactions: {include_transactions}\033[0m")
    print("----------------------------------------")

    # Generate HMAC using the base path (without query parameters)
    timestamp = str(int(time.time() * 1000))
    auth_header = generate_hmac_authorization(
        os.environ['BRINGIN_SECRET'],
        "GET",
        base_path,  # Use base path for HMAC calculation
        {},
        timestamp
    )

    print("\n\033[34mExecuting request:\033[0m")
    print(f"GET {request_url}")
    print(f"Authorization: {auth_header}")
    print(f"api-key: {os.environ['OPAGO_KEY']}")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            request_url,
            headers={
                "Authorization": auth_header,
                "api-key": os.environ['OPAGO_KEY']
            }
        )

        print("\n\033[32mResponse:\033[0m")
        try:
            print(json.dumps(response.json(), indent=2))
        except:
            print(response.text)

    print("\n\033[32mTesting completed!\033[0m")

async def run_all_tests():
    # Test 1: All users without transactions (known working case)
    await test_bringin_audit()

    # Test 2: All users with transactions
    await test_bringin_audit(include_transactions=True)

    # Test 3: Specific user without transactions
    await test_bringin_audit(username="michaelantonf")

    # Test 4: Specific user with transactions
    await test_bringin_audit(username="michaelantonf", include_transactions=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test Bringin audit endpoint')
    parser.add_argument('--username', '-u', help='Optional username to filter results')
    parser.add_argument('--transactions', '-t', action='store_true', help='Include transactions in response')
    parser.add_argument('--all', '-a', action='store_true', help='Run all test combinations')
    args = parser.parse_args()

    import asyncio
    if args.all:
        asyncio.run(run_all_tests())
    else:
        asyncio.run(test_bringin_audit(args.username, args.transactions)) 