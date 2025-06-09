#!/usr/bin/env python3
"""
Debug script for HMAC authentication issues.
This script helps identify discrepancies between client and server HMAC generation.
"""

import os
import json
import time
import hmac
import hashlib
import argparse
import subprocess


def get_pass_secret(secret_path: str) -> str:
    """Get secret from pass password manager."""
    try:
        result = subprocess.run(
            ['pass', secret_path], 
            capture_output=True, 
            text=True, 
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to get secret from pass: {secret_path}")
        print(f"Error: {e.stderr}")
        raise ValueError(f"Could not retrieve secret from pass: {secret_path}")
    except FileNotFoundError:
        raise ValueError("'pass' command not found. Please install pass password manager.")


def generate_hmac_authorization(secret, method, path, body, timestamp=None):
    """
    Generate HMAC authorization header exactly as the server does.
    This matches the implementation in bringin.py and views_api.py
    """
    # Use the provided timestamp or generate a new one if not provided
    if timestamp is None:
        timestamp = str(int(time.time() * 1000))
    else:
        timestamp = str(timestamp)  # Ensure timestamp is a string

    print(f"🔑 Secret: {secret}")
    print(f"📅 Timestamp: {timestamp}")
    print(f"🔧 Method: {method}")
    print(f"🛤️  Path: {path}")
    
    # Handle body serialization
    if body is None:
        body_string = '{}'
    elif isinstance(body, str):
        body_string = body
    else:
        body_string = json.dumps(body, separators=(',', ':'), sort_keys=True)
    
    print(f"📄 Body string: {body_string}")
    
    # Convert the body string to bytes and log the hexadecimal representation
    body_bytes = body_string.encode('utf-8')
    hex_representation = body_bytes.hex()
    print(f"🔢 Bytes for Hashing (Hex): {hex_representation}")

    # Generate MD5 hash
    md5_hasher = hashlib.md5()
    md5_hasher.update(body_bytes)
    request_content_hex_string = md5_hasher.hexdigest()
    print(f"🔐 MD5 Hash: {request_content_hex_string}")

    # Create signature raw data
    signature_raw_data = timestamp + method + path + request_content_hex_string
    print(f"📝 Raw Data for HMAC: {signature_raw_data}")

    # Generate HMAC signature
    signature = hmac.new(secret.encode(), signature_raw_data.encode(), hashlib.sha256).hexdigest()
    print(f"✍️  HMAC Signature: {signature}")
    
    hmac_auth = f"HMAC {timestamp}:{signature}"
    print(f"🎯 Final Authorization Header: {hmac_auth}")
    
    return hmac_auth


def compare_hmac_implementations():
    """Compare different HMAC implementations to identify issues."""
    print("=" * 60)
    print("🔍 HMAC IMPLEMENTATION COMPARISON")
    print("=" * 60)
    
    # Test parameters - try pass first, then environment variable
    try:
        secret = get_pass_secret("bringin/BRINGIN_SECRET")
        print("🔑 Secret loaded from pass")
    except ValueError:
        secret = os.environ.get("BRINGIN_SECRET", "test_secret")
        if secret != "test_secret":
            print("🔑 Secret loaded from environment variable")
        else:
            print("⚠️  Using test_secret (no pass or env var found)")
    method = "POST"
    path = "/splitpayments/api/v1/add_bringin_user"
    body = {"lightning_address": "test@example.com"}
    timestamp = 1234567890123  # Fixed timestamp for reproducible results
    
    print("\n📊 Test Parameters:")
    print(f"   Secret: {secret}")
    print(f"   Method: {method}")
    print(f"   Path: {path}")
    print(f"   Body: {body}")
    print(f"   Timestamp: {timestamp}")
    
    print("\n" + "-" * 60)
    print("🔧 Implementation 1: Current (bringin.py style)")
    print("-" * 60)
    hmac1 = generate_hmac_authorization(secret, method, path, body, timestamp)
    
    print("\n" + "-" * 60)
    print("🔧 Implementation 2: Alternative (views_api.py style)")
    print("-" * 60)
    
    # Alternative implementation (as seen in views_api.py)
    timestamp_str = str(timestamp)
    body_string = json.dumps(body, separators=(',', ':'), sort_keys=True)
    print(f"📄 Body string (alt): {body_string}")
    
    body_bytes = body_string.encode('utf-8')
    md5_hasher = hashlib.md5()
    md5_hasher.update(body_bytes)
    request_content_hex_string = md5_hasher.hexdigest()
    print(f"🔐 MD5 Hash (alt): {request_content_hex_string}")
    
    signature_raw_data = timestamp_str + method + path + request_content_hex_string
    print(f"📝 Raw Data for HMAC (alt): {signature_raw_data}")
    
    signature = hmac.new(secret.encode(), signature_raw_data.encode(), hashlib.sha256).hexdigest()
    print(f"✍️  HMAC Signature (alt): {signature}")
    
    hmac2 = f"HMAC {timestamp_str}:{signature}"
    print(f"🎯 Final Authorization Header (alt): {hmac2}")
    
    print("\n" + "=" * 60)
    print("📋 COMPARISON RESULTS")
    print("=" * 60)
    
    if hmac1 == hmac2:
        print("✅ IMPLEMENTATIONS MATCH!")
    else:
        print("❌ IMPLEMENTATIONS DIFFER!")
        print(f"   Implementation 1: {hmac1}")
        print(f"   Implementation 2: {hmac2}")
    
    return hmac1, hmac2


def test_edge_cases():
    """Test edge cases that might cause HMAC mismatches."""
    print("\n" + "=" * 60)
    print("🧪 EDGE CASE TESTING")
    print("=" * 60)
    
    # Try pass first, then environment variable
    try:
        secret = get_pass_secret("bringin/BRINGIN_SECRET")
    except ValueError:
        secret = os.environ.get("BRINGIN_SECRET", "test_secret")
    
    # Test cases
    test_cases = [
        {
            "name": "Empty body",
            "method": "GET",
            "path": "/splitpayments/api/v1/bringin_audit",
            "body": None
        },
        {
            "name": "Empty object body",
            "method": "POST",
            "path": "/splitpayments/api/v1/add_bringin_user",
            "body": {}
        },
        {
            "name": "Complex body with special characters",
            "method": "POST",
            "path": "/splitpayments/api/v1/add_bringin_user",
            "body": {"lightning_address": "test+special@example.com", "data": "test & data"}
        },
        {
            "name": "Path with query parameters",
            "method": "GET",
            "path": "/splitpayments/api/v1/bringin_audit?include_transactions=true",
            "body": None
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n📋 Test Case {i}: {test_case['name']}")
        print("-" * 40)
        
        try:
            hmac_auth = generate_hmac_authorization(
                secret, 
                test_case["method"], 
                test_case["path"], 
                test_case["body"]
            )
            print(f"✅ Success: {hmac_auth}")
        except Exception as e:
            print(f"❌ Error: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description="Debug HMAC authentication issues")
    parser.add_argument("--compare", action="store_true", help="Compare HMAC implementations")
    parser.add_argument("--edge-cases", action="store_true", help="Test edge cases")
    parser.add_argument("--custom", action="store_true", help="Generate custom HMAC")
    parser.add_argument("--method", default="POST", help="HTTP method for custom HMAC")
    parser.add_argument("--path", default="/splitpayments/api/v1/add_bringin_user", help="Path for custom HMAC")
    parser.add_argument("--body", help="JSON body for custom HMAC (as string)")
    parser.add_argument("--timestamp", type=int, help="Custom timestamp")
    
    args = parser.parse_args()
    
    # Check for secrets availability
    try:
        get_pass_secret("bringin/BRINGIN_SECRET")
        print("🔑 BRINGIN_SECRET found in pass")
    except ValueError:
        if not os.environ.get("BRINGIN_SECRET"):
            print("⚠️  Warning: BRINGIN_SECRET not found in pass or environment variables, using test_secret")
    
    if args.compare or not any([args.edge_cases, args.custom]):
        compare_hmac_implementations()
    
    if args.edge_cases:
        test_edge_cases()
    
    if args.custom:
        print("\n" + "=" * 60)
        print("🎯 CUSTOM HMAC GENERATION")
        print("=" * 60)
        
        # Try pass first, then environment variable
        try:
            secret = get_pass_secret("bringin/BRINGIN_SECRET")
        except ValueError:
            secret = os.environ.get("BRINGIN_SECRET", "test_secret")
        body = None
        
        if args.body:
            try:
                body = json.loads(args.body)
            except json.JSONDecodeError:
                print(f"❌ Invalid JSON body: {args.body}")
                return 1
        
        hmac_auth = generate_hmac_authorization(
            secret, 
            args.method, 
            args.path, 
            body, 
            args.timestamp
        )
        
        print(f"\n🎯 Generated HMAC for custom parameters:")
        print(f"   Authorization: {hmac_auth}")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main()) 