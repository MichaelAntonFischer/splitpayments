import os
import argparse
import requests
import time
import json
import hmac
import hashlib

def generate_hmac_authorization(secret, method, path, body, timestamp=None):
    if timestamp is None:
        timestamp = str(int(time.time() * 1000))
    else:
        timestamp = str(timestamp)
    body_string = json.dumps(body, separators=(',', ':'), sort_keys=True) if body else '{}'
    body_bytes = body_string.encode('utf-8')
    md5_hasher = hashlib.md5()
    md5_hasher.update(body_bytes)
    request_content_hex_string = md5_hasher.hexdigest()
    signature_raw_data = timestamp + method + path + request_content_hex_string
    signature = hmac.new(secret.encode(), signature_raw_data.encode(), hashlib.sha256).hexdigest()
    return f"HMAC {timestamp}:{signature}"

def main():
    parser = argparse.ArgumentParser(description="Test Bringin User Management via API")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create user
    create_parser = subparsers.add_parser("create", help="Create a new bringin user")
    create_parser.add_argument("user_name", help="Username for the new user")
    create_parser.add_argument("wallet_name", help="Wallet name for the new user")
    create_parser.add_argument("lnaddress", help="Lightning address (email) for the new user")

    # Update user
    update_parser = subparsers.add_parser("update", help="Update bringin user lightning address")
    update_parser.add_argument("old_lnaddress", help="Old lightning address (email)")
    update_parser.add_argument("new_lnaddress", help="New lightning address (email)")

    # Delete user (not exposed via API, so not implemented)
    # delete_parser = subparsers.add_parser("delete", help="Delete bringin user by user_id")
    # delete_parser.add_argument("user_id", help="User ID to delete")

    # Get audit data for a single user
    audit_one_parser = subparsers.add_parser("audit_one", help="Get audit data for a single user (by lnaddress)")
    audit_one_parser.add_argument("lnaddress", help="Lightning address (email) to audit")

    # Get audit data for all users
    audit_all_parser = subparsers.add_parser("audit_all", help="Get audit data for all users")

    args = parser.parse_args()

    # Get API base URL and keys from env
    api_base = os.environ.get("API_BASE", "http://localhost:5000/splitpayments/api/v1")
    opago_key = os.environ.get("OPAGO_KEY")
    bringin_secret = os.environ.get("BRINGIN_SECRET")
    if not opago_key or not bringin_secret:
        print("OPAGO_KEY and BRINGIN_SECRET must be set in environment.")
        exit(1)

    session = requests.Session()

    if args.command == "create":
        url = f"{api_base}/add_bringin_user"
        body = {
            "lightning_address": args.lnaddress
        }
        # Path must match exactly as in FastAPI route
        path = "/splitpayments/api/v1/add_bringin_user"
        method = "POST"
        signature = generate_hmac_authorization(bringin_secret, method, path, body)
        headers = {
            "Authorization": signature,
            "X-Api-Key": opago_key,
            "Content-Type": "application/json"
        }
        resp = session.post(url, headers=headers, json=body)
        print("Status:", resp.status_code)
        print("Response:", resp.text)

    elif args.command == "update":
        url = f"{api_base}/update_bringin_user"
        body = {
            "old_lightning_address": args.old_lnaddress,
            "new_lightning_address": args.new_lnaddress
        }
        path = "/splitpayments/api/v1/update_bringin_user"
        method = "POST"
        signature = generate_hmac_authorization(bringin_secret, method, path, body)
        headers = {
            "Authorization": signature,
            "X-Api-Key": opago_key,
            "Content-Type": "application/json"
        }
        resp = session.post(url, headers=headers, json=body)
        print("Status:", resp.status_code)
        print("Response:", resp.text)

    elif args.command == "audit_one":
        lnaddress = args.lnaddress
        url = f"{api_base}/bringin_audit?lnaddress={lnaddress}&include_transactions=true"
        path = "/splitpayments/api/v1/bringin_audit"
        method = "GET"
        signature = generate_hmac_authorization(bringin_secret, method, path, {})
        headers = {
            "Authorization": signature,
            "X-Api-Key": opago_key
        }
        resp = session.get(url, headers=headers)
        print("Status:", resp.status_code)
        print("Response:", resp.text)

    elif args.command == "audit_all":
        url = f"{api_base}/bringin_audit?include_transactions=true"
        path = "/splitpayments/api/v1/bringin_audit"
        method = "GET"
        signature = generate_hmac_authorization(bringin_secret, method, path, {})
        headers = {
            "Authorization": signature,
            "X-Api-Key": opago_key
        }
        resp = session.get(url, headers=headers)
        print("Status:", resp.status_code)
        print("Response:", resp.text)

if __name__ == "__main__":
    main() 