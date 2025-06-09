#!/usr/bin/env python3
"""
Comprehensive test script for splitpayments API endpoints.
This script tests all endpoints and helps diagnose 401 authentication issues.
"""

import os
import asyncio
import json
import time
import hmac
import hashlib
import argparse
import subprocess
from typing import Dict, Any, Optional
import httpx
from loguru import logger

# Configure logger
logger.add("test_api.log", level="DEBUG", format="{time} | {level} | {message}")

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
        logger.error(f"Failed to get secret from pass: {secret_path}")
        logger.error(f"Error: {e.stderr}")
        raise ValueError(f"Could not retrieve secret from pass: {secret_path}")
    except FileNotFoundError:
        raise ValueError("'pass' command not found. Please install pass password manager.")

class APITester:
    def __init__(self):
        # Load secrets from pass or environment variables
        self.opago_key = self._load_secret_from_pass_or_env("bringin/OPAGO_KEY", "OPAGO_KEY")
        self.bringin_secret = self._load_secret_from_pass_or_env("bringin/BRINGIN_SECRET", "BRINGIN_SECRET")
        
        # Generate unique test addresses with timestamp
        timestamp = str(int(time.time()))
        self.test_address = f"test-{timestamp}@bringin.xyz"
        self.new_test_address = f"new-test-{timestamp}@bringin.xyz"
        
        self.base_url = "https://bringin.opago-pay.com/splitpayments/api/v1"
        self.api_prefix = "/splitpayments/api/v1"
        
        logger.info(f"Base URL: {self.base_url}")
        logger.info(f"API Prefix: {self.api_prefix}")
        
    def _load_secret_from_pass_or_env(self, pass_path: str, env_var: str) -> str:
        """Load secret from pass or environment variable."""
        try:
            secret = get_pass_secret(pass_path)
            logger.info(f"{env_var} loaded from pass")
            return secret
        except ValueError:
            secret = os.environ.get(env_var)
            if secret:
                logger.info(f"{env_var} loaded from environment variable")
                return secret
            else:
                raise ValueError(f"{env_var} not found in pass ({pass_path}) or environment variables")

    def generate_hmac_authorization(self, method: str, path: str, body: Dict[str, Any] = None, timestamp: int = None) -> str:
        """Generate HMAC authorization header matching the server-side implementation."""
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        
        timestamp_str = str(timestamp)
        
        # Handle body serialization consistently
        if body is None:
            body_string = '{}'
        else:
            body_string = json.dumps(body, separators=(',', ':'), sort_keys=True)
        
        logger.debug(f"HMAC Generation:")
        logger.debug(f"  Secret: {self.bringin_secret}")
        logger.debug(f"  Method: {method}")
        logger.debug(f"  Path: {path}")
        logger.debug(f"  Body string: {body_string}")
        logger.debug(f"  Timestamp: {timestamp_str}")
        
        # Generate MD5 hash of body
        body_bytes = body_string.encode('utf-8')
        logger.debug(f"  Body bytes (hex): {body_bytes.hex()}")
        
        md5_hasher = hashlib.md5()
        md5_hasher.update(body_bytes)
        request_content_hex_string = md5_hasher.hexdigest()
        logger.debug(f"  MD5 hash: {request_content_hex_string}")
        
        # Create signature raw data
        signature_raw_data = timestamp_str + method + path + request_content_hex_string
        logger.debug(f"  Raw data for HMAC: {signature_raw_data}")
        
        # Generate HMAC signature
        signature = hmac.new(
            self.bringin_secret.encode(), 
            signature_raw_data.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        hmac_auth = f"HMAC {timestamp_str}:{signature}"
        logger.debug(f"  Generated HMAC: {hmac_auth}")
        
        return hmac_auth
    
    async def test_endpoint(self, method: str, endpoint: str, body: Dict[str, Any] = None, 
                          params: Dict[str, str] = None, description: str = "Test") -> Dict[str, Any]:
        """Test a single API endpoint."""
        full_url = f"{self.base_url}{endpoint}"
        path = f"{self.api_prefix}{endpoint}"
        
        logger.info(f"\n=== {description} ===")
        logger.info(f"URL: {full_url}")
        logger.info(f"Method: {method}")
        logger.info(f"Path for HMAC: {path}")
        
        try:
            # Generate HMAC signature
            hmac_auth = self.generate_hmac_authorization(method, path, body)
            
            # Prepare headers
            headers = {
                "Authorization": hmac_auth,
                "X-Api-Key": self.opago_key,
                "Content-Type": "application/json"
            }
            
            logger.info(f"Headers: {headers}")
            if body:
                logger.info(f"Body: {json.dumps(body, indent=2)}")
            if params:
                logger.info(f"Params: {params}")
            
            # Make request
            async with httpx.AsyncClient(timeout=30.0) as client:
                if method.upper() == "GET":
                    response = await client.get(full_url, headers=headers, params=params)
                elif method.upper() == "POST":
                    response = await client.post(full_url, headers=headers, json=body, params=params)
                elif method.upper() == "PUT":
                    response = await client.put(full_url, headers=headers, json=body, params=params)
                elif method.upper() == "DELETE":
                    response = await client.delete(full_url, headers=headers, params=params)
                else:
                    raise ValueError(f"Unsupported method: {method}")
            
            logger.info(f"Status Code: {response.status_code}")
            logger.info(f"Response Headers: {dict(response.headers)}")
            
            # Try to parse JSON response
            try:
                response_data = response.json()
                logger.info(f"Response JSON: {json.dumps(response_data, indent=2)}")
            except:
                logger.info(f"Response Text: {response.text}")
                response_data = {"raw_text": response.text}
            
            return {
                "success": 200 <= response.status_code < 300,
                "status_code": response.status_code,
                "response": response_data,
                "description": description
            }
            
        except Exception as e:
            logger.error(f"Error testing {endpoint}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "description": description
            }
    
    async def test_add_bringin_user(self, lightning_address: str) -> Dict[str, Any]:
        """Test adding a bringin user."""
        body = {"lightning_address": lightning_address}
        return await self.test_endpoint(
            "POST", 
            "/add_bringin_user", 
            body, 
            description=f"Add Bringin User: {lightning_address}"
        )
    
    async def test_update_bringin_user(self, old_address: str, new_address: str) -> Dict[str, Any]:
        """Test updating a bringin user."""
        body = {
            "old_lightning_address": old_address,
            "new_lightning_address": new_address
        }
        return await self.test_endpoint(
            "POST", 
            "/update_bringin_user", 
            body, 
            description=f"Update Bringin User: {old_address} -> {new_address}"
        )
    
    async def test_bringin_audit(self, lnaddress: str = None, include_transactions: bool = True) -> Dict[str, Any]:
        """Test bringin audit endpoint."""
        params = {"include_transactions": str(include_transactions).lower()}
        if lnaddress:
            params["lnaddress"] = lnaddress
        
        description = f"Bringin Audit"
        if lnaddress:
            description += f" for {lnaddress}"
        if include_transactions:
            description += " (with transactions)"
        
        return await self.test_endpoint(
            "GET", 
            "/bringin_audit", 
            params=params, 
            description=description
        )
    
    async def test_targets_endpoints(self) -> Dict[str, Any]:
        """Test the targets CRUD endpoints."""
        results = {}
        
        # Test GET targets
        results["get_targets"] = await self.test_endpoint(
            "GET",
            "/targets",
            description="Get Targets"
        )
        
        # Test PUT targets (this requires admin key, might fail)
        sample_targets = {
            "targets": [
                {
                    "wallet": "test@example.com",
                    "percent": 50,
                    "alias": "Test Target"
                }
            ]
        }
        results["put_targets"] = await self.test_endpoint(
            "PUT",
            "/targets",
            sample_targets,
            description="Set Targets (Sample)"
        )
        
        # Test DELETE targets
        results["delete_targets"] = await self.test_endpoint(
            "DELETE",
            "/targets",
            description="Delete Targets"
        )
        
        return results
    
    async def test_execute_split_for_all(self) -> Dict[str, Any]:
        """Test execute split for all endpoint."""
        return await self.test_endpoint(
            "POST",
            "/execute_split_for_all",
            description="Execute Split for All"
        )
    
    async def run_comprehensive_test(self):
        """Run comprehensive tests on all endpoints."""
        logger.info("Starting comprehensive API endpoint tests...")
        
        results = {}
        
        # Test basic endpoints first
        logger.info("\n" + "="*50)
        logger.info("TESTING BASIC ENDPOINTS")
        logger.info("="*50)
        
        # Test targets endpoints
        results["targets"] = await self.test_targets_endpoints()
        
        # Test execute split for all
        results["execute_split"] = await self.test_execute_split_for_all()
        
        # Test bringin-specific endpoints
        logger.info("\n" + "="*50)
        logger.info("TESTING BRINGIN ENDPOINTS")
        logger.info("="*50)
        
        # Test audit endpoints
        results["audit_all"] = await self.test_bringin_audit()
        
        # Use dynamic test addresses
        results["audit_single"] = await self.test_bringin_audit(self.test_address)
        results["add_user"] = await self.test_add_bringin_user(self.test_address)
        
        # Test update user (from test address to new test address)
        results["update_user"] = await self.test_update_bringin_user(
            self.test_address, 
            self.new_test_address
        )
        
        # Summary
        logger.info("\n" + "="*50)
        logger.info("TEST RESULTS SUMMARY")
        logger.info("="*50)
        
        for category, tests in results.items():
            if isinstance(tests, dict) and "success" in tests:
                # Single test result
                status = "✅ PASS" if tests["success"] else "❌ FAIL"
                logger.info(f"{status} {tests['description']} (Status: {tests.get('status_code', 'N/A')})")
            elif isinstance(tests, dict):
                # Multiple test results
                for test_name, test_result in tests.items():
                    if isinstance(test_result, dict) and "success" in test_result:
                        status = "✅ PASS" if test_result["success"] else "❌ FAIL"
                        logger.info(f"{status} {test_result['description']} (Status: {test_result.get('status_code', 'N/A')})")
        
        return results


async def main():
    parser = argparse.ArgumentParser(description="Comprehensive API endpoint tester for splitpayments")
    parser.add_argument("--base-url", help="Base API URL", 
                      default="https://bringin.opago-pay.com/splitpayments/api/v1")
    parser.add_argument("--api-prefix", help="API prefix for HMAC path", 
                      default="/splitpayments/api/v1")
    parser.add_argument("--test-address", help="Lightning address to use for testing", 
                      default="test@example.com")
    parser.add_argument("--single-test", choices=[
        "add_user", "update_user", "audit_all", "audit_single", 
        "targets", "execute_split"
    ], help="Run only a single test")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.add(lambda msg: print(msg), level="DEBUG")
    
    try:
        tester = APITester()
        
        if args.single_test:
            # Run single test
            if args.single_test == "add_user":
                result = await tester.test_add_bringin_user(args.test_address)
            elif args.single_test == "update_user":
                result = await tester.test_update_bringin_user(args.test_address, args.test_address)
            elif args.single_test == "audit_all":
                result = await tester.test_bringin_audit()
            elif args.single_test == "audit_single":
                result = await tester.test_bringin_audit(args.test_address)
            elif args.single_test == "targets":
                result = await tester.test_targets_endpoints()
            elif args.single_test == "execute_split":
                result = await tester.test_execute_split_for_all()
            
            print(json.dumps(result, indent=2))
        else:
            # Run comprehensive test
            await tester.run_comprehensive_test()
            
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main())) 