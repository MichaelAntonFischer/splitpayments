# Splitpayments API Testing Scripts

This directory contains comprehensive testing scripts to help diagnose and test the splitpayments API endpoints, particularly focusing on resolving 401 authentication errors.

## Prerequisites

The scripts can get secrets from either the `pass` password manager or environment variables (with `pass` being preferred).

### Option 1: Using pass (Recommended)

Store your secrets in pass under the `bringin/` directory:

```bash
pass insert bringin/OPAGO_KEY
pass insert bringin/BRINGIN_SECRET
```

### Option 2: Using Environment Variables

```bash
export OPAGO_KEY="your_opago_api_key"
export BRINGIN_SECRET="your_bringin_secret_key"
```

The scripts will automatically try `pass` first, then fallback to environment variables.

## Scripts Overview

### 1. `test_api_endpoints.py` - Comprehensive API Tester

This is the main testing script that tests all API endpoints with proper HMAC authentication.

#### Features:
- Tests all splitpayments API endpoints
- Detailed HMAC authentication debugging
- Comprehensive logging to file and console
- Support for testing individual endpoints
- JSON output for single tests

#### Usage:

```bash
# Run all tests
python tests/test_api_endpoints.py

# Run all tests with verbose output
python tests/test_api_endpoints.py --verbose

# Test a specific endpoint
python tests/test_api_endpoints.py --single-test add_user --test-address "user@example.com"

# Use custom base URL
python tests/test_api_endpoints.py --base-url "https://custom.domain.com/splitpayments/api/v1"

# Test with custom lightning address
python tests/test_api_endpoints.py --test-address "mytest@example.com"
```

#### Available Single Tests:
- `add_user` - Test adding a bringin user
- `update_user` - Test updating a bringin user
- `audit_all` - Test audit endpoint for all users
- `audit_single` - Test audit endpoint for specific user
- `targets` - Test targets CRUD endpoints
- `execute_split` - Test split execution endpoint

### 2. `debug_hmac.py` - HMAC Authentication Debugger

This script helps debug HMAC authentication issues by comparing implementations and testing edge cases.

#### Features:
- Compare different HMAC implementations
- Test edge cases that might cause authentication failures
- Generate custom HMAC signatures for debugging
- Detailed step-by-step HMAC generation logging

#### Usage:

```bash
# Compare HMAC implementations
python tests/debug_hmac.py --compare

# Test edge cases
python tests/debug_hmac.py --edge-cases

# Generate custom HMAC for debugging
python tests/debug_hmac.py --custom --method POST --path "/splitpayments/api/v1/add_bringin_user" --body '{"lightning_address":"test@example.com"}'

# Generate HMAC with custom timestamp
python tests/debug_hmac.py --custom --timestamp 1234567890123
```

### 3. `test_bringin.py` - Legacy CLI Tester

The original command-line testing script for bringin operations.

#### Usage:

```bash
# Create a new user
python tests/test_bringin.py create username wallet_name user@example.com

# Update user lightning address
python tests/test_bringin.py update old@example.com new@example.com

# Get audit data for specific user
python tests/test_bringin.py audit_one user@example.com

# Get audit data for all users
python tests/test_bringin.py audit_all
```

## Common Issues and Solutions

### 401 Unauthorized Error

This typically indicates an HMAC authentication issue. To diagnose:

1. **Check Environment Variables**: Ensure `OPAGO_KEY` and `BRINGIN_SECRET` are set correctly
2. **Verify HMAC Generation**: Use the debug script to verify HMAC generation:
   ```bash
   python tests/debug_hmac.py --compare
   ```
3. **Check Timestamps**: Ensure system time is synchronized
4. **Test with Known Values**: Use the debug script with fixed timestamps for reproducible results

### Server-Side Debugging

To debug server-side HMAC generation, look at the logs in `views_api.py` where the expected signature is logged:

```python
logger.info(f"Generated HMAC: {expected_signature}")
logger.info(f"Received HMAC: {signature}")
```

### Body Serialization Issues

The most common cause of HMAC mismatches is inconsistent JSON serialization. The scripts use:
- `json.dumps(body, separators=(',', ':'), sort_keys=True)` for consistent output
- Empty body is represented as `'{}'`

## Output Files

- `test_api.log` - Detailed debug logs from the comprehensive tester
- Test results are printed to console with clear success/failure indicators

## Dependencies

The test scripts require:
- `httpx` - For async HTTP requests
- `loguru` - For enhanced logging
- Standard library modules: `os`, `json`, `time`, `hmac`, `hashlib`, `argparse`

Install dependencies:
```bash
pip install httpx loguru
```

## Example Workflow

1. **Start with HMAC debugging**:
   ```bash
   python tests/debug_hmac.py --compare
   ```

2. **Run comprehensive tests**:
   ```bash
   python tests/test_api_endpoints.py --verbose --test-address "your@example.com"
   ```

3. **If issues persist, test specific endpoints**:
   ```bash
   python tests/test_api_endpoints.py --single-test add_user --test-address "debug@example.com"
   ```

4. **Check logs**:
   ```bash
   tail -f test_api.log
   ```

This approach should help identify and resolve the 401 authentication issues with the bringin API endpoints. 