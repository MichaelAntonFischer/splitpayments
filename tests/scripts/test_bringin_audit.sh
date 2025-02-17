#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 -l <lightning_address>"
    echo "Example: $0 -l michaelantonf@bringin.xyz"
    exit 1
}

# Function to check if environment variables are set
check_env() {
    if [ -z "$OPAGO_KEY" ]; then
        echo -e "${RED}Error: OPAGO_KEY environment variable is not set${NC}"
        exit 1
    fi
}

# Parse command line arguments
while getopts "l:" opt; do
    case $opt in
        l) LIGHTNING_ADDRESS="$OPTARG"
        ;;
        \?) echo "Invalid option -$OPTARG" >&2
            usage
        ;;
    esac
done

# Check if lightning address is provided
if [ -z "$LIGHTNING_ADDRESS" ]; then
    echo -e "${RED}Error: Lightning address is required${NC}"
    usage
fi

# Extract username from lightning address
USERNAME=$(echo "$LIGHTNING_ADDRESS" | cut -d@ -f1)

# Check environment variables
check_env

# Base URL and endpoint
BASE_URL="https://bringin.opago-pay.com"
AUDIT_ENDPOINT="/usermanager/api/v1/audit"

echo -e "${GREEN}Testing Bringin audit endpoint for username: $USERNAME${NC}"
echo "----------------------------------------"

# Display and execute the curl command for audit data
echo -e "${BLUE}Executing command:${NC}"
echo "curl -s -X GET \"$BASE_URL$AUDIT_ENDPOINT?email=$USERNAME&include_transactions=true\" \\"
echo "    -H \"X-Api-Key: $OPAGO_KEY\""

AUDIT_RESPONSE=$(curl -s -X GET "$BASE_URL$AUDIT_ENDPOINT?email=$USERNAME&include_transactions=true" \
    -H "X-Api-Key: $OPAGO_KEY")

echo -e "\n${GREEN}Audit Response:${NC}"
echo "$AUDIT_RESPONSE" | jq '.'

echo -e "\n${GREEN}Testing completed successfully!${NC}" 