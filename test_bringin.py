import os
import argparse
import asyncio
from bringin import (
    create_bringin_user,
    update_bringin_user,
    delete_user,
    get_bringin_audit_data
)


def main():
    parser = argparse.ArgumentParser(description="Test Bringin User Management")
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

    # Delete user
    delete_parser = subparsers.add_parser("delete", help="Delete bringin user by user_id")
    delete_parser.add_argument("user_id", help="User ID to delete")

    # Get audit data for a single user
    audit_one_parser = subparsers.add_parser("audit_one", help="Get audit data for a single user (by lnaddress)")
    audit_one_parser.add_argument("lnaddress", help="Lightning address (email) to audit")

    # Get audit data for all users
    audit_all_parser = subparsers.add_parser("audit_all", help="Get audit data for all users")

    args = parser.parse_args()

    # Get admin key and id from env
    admin_key = os.environ.get("OPAGO_KEY")
    admin_id = os.environ.get("OPAGO_ID")
    if not admin_key or not admin_id:
        print("OPAGO_KEY and OPAGO_ID must be set in environment.")
        exit(1)

    async def run():
        if args.command == "create":
            result = await create_bringin_user(admin_id, args.user_name, args.wallet_name, args.lnaddress)
            print("User created:", result)
        elif args.command == "update":
            result = await update_bringin_user(args.old_lnaddress, args.new_lnaddress, admin_key)
            print("User updated:", result)
        elif args.command == "delete":
            await delete_user(args.user_id)
            print(f"User {args.user_id} deleted.")
        elif args.command == "audit_one":
            result = await get_bringin_audit_data(admin_key, include_transactions=True, lnaddress=args.lnaddress)
            print("Audit data for user:", result)
        elif args.command == "audit_all":
            result = await get_bringin_audit_data(admin_key, include_transactions=True)
            print("Audit data for all users:", result)

    asyncio.run(run())

if __name__ == "__main__":
    main() 