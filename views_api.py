import os
import time
import json 

from http import HTTPStatus
from typing import List

from fastapi import Depends, Request
from loguru import logger
from starlette.exceptions import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_200_OK

from lnbits.core.crud import get_wallet, get_wallet_for_key
from lnbits.decorators import WalletTypeInfo, check_admin, require_admin_key

from .tasks import execute_split
from . import scheduled_tasks, splitpayments_ext
from .crud import get_targets, set_targets
from .models import Target, TargetPutList
from .bringin import create_bringin_user, activate_extensions, create_lnurlp_link, generate_hmac_authorization, delete_user, delete_lnurlp_link

@splitpayments_ext.get("/api/v1/targets")
async def api_targets_get(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> List[Target]:
    targets = await get_targets(wallet.wallet.id)
    return targets or []


@splitpayments_ext.post("/api/v1/execute_split", status_code=HTTPStatus.OK)
async def api_execute_split(wallet_id: str, amount: int) -> None:
    result = await execute_split(wallet_id, amount)
    return result

@splitpayments_ext.post("/api/v1/add_bringin_user", status_code=HTTP_200_OK)
async def add_bringin_user(lightning_address: str, request: Request):
    body = await request.json()
    signature = request.headers.get("Authorization")
    secret = os.environ["BRINGIN_SECRET"]

    # Include lightning_address in the body for HMAC generation
    body['lightning_address'] = lightning_address  # Ensure this key matches client's key

    # Extract timestamp from the client's HMAC and ensure it's a string
    client_timestamp_str = signature.split()[1].split(':')[0]

    # Serialize body with consistent order
    body_string = json.dumps(body, separators=(',', ':'), sort_keys=True)
    raw_data = client_timestamp_str + request.method + request.url.path + body_string

    # Generate expected HMAC signature using the client's timestamp and the full request path
    expected_signature = generate_hmac_authorization(secret, request.method, request.url.path, body, client_timestamp_str)

    # Log the received and the generated HMAC
    logger.info(f"Generated HMAC: {expected_signature}")
    logger.info(f"Received HMAC: {signature}")

    if not signature == expected_signature:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    admin_id = os.environ['OPAGO_ID']
    user_name = lightning_address.split("@")[0]
    wallet_name = "Offramp"

    try:
        logger.info("Creating Bringin user")
        user_data = await create_bringin_user(admin_id, user_name, wallet_name, lightning_address)
        user_id = user_data["id"]
        invoice_key = user_data["wallets"][0]["inkey"]
        wallet_id = user_data["wallets"][0]["id"]
        admin_key = user_data["wallets"][0]["adminkey"]  # Get the admin key of the newly created user
        logger.info(f"User created with ID: {user_id}, Invoice Key: {invoice_key}, Admin Key: {admin_key}, Wallet ID: {wallet_id}")

        logger.info("Activating extensions for the user")
        await activate_extensions(user_id, ["splitpayments", "lnurlp"])
        logger.info("Extensions activated")

        logger.info("Creating LNURLp link")
        lnurl = None
        try:
            lnurl = await create_lnurlp_link(lightning_address, admin_key)  
            logger.info(f"LNURLp link created: {lnurl}")
        except Exception as e:
            if "Username already exists" in str(e):
                logger.warning(f"Username already exists: {lightning_address}")
                raise HTTPException(status_code=409, detail=str(e))
            else:
                raise

        logger.info("Setting targets for the wallet")
        target = Target(wallet=lightning_address, percent=100, alias="Offramp Order")
        await set_targets(wallet_id, [target])  
        logger.info("Targets set")

        return {"lnurl": lnurl}

    except HTTPException as e:
        raise e

    except Exception as e:
        logger.error(f"Error during setup: {str(e)}")

        # Cleanup: Delete the created user and LNURLp link
        try:
            if lnurl:
                pay_id = lnurl.split("/")[-1]  # Extract the pay_id from the LNURLp link
                logger.info(f"Deleting LNURLp link: {pay_id}")
                await delete_lnurlp_link(pay_id, admin_key)  # Use the admin key of the new user
                logger.info("LNURLp link deleted")
            
            if user_id:
                logger.info(f"Deleting user: {user_id}")
                await delete_user(user_id)
                logger.info("User deleted")

        except Exception as cleanup_error:
            logger.error(f"Error during cleanup: {str(cleanup_error)}")

        raise HTTPException(status_code=500, detail=str(e))

    except HTTPException as e:
        raise e

    except Exception as e:
        logger.error(f"Error during setup: {str(e)}")

        # Cleanup: Delete the created user and LNURLp link
        try:
            if user_id:
                logger.info(f"Deleting user: {user_id}")
                await delete_user(user_id)
                logger.info("User deleted")

            if lnurl:
                pay_id = lnurl.split("/")[-1]  # Extract the pay_id from the LNURLp link
                logger.info(f"Deleting LNURLp link: {pay_id}")
                await delete_lnurlp_link(pay_id)
                logger.info("LNURLp link deleted")

        except Exception as cleanup_error:
            logger.error(f"Error during cleanup: {str(cleanup_error)}")

        raise HTTPException(status_code=500, detail=str(e))

@splitpayments_ext.put("/api/v1/targets", status_code=HTTPStatus.OK)
async def api_targets_set(
    target_put: TargetPutList,
    source_wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    try:
        targets: List[Target] = []
        for entry in target_put.targets:

            if entry.wallet.find("@") < 0 and entry.wallet.find("LNURL") < 0:
                wallet = await get_wallet(entry.wallet)
                if not wallet:
                    wallet = await get_wallet_for_key(entry.wallet, "invoice")
                    if not wallet:
                        raise HTTPException(
                            status_code=HTTPStatus.BAD_REQUEST,
                            detail=f"Invalid wallet '{entry.wallet}'.",
                        )

                if wallet.id == source_wallet.wallet.id:
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST, detail="Can't split to itself."
                    )

            if entry.percent <= 0:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"Invalid percent '{entry.percent}'.",
                )

            targets.append(
                Target(
                    wallet=entry.wallet,
                    source=source_wallet.wallet.id,
                    percent=entry.percent,
                    alias=entry.alias,
                )
            )

            percent_sum = sum([target.percent for target in targets])
            if percent_sum > 100:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST, detail="Splitting over 100%"
                )

        await set_targets(source_wallet.wallet.id, targets)

    except Exception as ex:
        logger.warning(ex)
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Cannot set targets.",
        )


@splitpayments_ext.delete("/api/v1/targets", status_code=HTTPStatus.OK)
async def api_targets_delete(
    source_wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    await set_targets(source_wallet.wallet.id, [])


# deinit extension invoice listener
@splitpayments_ext.delete(
    "/api/v1", status_code=HTTPStatus.OK, dependencies=[Depends(check_admin)]
)
async def api_stop():
    for t in scheduled_tasks:
        try:
            t.cancel()
        except Exception as ex:
            logger.warning(ex)
    return {"success": True}
