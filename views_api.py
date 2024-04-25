import os
import csv
import io
import smtplib
import json 

from http import HTTPStatus
from typing import List

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

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
from .bringin import add_bringin_user, generate_hmac_authorization, get_bringin_audit_data, update_bringin_user

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
async def add_bringin_user_endpoint(request: Request):
    body = await request.json()
    lightning_address = body.get("lightning_address")

    signature = request.headers.get("Authorization")
    secret = os.environ["BRINGIN_SECRET"]
    admin_key = os.environ["OPAGO_KEY"]

    client_timestamp_str = signature.split()[1].split(':')[0]
    expected_signature = generate_hmac_authorization(secret, request.method, request.url.path, body, client_timestamp_str)

    logger.info(f"Generated HMAC: {expected_signature}")
    logger.info(f"Received HMAC: {signature}")

    if not signature == expected_signature:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    try:
        result = await add_bringin_user(lightning_address, admin_key)
        return result

    except HTTPException as e:
        raise e

    except Exception as e:
        logger.error(f"Error during setup: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@splitpayments_ext.post("/api/v1/update_bringin_user", status_code=HTTP_200_OK)
async def update_bringin_user_endpoint(request: Request):
    body = await request.json()
    old_lightning_address = body.get("old_lightning_address")
    new_lightning_address = body.get("new_lightning_address")

    signature = request.headers.get("Authorization")
    secret = os.environ["BRINGIN_SECRET"]
    admin_key = os.environ["OPAGO_KEY"]

    client_timestamp_str = signature.split()[1].split(':')[0]
    body_string = json.dumps(body, separators=(',', ':'), sort_keys=True)
    expected_signature = generate_hmac_authorization(secret, request.method, request.url.path, body_string, client_timestamp_str)
    
    logger.info(f"Generated HMAC: {expected_signature}")
    logger.info(f"Received HMAC: {signature}")

    if not signature == expected_signature:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    try:
        result = await update_bringin_user(old_lightning_address, new_lightning_address, admin_key)
        return result

    except HTTPException as e:
        raise e

    except Exception as e:
        logger.error(f"Error during update: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@splitpayments_ext.get("/api/v1/bringin_audit")
async def bringin_audit(request: Request):
    signature = request.headers.get("Authorization")
    secret = os.environ["BRINGIN_SECRET"]
    admin_key = os.environ["OPAGO_KEY"]

    client_timestamp_str = signature.split()[1].split(':')[0]
    expected_signature = generate_hmac_authorization(secret, request.method, request.url.path, {}, client_timestamp_str)

    logger.info(f"Generated HMAC: {expected_signature}")
    logger.info(f"Received HMAC: {signature}")

    if not signature == expected_signature:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    include_transactions = request.query_params.get("include_transactions", "false").lower() == "true"

    try:
        audit_data = await get_bringin_audit_data(admin_key, include_transactions)
        return audit_data

    except Exception as e:
        logger.error(f"Error during Bringin audit: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@splitpayments_ext.post("/api/v1/execute_split_for_all", status_code=HTTP_200_OK)
async def execute_split_for_all(request: Request):
    signature = request.headers.get("Authorization")
    secret = os.environ["BRINGIN_SECRET"]
    admin_key = os.environ["OPAGO_KEY"]

    client_timestamp_str = signature.split()[1].split(':')[0]
    expected_signature = generate_hmac_authorization(secret, request.method, request.url.path, {}, client_timestamp_str)

    logger.info(f"Generated HMAC: {expected_signature}")
    logger.info(f"Received HMAC: {signature}")

    if not signature == expected_signature:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    BRINGIN_MIN = float(os.environ["BRINGIN_MIN"])
    BRINGIN_MAX = float(os.environ["BRINGIN_MAX"])

    try:
        audit_data = await get_bringin_audit_data(admin_key, include_transactions=True)
        for wallet in audit_data:
            balance = wallet['wallet_balance']
            if balance > BRINGIN_MIN:
                amount = balance * 0.98  # Subtract 2%
                if balance > BRINGIN_MAX:
                    amount = BRINGIN_MAX
                await execute_split(wallet['wallet_id'], int(amount))
        return {"message": "Split executed for all eligible wallets"}

    except Exception as e:
        logger.error(f"Error during processing: {str(e)}")
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

@splitpayments_ext.post("/api/v1/execute_split_for_all", status_code=HTTP_200_OK)
async def execute_split_for_all(request: Request):
    admin_key = os.environ["OPAGO_KEY"]
    BRINGIN_MIN = float(os.environ["BRINGIN_MIN"])
    BRINGIN_MAX = float(os.environ["BRINGIN_MAX"])

    try:
        # Run the audit before executing the splits
        audit_data_before = await get_bringin_audit_data(admin_key, include_transactions=True)

        # Execute the splits
        for wallet in audit_data_before:
            balance = wallet['wallet_balance']
            if balance > BRINGIN_MIN:
                amount = balance * 0.98  # Subtract 2%
                if balance > BRINGIN_MAX:
                    amount = BRINGIN_MAX
                await execute_split(wallet['wallet_id'], int(amount))

        # Run the audit again after executing the splits
        audit_data_after = await get_bringin_audit_data(admin_key, include_transactions=True)

        # Compare the balances and create the response
        response_data = []
        for wallet_before in audit_data_before:
            wallet_id = wallet_before['wallet_id']
            balance_before = wallet_before['wallet_balance']

            # Find the corresponding wallet in the audit data after the splits
            wallet_after = next((w for w in audit_data_after if w['wallet_id'] == wallet_id), None)
            balance_after = wallet_after['wallet_balance'] if wallet_after else None

            if balance_after is not None and balance_after > BRINGIN_MIN:
                response_data.append({
                    'wallet_id': wallet_id,
                    'balance_before': balance_before,
                    'balance_after': balance_after
                })

        # If there are wallets above BRINGIN_MIN, send an email with the CSV report
        if response_data:
            # Create a CSV file in memory
            csv_file = io.StringIO()
            fieldnames = ['wallet_id', 'balance_before', 'balance_after']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(response_data)

            # Create the email message
            msg = MIMEMultipart()
            msg['From'] = 'your_email@example.com'
            msg['To'] = 'technology@opago-pay.com'
            msg['Subject'] = 'Bringin Split Report'
            msg.attach(MIMEText('This is a test email', 'plain'))
            msg.attach(MIMEApplication(csv_file.getvalue(), Name='report.csv'))

            # Send the email
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login('your_email@example.com', 'your_password')
                server.send_message(msg)
                server.quit()

        return {"message": "Email sent successfully"}

    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
