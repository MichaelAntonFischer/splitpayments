import os
import csv
import io
import smtplib
from email.message import EmailMessage
from http import HTTPStatus
from fastapi import APIRouter, Depends, HTTPException, Request
from lnbits.core.crud import get_wallet, get_wallet_for_key
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key
from lnbits.helpers import urlsafe_short_hash
from loguru import logger

from .crud import get_targets, set_targets
from .models import Target, TargetPutList
from .tasks import execute_split
from .bringin import add_bringin_user, generate_hmac_authorization, get_bringin_audit_data, update_bringin_user

def send_mail(to_email, subject, message, attachment=None, maintype=None, subtype=None, filename=None):
    """
    Sends an email using Microsoft 365's SMTP relay service.
    Uses IP-based authentication through Exchange Online connector.
    """
    server_address = os.environ.get('SMTP_SERVER', 'opago-com.mail.protection.outlook.com')
    server_port = int(os.environ.get('SMTP_PORT', '25'))
    from_email = os.environ.get('SMTP_FROM', 'info@opago.com')

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    msg.add_alternative(message, subtype='html')
    if attachment is not None:
        msg.add_attachment(attachment, maintype=maintype, subtype=subtype, filename=filename)
    try:
        with smtplib.SMTP(server_address, server_port) as server:
            server.send_message(msg)
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
        raise HTTPException(status_code=500, detail=f"SMTP error: {e}")

splitpayments_api_router = APIRouter()


@splitpayments_api_router.get("/api/v1/targets")
async def api_targets_get(
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> list[Target]:
    targets = await get_targets(wallet.wallet.id)
    return targets or []


@splitpayments_api_router.put("/api/v1/targets", status_code=HTTPStatus.OK)
async def api_targets_set(
    target_put: TargetPutList,
    source_wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    try:
        targets: list[Target] = []
        for entry in target_put.targets:

            if entry.wallet.find("@") < 0 and entry.wallet.find("LNURL") < 0:
                wallet = await get_wallet(entry.wallet)
                if not wallet:
                    wallet = await get_wallet_for_key(entry.wallet)
                    if not wallet:
                        raise HTTPException(
                            status_code=HTTPStatus.BAD_REQUEST,
                            detail=f"Invalid wallet '{entry.wallet}'.",
                        )

                if wallet.id == source_wallet.wallet.id:
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail="Can't split to itself.",
                    )

            if entry.percent <= 0:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"Invalid percent '{entry.percent}'.",
                )

            targets.append(
                Target(
                    id=urlsafe_short_hash(),
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
        ) from ex


@splitpayments_api_router.delete("/api/v1/targets", status_code=HTTPStatus.OK)
async def api_targets_delete(
    source_wallet: WalletTypeInfo = Depends(require_admin_key),
) -> None:
    await set_targets(source_wallet.wallet.id, [])

# --- RESTORE CUSTOM ENDPOINTS ---
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED
import json

@splitpayments_api_router.post("/api/v1/add_bringin_user", status_code=HTTP_200_OK)
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

@splitpayments_api_router.post("/api/v1/update_bringin_user", status_code=HTTP_200_OK)
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

@splitpayments_api_router.get("/api/v1/bringin_audit")
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
    lnaddress = request.query_params.get("lnaddress")
    try:
        audit_data = await get_bringin_audit_data(admin_key, include_transactions, lnaddress)
        if lnaddress and not audit_data:
            raise HTTPException(
                status_code=409,
                detail=f"User not found: {lnaddress}@bringin.xyz" if '@' not in lnaddress else f"User not found: {lnaddress}"
            )
        return audit_data
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during Bringin audit: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@splitpayments_api_router.post("/api/v1/execute_split_for_all", status_code=HTTP_200_OK)
async def execute_split_for_all(request: Request):
    admin_key = os.environ["OPAGO_KEY"]
    BRINGIN_MIN = float(os.environ["BRINGIN_MIN"])
    BRINGIN_MAX = float(os.environ["BRINGIN_MAX"])
    FEE_RESERVE_PERCENT = 0.001  # 0.1%
    try:
        audit_data_before = await get_bringin_audit_data(admin_key, include_transactions=True)
        response_data = []
        for wallet in audit_data_before:
            balance = wallet['wallet_balance'] / 1000  # msats to sats
            user_id = wallet['user_id']
            email = wallet['user_email']
            logger.info(f"Balance for {wallet['wallet_id']}: {balance} sats")
            if BRINGIN_MIN < balance < BRINGIN_MAX:
                fee_reserve_amount = balance * FEE_RESERVE_PERCENT
                amount = balance - fee_reserve_amount
                amount = int(amount)
                try:
                    await execute_split(wallet['wallet_id'], amount * 1000)  # sats to msats
                    reason = 'Split executed successfully'
                except Exception as e:
                    reason = f'Error executing split: {str(e)}'
            else:
                reason = f'Amount {balance} sats not within BRINGIN limits ({BRINGIN_MIN}-{BRINGIN_MAX} sats). Skipping offramp.'
            response_data.append({
                'wallet_id': wallet['wallet_id'],
                'user_id': user_id,
                'email': email,
                'balance_before': balance,
                'balance_after': None,
                'reason': reason
            })
        audit_data_after = await get_bringin_audit_data(admin_key, include_transactions=True)
        for wallet_data in response_data:
            wallet_id = wallet_data['wallet_id']
            wallet_after = next((w for w in audit_data_after if w['wallet_id'] == wallet_id), None)
            balance_after = (wallet_after['wallet_balance'] / 1000) if wallet_after else None
            wallet_data['balance_after'] = balance_after
            if balance_after is not None and balance_after > BRINGIN_MIN:
                wallet_data['reason'] = 'Split executed successfully'
            elif balance_after is not None:
                wallet_data['reason'] = 'Balance below BRINGIN_MIN after split'
            else:
                wallet_data['reason'] = 'Wallet not found after split'
        wallets_above_min = any(wallet['balance_after'] is not None and wallet['balance_after'] > BRINGIN_MIN for wallet in response_data)
        if wallets_above_min:
            csv_file = io.StringIO()
            fieldnames = ['wallet_id', 'user_id', 'email', 'balance_before', 'balance_after', 'reason']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(response_data)
            csv_content = csv_file.getvalue().encode('utf-8')
            subject = 'Bringin Split Report'
            message = 'Please find the attached Bringin Split Report.'
            to_email = 'technology@opago-pay.com'
            send_mail(
                to_email=to_email,
                subject=subject,
                message=message,
                attachment=csv_content,
                maintype='text',
                subtype='csv',
                filename='report.csv'
            )
            return {"message": "Email sent successfully"}
        else:
            return {"message": "All wallets below min balance."}
    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
