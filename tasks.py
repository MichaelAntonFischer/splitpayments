import asyncio
import os
import json
from math import floor
from typing import Optional

import httpx
from loguru import logger

from lnbits import bolt11
from lnbits.core.crud import get_standalone_payment
from lnbits.core.models import Payment
from lnbits.core.services import create_invoice, fee_reserve, pay_invoice
from lnbits.helpers import get_current_extension_name
from lnbits.tasks import register_invoice_listener
from .bringin import offramp
from lnbits.core.crud.wallets import get_wallet_for_key

from .crud import get_targets

BRINGIN_DOMAINS = ["bringin.xyz", "bringin.opago-pay.com", "bringin.opago.com"]
FEE_RESERVE_PERCENT = 0.001  # 0.1%

async def wait_for_paid_invoices():
    invoice_queue = asyncio.Queue()
    register_invoice_listener(invoice_queue, get_current_extension_name())

    while True:
        payment = await invoice_queue.get()
        await on_invoice_paid(payment)


async def on_invoice_paid(payment: Payment) -> None:

    if payment.extra.get("tag") == "splitpayments" or payment.extra.get("splitted"):
        # already a splitted payment, ignore
        return

    targets = await get_targets(payment.wallet_id)

    if not targets:
        return

    total_percent = sum([target.percent for target in targets])

    if total_percent > 100:
        logger.error("splitpayment: total percent adds up to more than 100%")
        return

    logger.trace(f"splitpayments: performing split payments to {len(targets)} targets")

    for target in targets:

        if target.percent > 0:

            amount_msat = int(payment.amount * target.percent / 100)
            memo = (
                f"Split payment: {target.percent}% for {target.alias or target.wallet}"
            )

            if any(domain in target.wallet for domain in BRINGIN_DOMAINS):
                # Use offramp function for BRINGIN_DOMAINS
                logger.info(f"Using offramp for BRINGIN_DOMAINS: {target.wallet}")
                amount_sats = int(amount_msat / 1000)
                bringin_min = int(os.environ.get("BRINGIN_MIN", 0))
                bringin_max = int(os.environ.get("BRINGIN_MAX", float('inf')))
                payment_request = None
                fee_reserve_amount = bringin_min * FEE_RESERVE_PERCENT
                
                # First check if amount is above 2 sats to trigger webhook
                if amount_sats > 2:
                    # Get user's current balance
                    balance = await get_bringin_wallet_balance(target.wallet)
                    if balance is not None:
                        await trigger_bringin_webhook(target.wallet, balance)
                
                # Then check if amount is within Bringin limits for offramp
                if bringin_min - fee_reserve_amount <= amount_sats <= bringin_max:
                    payment_request = await offramp(target.wallet, amount_sats)
                else:
                    logger.info(f"Amount {amount_sats} sats not within BRINGIN limits ({bringin_min}-{bringin_max} sats). Skipping offramp.")
            elif target.wallet.find("@") >= 0 or target.wallet.find("LNURL") >= 0:
                logger.info(f"Using standard LNURL process: {target.wallet}")
                safe_amount_msat = amount_msat - fee_reserve(amount_msat)
                payment_request = await get_lnurl_invoice(
                    target.wallet, payment.wallet_id, safe_amount_msat, memo
                )
            else:
                # Key-based wallet resolution (backwards compatible)
                wallet = await get_wallet_for_key(target.wallet)
                wallet_id_to_use = wallet.id if wallet is not None else target.wallet
                logger.info(f"Internal payment: {wallet_id_to_use}")
                _, payment_request = await create_invoice(
                    wallet_id=wallet_id_to_use,
                    amount=int(amount_msat / 1000),
                    internal=True,
                    memo=memo,
                )

            extra = {**payment.extra, "tag": "splitpayments", "splitted": True}

            if payment_request:
                await pay_invoice(
                    payment_request=payment_request,
                    wallet_id=payment.wallet_id,
                    description=memo,
                    extra=extra,
                )


async def execute_split(wallet_id, amount):

    targets = await get_targets(wallet_id)

    if not targets:
        return

    total_percent = sum([target.percent for target in targets])

    if total_percent > 100:
        logger.error("splitpayment: total percent adds up to more than 100%")
        return

    logger.trace(f"splitpayments: performing split payments to {len(targets)} targets")

    for target in targets:

        if target.percent > 0:

            amount_msat = int(amount * target.percent / 100)

            if amount_msat < 1000:
                continue

            memo = (
                f"{target.alias or target.wallet}"
            )

            if any(domain in target.wallet for domain in BRINGIN_DOMAINS):
                # Use offramp function for BRINGIN_DOMAINS
                amount_sats = int(amount_msat / 1000)
                bringin_min = int(os.environ.get("BRINGIN_MIN", 0))
                bringin_max = int(os.environ.get("BRINGIN_MAX", float('inf')))
                payment_request = None
                if bringin_min <= amount_sats <= bringin_max:
                    payment_request = await offramp(target.wallet, amount_sats)
                else:
                    logger.info(f"Amount {amount_sats} sats not within BRINGIN limits ({bringin_min}-{bringin_max} sats). Skipping offramp.")
            elif target.wallet.find("@") >= 0 or target.wallet.find("LNURL") >= 0:
                payment_request = await get_lnurl_invoice(
                    target.wallet, wallet_id, amount_msat, memo
                )
            else:
                # Key-based wallet resolution (backwards compatible)
                wallet = await get_wallet_for_key(target.wallet)
                wallet_id_to_use = wallet.id if wallet is not None else target.wallet
                _, payment_request = await create_invoice(
                    wallet_id=wallet_id_to_use,
                    amount=int(amount_msat / 1000),
                    internal=True,
                    memo=memo,
                )

            extra = {"tag": "splitpayments", "splitted": True}

            if payment_request:
                await pay_invoice(
                    payment_request=payment_request,
                    wallet_id=wallet_id,
                    description=memo,
                    extra=extra,
                )


async def get_lnurl_invoice(
        payoraddress, wallet_id, amount_msat, memo
) -> Optional[str]:
    from lnbits.core.views.api import api_lnurlscan

    data = await api_lnurlscan(payoraddress)
    rounded_amount = floor(amount_msat / 1000) * 1000

    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(
                data["callback"],
                params={"amount": rounded_amount, "comment": memo},
                timeout=40,
            )
            if r.is_error:
                raise httpx.ConnectError("issue with scrub callback")
            r.raise_for_status()
        except (httpx.ConnectError, httpx.RequestError):
            logger.error(
                f"splitting LNURL failed: Failed to connect to {data['callback']}."
            )
            return None
        except Exception as exc:
            logger.error(f"splitting LNURL failed: {str(exc)}.")
            return None

    params = json.loads(r.text)
    if params.get("status") == "ERROR":
        logger.error(f"{data['callback']} said: '{params.get('reason', '')}'")
        return None

    invoice = bolt11.decode(params["pr"])

    lnurlp_payment = await get_standalone_payment(invoice.payment_hash)

    if lnurlp_payment and lnurlp_payment.wallet_id == wallet_id:
        logger.error(f"split failed. cannot split payments to yourself via LNURL.")
        return None

    if invoice.amount_msat != rounded_amount:
        logger.error(
            f"{data['callback']} returned an invalid invoice. Expected {amount_msat} msat, got {invoice.amount_msat}."
        )
        return None

    return params["pr"]

async def trigger_bringin_webhook(lightning_address: str, balance: int):
    webhook_url = "https://app.bringin.xyz/hooks/opago/payments"
    username = lightning_address.split("@")[0]
    
    payload = {
        "username": username,
        "balance": balance
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"Bringin webhook triggered successfully for {username}")
        except Exception as e:
            logger.error(f"Failed to trigger Bringin webhook: {str(e)}")

# Add this new function to get wallet balance
async def get_bringin_wallet_balance(lightning_address: str) -> Optional[int]:
    base_url = "https://bringin.opago-pay.com"
    admin_key = os.environ['OPAGO_KEY']
    
    # First get the user's wallet info
    headers = {"X-Api-Key": admin_key}
    async with httpx.AsyncClient() as client:
        try:
            # Get user info to find their wallet
            users_response = await client.get(
                f"{base_url}/usermanager/api/v1/users", 
                headers=headers
            )
            users_response.raise_for_status()
            users = [u for u in users_response.json() if u["email"] == lightning_address]
            if not users:
                logger.error(f"No user found for {lightning_address}")
                return None
                
            # Get user's wallet
            wallets_response = await client.get(
                f"{base_url}/usermanager/api/v1/wallets", 
                headers=headers
            )
            wallets_response.raise_for_status()
            user_wallet = next(
                (w for w in wallets_response.json() if w["user"] == users[0]["id"]), 
                None
            )
            if not user_wallet:
                logger.error(f"No wallet found for user {lightning_address}")
                return None

            # Get wallet balance using the wallet's admin key
            balance_response = await client.get(
                f"{base_url}/api/v1/wallet",
                headers={"X-Api-Key": user_wallet["adminkey"]}
            )
            balance_response.raise_for_status()
            return balance_response.json()["balance"]

        except Exception as e:
            logger.error(f"Failed to get wallet balance: {str(e)}")
            return None
