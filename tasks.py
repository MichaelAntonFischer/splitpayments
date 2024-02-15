import asyncio
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

from .crud import get_targets


async def wait_for_paid_invoices():
    invoice_queue = asyncio.Queue()
    register_invoice_listener(invoice_queue, get_current_extension_name())

    while True:
        payment = await invoice_queue.get()
        await on_invoice_paid(payment)

async def fetch_bringin_invoice(target_wallet: str, amount_msat: int, memo: str) -> Optional[str]:
    bringin_domains = ["bringin.example.com", "anotherbringin.example.com"]
    target_domain = target_wallet.split("@")[-1] if "@" in target_wallet else None

    if target_domain in bringin_domains:
        bringin_api_url = f"https://{target_domain}/api/create_order"
        data = {"amount_msat": amount_msat, "memo": memo}
        async with httpx.AsyncClient() as client:
            response = await client.post(bringin_api_url, json=data)
            if response.status_code == 200:
                invoice = response.json().get("invoice")
                return invoice
            else:
                logger.error(f"Failed to fetch invoice from Bringin: {response.text}")
    return None

async def on_invoice_paid(payment: Payment) -> None:
    # Existing logic up to determining the payment request for each target
    for target in targets:
        if target.percent > 0:
            amount_msat = int(payment.amount * target.percent / 100)
            memo = f"Split payment: {target.percent}% for {target.alias or target.wallet}"
            payment_request = None

            # Check if the target wallet is a lightning address
            if target.wallet.find("@") >= 0:
                target_domain = target.wallet.split("@")[-1]

                # Check for Bringin domain
                if target_domain in ["bringin.example.com", "anotherbringin.example.com"]:
                    payment_request = await fetch_bringin_invoice(target.wallet, amount_msat - fee_reserve(amount_msat), memo)
                else:
                    # Handle other lightning addresses not associated with Bringin
                    # This includes the explicit LNURL check
                    safe_amount_msat = amount_msat - fee_reserve(amount_msat)
                    payment_request = await get_lnurl_invoice(target.wallet, payment.wallet_id, safe_amount_msat, memo)
            elif target.wallet.find("LNURL") >= 0:
                # Direct handling for explicit LNURLs in the wallet address
                safe_amount_msat = amount_msat - fee_reserve(amount_msat)
                payment_request = await get_lnurl_invoice(target.wallet, payment.wallet_id, safe_amount_msat, memo)
            else:
                # Existing internal wallet logic remains unchanged
                _, payment_request = await create_invoice(
                    wallet_id=target.wallet,
                    amount=int(amount_msat / 1000),
                    internal=True,
                    memo=memo,
                )

            # Existing logic to execute payment if payment_request is not None
            if payment_request:
                await pay_invoice(
                    payment_request=payment_request,
                    wallet_id=payment.wallet_id,
                    description=memo,
                    extra={**payment.extra, "tag": "splitpayments", "splitted": True},
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

            memo = f"{target.alias or target.wallet}"
            payment_request = None

            if target.wallet.find("@") >= 0:
                target_domain = target.wallet.split("@")[-1]
                if target_domain in ["bringin.example.com", "anotherbringin.example.com"]:
                    payment_request = await fetch_bringin_invoice(target.wallet, amount_msat - fee_reserve(amount_msat), memo)
                else:
                    # Handle other lightning addresses not associated with Bringin
                    # This includes the explicit LNURL check
                    safe_amount_msat = amount_msat - fee_reserve(amount_msat)
                    payment_request = await get_lnurl_invoice(target.wallet, wallet_id, safe_amount_msat, memo)
            elif target.wallet.find("LNURL") >= 0:
                # Direct handling for explicit LNURLs in the wallet address
                safe_amount_msat = amount_msat - fee_reserve(amount_msat)
                payment_request = await get_lnurl_invoice(target.wallet, wallet_id, safe_amount_msat, memo)
            else:
                _, payment_request = await create_invoice(
                    wallet_id=target.wallet,
                    amount=int(amount_msat / 1000),
                    internal=True,
                    memo=memo,
                )

            if payment_request:
                extra = {"tag": "splitpayments", "splitted": True}
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



