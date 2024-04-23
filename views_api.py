import os
import time

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
from .bringin import create_bringin_user, activate_extensions, create_lnurlp_link, generate_hmac_authorization

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

    # Extract timestamp from the client's HMAC
    client_timestamp = int(signature.split()[1].split(':')[0])
    server_timestamp = int(time.time() * 1000)

    full_external_path = "/splitpayments" + request.url.path

    # Check if the timestamp is within a 5-second window (5000 milliseconds)
    if abs(server_timestamp - client_timestamp) > 5000:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Timestamp is not valid")

    # Generate expected HMAC signature
    expected_signature = generate_hmac_authorization(secret, request.method, full_external_path, body, client_timestamp)

    # Log the generated HMAC and the raw data
    logger.info(f"Generated HMAC: {expected_signature}")
    logger.info(f"Received HMAC: {signature}")

    if not signature == expected_signature:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    admin_id = os.environ['OPAGO_ID']
    user_name = lightning_address.split("@")[0]
    wallet_name = "Offramp"

    try:
        user_data = await create_bringin_user(admin_id, user_name, wallet_name)
        user_id = user_data["id"]
        invoice_key = user_data["wallets"][0]["inkey"]
        wallet_id = user_data["wallets"][0]["id"]

        await activate_extensions(user_id, ["splitpayments", "lnurlp"])
        lnurl = await create_lnurlp_link(lightning_address)

        target = Target(wallet=wallet_id, wallet_target=lightning_address, percent=100, alias="Offramp Order")
        await set_targets(wallet_id, [target])

        return { "lnurl": lnurl}
    except Exception as e:
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
