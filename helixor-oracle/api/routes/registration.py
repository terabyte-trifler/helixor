"""
api/routes/registration.py — prepare-registration helper endpoint.

Lets the elizaOS plugin (or any web client) request an unsigned
register_agent transaction without bundling the program IDL into the SDK.

This endpoint does NOT submit transactions. It returns a base64 unsigned tx
that the operator's wallet signs + submits.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from solana.rpc.async_api import AsyncClient
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.instruction import AccountMeta, Instruction
from solders.transaction import Transaction

from api.rate_limit import rate_limit_dep
from api.validation import validate_agent_wallet
from indexer.config import settings

log = structlog.get_logger(__name__)
router = APIRouter()


PUBKEY_RE_LEN = (32, 44)
MAX_NAME_BYTES = 64


class PrepareRegistrationRequest(BaseModel):
    agent_wallet: str = Field(..., description="Agent hot wallet (base58)")
    owner_wallet: str = Field(..., description="Owner cold wallet (base58)")
    name:         str = Field(..., min_length=1, max_length=MAX_NAME_BYTES)


class PrepareRegistrationResponse(BaseModel):
    unsigned_tx_base64: str
    registration_pda:   str
    escrow_vault_pda:   str
    recent_blockhash:   str
    program_id:         str


def _register_agent_discriminator() -> bytes:
    """First 8 bytes of sha256('global:register_agent')."""
    return hashlib.sha256(b"global:register_agent").digest()[:8]


@router.post(
    "/agents/prepare-registration",
    response_model=PrepareRegistrationResponse,
    dependencies=[Depends(rate_limit_dep)],
    summary="Build an unsigned register_agent transaction.",
)
async def prepare_registration(
    body: PrepareRegistrationRequest,
) -> PrepareRegistrationResponse:
    # Validate via the same pubkey check used elsewhere
    validate_agent_wallet(body.agent_wallet)
    validate_agent_wallet(body.owner_wallet)

    if body.agent_wallet == body.owner_wallet:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "agent_wallet must differ from owner_wallet",
                "code":  "AGENT_EQUALS_OWNER",
            },
        )

    name_bytes = body.name.encode("utf-8")
    if len(name_bytes) == 0:
        raise HTTPException(status_code=400, detail={
            "error": "name cannot be empty", "code": "EMPTY_NAME",
        })
    if len(name_bytes) > MAX_NAME_BYTES:
        raise HTTPException(status_code=400, detail={
            "error": f"name is {len(name_bytes)} bytes, max {MAX_NAME_BYTES}",
            "code":  "NAME_TOO_LONG",
        })

    program_id = Pubkey.from_string(settings.health_oracle_program_id)
    agent      = Pubkey.from_string(body.agent_wallet)
    owner      = Pubkey.from_string(body.owner_wallet)

    registration_pda, _ = Pubkey.find_program_address(
        [b"agent", bytes(agent)], program_id,
    )
    escrow_vault_pda, _ = Pubkey.find_program_address(
        [b"escrow", bytes(agent)], program_id,
    )

    # Encode RegisterParams { name: String }
    discriminator = _register_agent_discriminator()
    length_bytes  = struct.pack("<I", len(name_bytes))
    data = discriminator + length_bytes + name_bytes

    ix = Instruction(
        program_id=program_id,
        accounts=[
            AccountMeta(pubkey=owner,             is_signer=True,  is_writable=True),
            AccountMeta(pubkey=agent,             is_signer=False, is_writable=False),
            AccountMeta(pubkey=registration_pda,  is_signer=False, is_writable=True),
            AccountMeta(pubkey=escrow_vault_pda,  is_signer=False, is_writable=True),
            AccountMeta(pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        ],
        data=data,
    )

    rpc = AsyncClient(settings.solana_rpc_url)
    try:
        latest = await rpc.get_latest_blockhash()
        blockhash = latest.value.blockhash
    finally:
        await rpc.close()

    msg = Message.new_with_blockhash([ix], owner, blockhash)
    tx  = Transaction.new_unsigned(msg)
    serialized = bytes(tx)

    log.info(
        "registration_prepared",
        agent=body.agent_wallet[:12] + "...",
        owner=body.owner_wallet[:12] + "...",
        name=body.name,
    )

    return PrepareRegistrationResponse(
        unsigned_tx_base64 = base64.b64encode(serialized).decode("ascii"),
        registration_pda   = str(registration_pda),
        escrow_vault_pda   = str(escrow_vault_pda),
        recent_blockhash   = str(blockhash),
        program_id         = str(program_id),
    )
