"""
indexer/parser.py — parse Helius enhanced-webhook payloads into our schema.

Isolated from I/O so we can unit-test parsing without a database or HTTP server.

Helius "enhanced" webhook payload (one tx) looks roughly like:

    {
        "signature":   "4xK...",
        "slot":        265_000_000,
        "timestamp":   1714_000_000,
        "type":        "TRANSFER" | "FAILED" | ...,
        "feePayer":    "3uF...",                      # the fee payer pubkey
        "fee":         5000,
        "instructions": [{"programId": "11111...", "accounts": [...]}],
        "accountData": [{"account": "3uF...", "nativeBalanceChange": -5000, ...}],
        ...
    }

We're permissive with missing fields (Helius schema evolves), but we always
require: signature, slot, timestamp, feePayer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ParsedTransaction:
    """A single parsed transaction ready for DB insertion."""
    signature:    str
    slot:         int
    block_time:   datetime          # tz-aware UTC
    fee_payer:    str
    success:      bool
    program_ids:  list[str]
    sol_change:   int               # signed lamports for fee_payer
    fee:          int
    raw_meta:     dict[str, Any]    # original payload for forensics


class ParseError(Exception):
    """Raised when a Helius tx is missing required fields."""
    pass


def parse_helius_tx(tx: dict[str, Any]) -> ParsedTransaction:
    """
    Parse one transaction from a Helius enhanced webhook.

    Raises ParseError if required fields are missing.
    Returns ParsedTransaction otherwise.
    """
    signature = tx.get("signature")
    if not signature or not isinstance(signature, str):
        raise ParseError("missing signature")

    slot = tx.get("slot")
    if not isinstance(slot, int):
        raise ParseError(f"missing or invalid slot for {signature}")

    timestamp = tx.get("timestamp")
    if not isinstance(timestamp, (int, float)) or timestamp <= 0:
        raise ParseError(f"missing or invalid timestamp for {signature}")

    fee_payer = tx.get("feePayer")
    if not fee_payer or not isinstance(fee_payer, str):
        raise ParseError(f"missing feePayer for {signature}")

    # ── Convert epoch seconds to tz-aware UTC datetime ──────────────────────
    # Helius timestamps are unix seconds. Without tz=timezone.utc, datetime
    # would be naive and PG would assume server local time → off by hours.
    block_time = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)

    # ── Determine success ────────────────────────────────────────────────────
    # Helius marks failed txs with type="FAILED" or has a non-null err in meta.
    tx_type = tx.get("type", "")
    success = (
        tx_type != "FAILED"
        and tx.get("transactionError") is None
    )

    # ── Extract distinct program IDs from instructions ───────────────────────
    instructions = tx.get("instructions") or []
    program_ids: list[str] = []
    seen: set[str] = set()
    for ix in instructions:
        if not isinstance(ix, dict):
            continue
        pid = ix.get("programId")
        if isinstance(pid, str) and pid not in seen:
            seen.add(pid)
            program_ids.append(pid)

    # ── Compute fee_payer's SOL change ───────────────────────────────────────
    # nativeBalanceChange is signed lamports. We sum any entries matching the
    # fee_payer (Helius sometimes splits across multiple accountData entries).
    sol_change = 0
    for entry in tx.get("accountData") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("account") == fee_payer:
            change = entry.get("nativeBalanceChange") or 0
            if isinstance(change, int):
                sol_change += change

    fee = tx.get("fee") or 0
    if not isinstance(fee, int):
        fee = 0

    return ParsedTransaction(
        signature=signature,
        slot=slot,
        block_time=block_time,
        fee_payer=fee_payer,
        success=success,
        program_ids=program_ids,
        sol_change=sol_change,
        fee=fee,
        raw_meta=tx,
    )
