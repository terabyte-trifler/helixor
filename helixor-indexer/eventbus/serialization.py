"""
eventbus/serialization.py — the Kafka wire format.

Records on the bus carry `bytes`. This module is the single place that
maps the domain objects — a `Transaction`, a security alert — to and from
that wire format.

The format is canonical JSON (sorted keys, UTF-8): human-readable for
debugging, schema-stable, and round-trip exact. A transaction serialised
and deserialised is BYTE-IDENTICAL to the original — proven by
test_serialization.py — because the detection consumer's idempotent dedup
depends on the signature surviving the round trip intact.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Shared Transaction type from the oracle.
_ORACLE_ROOT = Path(__file__).resolve().parents[2] / "helixor-oracle"
if str(_ORACLE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ORACLE_ROOT))

from features.types import Transaction  # noqa: E402


class SerializationError(Exception):
    """Raised when a record cannot be (de)serialised."""


# =============================================================================
# Transaction <-> bytes
# =============================================================================

# The wire schema version — bumped if the Transaction shape changes, so a
# consumer can detect and reject an incompatible producer.
TRANSACTION_WIRE_VERSION = 1


def serialize_transaction(agent_wallet: str, tx: Transaction) -> bytes:
    """
    Serialise a `Transaction` (with its owning agent) to canonical-JSON
    bytes for the `agent.transactions` topic.

    Deterministic: sorted keys, no whitespace drift.
    """
    payload = {
        "wire_version": TRANSACTION_WIRE_VERSION,
        "agent_wallet": agent_wallet,
        "signature":    tx.signature,
        "slot":         tx.slot,
        "block_time":   tx.block_time.isoformat(),
        "success":      tx.success,
        "program_ids":  list(tx.program_ids),
        "sol_change":   tx.sol_change,
        "fee":          tx.fee,
        "priority_fee": tx.priority_fee,
        "compute_units": tx.compute_units,
        "counterparty": tx.counterparty,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize_transaction(data: bytes) -> tuple[str, Transaction]:
    """
    Deserialise `agent.transactions` bytes back to (agent_wallet,
    Transaction). The inverse of `serialize_transaction`.

    Raises SerializationError on malformed data or a wire-version mismatch
    — a poison message the consumer routes to the dead-letter topic.
    """
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError(f"not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise SerializationError("payload is not a JSON object")

    version = payload.get("wire_version")
    if version != TRANSACTION_WIRE_VERSION:
        raise SerializationError(
            f"wire version mismatch: got {version}, "
            f"expected {TRANSACTION_WIRE_VERSION}"
        )

    try:
        agent_wallet = payload["agent_wallet"]
        tx = Transaction(
            signature=payload["signature"],
            slot=int(payload["slot"]),
            block_time=datetime.fromisoformat(payload["block_time"]),
            success=bool(payload["success"]),
            program_ids=tuple(payload["program_ids"]),
            sol_change=int(payload["sol_change"]),
            fee=int(payload["fee"]),
            priority_fee=int(payload["priority_fee"]),
            compute_units=int(payload["compute_units"]),
            counterparty=payload["counterparty"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SerializationError(
            f"malformed transaction payload: {exc}"
        ) from exc

    return agent_wallet, tx


# =============================================================================
# Security alert <-> bytes
# =============================================================================

ALERT_WIRE_VERSION = 1


def serialize_alert(
    *,
    agent_wallet: str,
    score:        int,
    alert_tier:   str,
    immediate_red: bool,
    aggregated_flags: int,
    detected_at:  datetime,
    reason:       str = "",
) -> bytes:
    """
    Serialise a security alert for the `agent.alerts` topic — the
    IMMEDIATE_RED fast-path. Carries the minimum a downstream responder
    needs to act sub-epoch.
    """
    payload = {
        "wire_version":     ALERT_WIRE_VERSION,
        "agent_wallet":     agent_wallet,
        "score":            score,
        "alert_tier":       alert_tier,
        "immediate_red":    immediate_red,
        "aggregated_flags": aggregated_flags,
        "detected_at":      detected_at.isoformat(),
        "reason":           reason,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deserialize_alert(data: bytes) -> dict:
    """Deserialise an `agent.alerts` payload back to a dict."""
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError(f"not valid JSON: {exc}") from exc
    if payload.get("wire_version") != ALERT_WIRE_VERSION:
        raise SerializationError(
            f"alert wire version mismatch: got {payload.get('wire_version')}"
        )
    return payload
