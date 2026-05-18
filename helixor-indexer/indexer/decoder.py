"""
indexer/decoder.py — decode a Geyser update into the oracle's Transaction.

The decoder is a PURE function: `GeyserTransactionUpdate` -> `Transaction`.
No I/O, no clock — fully deterministic and unit-testable. The gRPC wire
format is isolated upstream (indexer/yellowstone.py); the database is
downstream (indexer/writer.py). The decoder is the clean middle.

WHAT THE DECODE DOES
--------------------
A Geyser update carries the raw transaction: every account, pre/post
lamport balances, the program-id list, fee, compute units. The oracle's
`Transaction` is a focused projection — the 10 fields the 100-feature
extractor needs. The decoder computes that projection:

  signature, slot, block_time, success   — direct copy
  program_ids                            — the invoked-program list
  fee, priority_fee, compute_units        — direct copy
  sol_change      — the AGENT's net lamport delta (post - pre on its own
                    account); the feature extractor's value-flow signal
  counterparty    — the largest non-agent account the value moved with;
                    a best-effort attribution from the balance changes
"""

from __future__ import annotations

import sys
from pathlib import Path

from indexer.types import GeyserAccountChange, GeyserTransactionUpdate

# The decoder targets the oracle's Transaction type. The indexer sits
# alongside helixor-oracle; add it to the path so the shared type is the
# SAME type, not a copy (a copy would drift).
_ORACLE_ROOT = Path(__file__).resolve().parents[2] / "helixor-oracle"
if str(_ORACLE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ORACLE_ROOT))

from features.types import Transaction  # noqa: E402


class DecodeError(Exception):
    """Raised when a Geyser update cannot be decoded into a Transaction."""


def decode_transaction(
    update:       GeyserTransactionUpdate,
    agent_wallet: str,
) -> Transaction:
    """
    Decode a Geyser update into the oracle's `Transaction`, from the
    perspective of `agent_wallet`.

    `agent_wallet` MUST be one of the update's `account_keys` — the update
    was streamed because this transaction touches a registered agent, and
    the decode needs the agent's account to compute its net SOL change.

    Pure + deterministic. Raises DecodeError on a malformed update.
    """
    if agent_wallet not in update.account_keys:
        raise DecodeError(
            f"agent {agent_wallet} is not among the transaction's accounts "
            f"({update.signature[:16]}...) — cannot decode from its perspective"
        )

    # ── The agent's net SOL change ──────────────────────────────────────────
    agent_change = _account_delta(update.account_changes, agent_wallet)

    # ── Counterparty attribution ────────────────────────────────────────────
    # The counterparty is the non-agent account whose balance moved most in
    # the OPPOSITE direction to the agent's — a best-effort attribution of
    # "who the value moved with". Ties broken by pubkey for determinism.
    counterparty = _attribute_counterparty(
        update.account_changes, agent_wallet, agent_change,
    )

    return Transaction(
        signature=update.signature,
        slot=update.slot,
        block_time=update.block_time,
        success=update.is_successful,
        program_ids=tuple(update.instr_program_ids),
        sol_change=agent_change,
        fee=update.fee_lamports,
        priority_fee=update.priority_fee_lamports,
        compute_units=update.compute_units,
        counterparty=counterparty,
    )


# =============================================================================
# Internals
# =============================================================================

def _account_delta(
    changes: tuple[GeyserAccountChange, ...],
    pubkey:  str,
) -> int:
    """The lamport delta for one account; 0 if it has no recorded change."""
    for change in changes:
        if change.pubkey == pubkey:
            return change.delta
    return 0


def _attribute_counterparty(
    changes:      tuple[GeyserAccountChange, ...],
    agent_wallet: str,
    agent_change: int,
) -> str | None:
    """
    Best-effort counterparty attribution.

    If the agent gained SOL, the counterparty is the account that lost the
    most; if the agent lost SOL, it is the account that gained the most.
    A flat agent change yields no attribution. Ties → smallest pubkey, so
    the result is deterministic.
    """
    if agent_change == 0:
        return None

    # We want the opposite-sign mover with the largest magnitude.
    want_sign = -1 if agent_change > 0 else 1
    candidates = [
        c for c in changes
        if c.pubkey != agent_wallet
        and c.delta != 0
        and (1 if c.delta > 0 else -1) == want_sign
    ]
    if not candidates:
        return None

    # Largest magnitude wins; ties broken by pubkey for determinism.
    best = max(candidates, key=lambda c: (abs(c.delta), _neg_str(c.pubkey)))
    return best.pubkey


def _neg_str(s: str) -> tuple:
    """
    A sort key that orders strings ASCENDING when used inside a `max()` —
    so a tie on magnitude resolves to the SMALLEST pubkey deterministically.
    """
    return tuple(-ord(ch) for ch in s)
