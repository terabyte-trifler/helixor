"""
features/types.py — input types for feature extraction.

The feature extractor is a PURE function. Its inputs must be immutable,
fully-typed, and carry no I/O handles. This module defines that contract.

Nothing here touches the network, disk, or system clock.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


# =============================================================================
# Action taxonomy — the canonical alphabet for transaction classification.
#
# This alphabet is FROZEN. Adding a member is a FEATURE_SCHEMA_VERSION bump,
# because tx-type distribution features are positional and n-gram features
# are computed over this alphabet.
# =============================================================================

class ActionType(enum.Enum):
    """Canonical transaction action classes. Order is frozen."""
    SWAP     = "swap"
    LEND     = "lend"
    STAKE    = "stake"
    TRANSFER = "transfer"
    OTHER    = "other"

    @classmethod
    def ordered(cls) -> tuple["ActionType", ...]:
        """Canonical iteration order — used for positional features."""
        return (cls.SWAP, cls.LEND, cls.STAKE, cls.TRANSFER, cls.OTHER)


# Well-known Solana program IDs → action classification.
# This map is intentionally small and explicit; anything unmatched → OTHER.
# Frozen alongside the action taxonomy.
_PROGRAM_ACTION_MAP: dict[str, ActionType] = {
    # Token program — transfers
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": ActionType.TRANSFER,
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": ActionType.TRANSFER,
    # System program — transfers
    "11111111111111111111111111111111": ActionType.TRANSFER,
    # Common swap programs (Jupiter, Raydium, Orca, Phoenix)
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4": ActionType.SWAP,
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": ActionType.SWAP,
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": ActionType.SWAP,
    "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY": ActionType.SWAP,
    # Lending (Solend, Kamino, MarginFi)
    "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo": ActionType.LEND,
    "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD": ActionType.LEND,
    "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA": ActionType.LEND,
    # Staking
    "Stake11111111111111111111111111111111111111": ActionType.STAKE,
    "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7uc":  ActionType.STAKE,
}


def classify_program(program_id: str) -> ActionType:
    """Map a program ID to its action class. Unknown → OTHER. Pure."""
    return _PROGRAM_ACTION_MAP.get(program_id, ActionType.OTHER)


# =============================================================================
# Transaction — the immutable input record.
# =============================================================================

@dataclass(frozen=True, slots=True)
class Transaction:
    """
    A single observed agent transaction. Immutable.

    All fields are required and typed. `block_time` MUST be timezone-aware UTC.
    `program_ids` is the ordered tuple of programs the transaction invoked
    (order = invocation order; used for n-gram sequence features).
    """
    signature:     str
    slot:          int
    block_time:    datetime
    success:       bool
    program_ids:   tuple[str, ...]
    # lamports moved: positive = inflow to agent, negative = outflow
    sol_change:    int
    # transaction fee in lamports
    fee:           int
    # priority fee in micro-lamports per compute unit (0 if none set)
    priority_fee:  int = 0
    # compute units consumed (0 if unknown)
    compute_units: int = 0
    # the counterparty wallet, if the transaction has a clear single
    # counterparty (transfers, swaps). None for multi-party / unclear.
    counterparty:  str | None = None

    def __post_init__(self) -> None:
        # Enforce the timezone-aware UTC contract at construction time.
        if self.block_time.tzinfo is None:
            raise ValueError(
                f"Transaction.block_time must be timezone-aware "
                f"(got naive datetime for sig {self.signature[:16]}...)"
            )
        # Normalise to UTC so downstream comparisons are total + canonical.
        if self.block_time.utcoffset() != timezone.utc.utcoffset(None):
            object.__setattr__(self, "block_time", self.block_time.astimezone(timezone.utc))

    @property
    def primary_action(self) -> ActionType:
        """
        The action class for this transaction. Defined as the class of the
        FIRST recognised (non-OTHER) program in invocation order; if every
        program is OTHER, the action is OTHER.

        Deterministic: depends only on the frozen program map + invocation order.
        """
        for pid in self.program_ids:
            action = classify_program(pid)
            if action is not ActionType.OTHER:
                return action
        return ActionType.OTHER


# =============================================================================
# ExtractionWindow — the time bounds for a feature extraction.
#
# Passed in explicitly so the extractor never reads the system clock.
# Two oracle nodes given the same window + transactions MUST produce identical
# feature vectors.
# =============================================================================

@dataclass(frozen=True, slots=True)
class ExtractionWindow:
    """The [start, end] time bounds for a feature extraction. Inclusive end."""
    start: datetime
    end:   datetime

    def __post_init__(self) -> None:
        for name, value in (("start", self.start), ("end", self.end)):
            if value.tzinfo is None:
                raise ValueError(f"ExtractionWindow.{name} must be timezone-aware UTC")
        if self.end < self.start:
            raise ValueError("ExtractionWindow.end must be >= start")
        # Normalise both ends to UTC
        object.__setattr__(self, "start", self.start.astimezone(timezone.utc))
        object.__setattr__(self, "end",   self.end.astimezone(timezone.utc))

    @property
    def duration_days(self) -> float:
        """Window span in days. Always >= 0."""
        return (self.end - self.start).total_seconds() / 86400.0

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    def contains(self, when: datetime) -> bool:
        """True if `when` falls within [start, end]. Inclusive both ends."""
        return self.start <= when <= self.end

    @classmethod
    def ending_at(cls, end: datetime, days: float) -> "ExtractionWindow":
        """Construct a window of `days` length ending at `end`. Convenience."""
        from datetime import timedelta
        return cls(start=end - timedelta(days=days), end=end)
