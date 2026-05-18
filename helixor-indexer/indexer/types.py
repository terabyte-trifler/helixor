"""
indexer/types.py — typed contracts for the Helixor Geyser indexer.

The indexer streams every transaction touching a registered agent wallet
off a Geyser-enabled RPC and writes it to TimescaleDB within ~500ms of
on-chain confirmation. This module defines the types that flow through it.

A NOTE ON GEYSER
----------------
"Geyser" is Solana's validator plugin interface. Third parties do not load
a plugin into someone else's validator — they consume the Yellowstone
gRPC stream a Geyser-enabled RPC provider (e.g. Helius) exposes. So the
Helixor indexer is a Geyser gRPC CONSUMER, not a validator plugin.

`GeyserTransactionUpdate` is the provider-agnostic shape of one streamed
transaction. The real Yellowstone gRPC client (indexer/yellowstone.py)
maps protobuf messages onto it; the decoder (indexer/decoder.py) maps it
onto the oracle's `Transaction`. Keeping a clean intermediate type means
the decoder is a pure, testable function and the gRPC wire format is
isolated at one edge.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


# =============================================================================
# IngestionSource — which path a transaction arrived by
# =============================================================================

class IngestionSource(enum.Enum):
    """
    The ingestion path a transaction was observed on.

    Both paths write to the same TimescaleDB hypertable; the source tag is
    what the reconciler compares.
    """
    GEYSER  = "geyser"     # the primary, low-latency Yellowstone gRPC stream
    WEBHOOK = "webhook"    # the Helius webhook fallback / reconciliation source


# =============================================================================
# GeyserTransactionUpdate — one streamed transaction, provider-agnostic
# =============================================================================

@dataclass(frozen=True, slots=True)
class GeyserAccountChange:
    """A single account's SOL balance change within a transaction."""
    pubkey:        str
    pre_lamports:  int
    post_lamports: int

    @property
    def delta(self) -> int:
        return self.post_lamports - self.pre_lamports


@dataclass(frozen=True, slots=True)
class GeyserTransactionUpdate:
    """
    One transaction as streamed off Geyser, before decoding to the oracle's
    `Transaction`. Provider-agnostic — the Yellowstone client populates it.

    `account_keys` is the full ordered account list; `account_changes`
    carries pre/post lamport balances; `instructions_program_ids` is the
    ordered list of invoked program IDs. `received_at` is stamped by the
    indexer the instant the update arrives — the start of the latency clock.
    """
    signature:        str
    slot:             int
    block_time:       datetime               # on-chain confirmation time
    is_successful:    bool
    fee_lamports:     int
    compute_units:    int
    account_keys:     tuple[str, ...]
    account_changes:  tuple[GeyserAccountChange, ...]
    instr_program_ids: tuple[str, ...]
    # Indexer-stamped: when this update was received off the stream.
    received_at:      datetime | None = None
    # The transaction's compute-budget priority fee, if the validator
    # surfaced it; 0 when absent.
    priority_fee_lamports: int = 0

    def __post_init__(self) -> None:
        if not self.signature:
            raise ValueError("GeyserTransactionUpdate.signature must be non-empty")
        if self.slot < 0:
            raise ValueError(f"slot must be non-negative, got {self.slot}")
        if self.block_time.tzinfo is None:
            raise ValueError("block_time must be timezone-aware UTC")


# =============================================================================
# IngestedTransaction — a decoded transaction + its provenance
# =============================================================================

@dataclass(frozen=True, slots=True)
class IngestedTransaction:
    """
    A transaction after decoding, paired with the agent it belongs to and
    the source it arrived by. This is what the writer persists and the
    reconciler compares.
    """
    agent_wallet: str
    transaction:  object                     # features.types.Transaction
    source:       IngestionSource
    # Latency: confirmation -> in-our-hands, in milliseconds. None if the
    # update carried no received_at stamp.
    ingest_latency_ms: float | None = None
