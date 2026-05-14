"""
helixor-oracle / baseline — Baseline Engine v2.

Public API:
    compute_baseline(agent_wallet, transactions, window) -> BaselineStats
    BaselineStats                       frozen, self-describing baseline
    BASELINE_ALGO_VERSION               version constant (= 2)
    compute_stats_hash(...)             the on-chain commitment hash
    stats_hash_to_bytes(hex)            64-hex -> 32 raw bytes for on-chain

    repository.save_baseline / load_latest / load_history / ...

    BaselineError / InsufficientDataError / IncompatibleBaselineError
"""

from __future__ import annotations

from baseline.engine import compute_baseline
from baseline.hashing import compute_stats_hash, stats_hash_to_bytes
from baseline.types import (
    BASELINE_ALGO_VERSION,
    MIN_DAYS_WITH_ACTIVITY,
    MIN_TRANSACTION_COUNT,
    BaselineError,
    BaselineStats,
    IncompatibleBaselineError,
    InsufficientDataError,
)

__all__ = [
    "compute_baseline",
    "BaselineStats",
    "BASELINE_ALGO_VERSION",
    "MIN_DAYS_WITH_ACTIVITY",
    "MIN_TRANSACTION_COUNT",
    "compute_stats_hash",
    "stats_hash_to_bytes",
    "BaselineError",
    "InsufficientDataError",
    "IncompatibleBaselineError",
]
