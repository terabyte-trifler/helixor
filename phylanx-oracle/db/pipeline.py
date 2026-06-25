"""
db/pipeline.py — repository-backed feature extraction + baseline computation.

This is the seam the Day-15 brief calls for: "the feature extractor reads
from TimescaleDB". It does NOT push a database into the pure functions —
`extract` and `compute_baseline` stay pure `Sequence[Transaction]` → result
functions (the BFT determinism rule).

Instead this module is the thin orchestration that:
  1. fetches a transaction window from a `TransactionRepository`
     (TimescaleDB in production, in-memory in tests),
  2. hands the resulting list to the unchanged pure functions.

The repository abstraction means the SAME pipeline code runs against the
TimescaleDB hypertable or an in-memory store, byte-identically.
"""

from __future__ import annotations

from datetime import datetime

from baseline import BaselineStats, compute_baseline
from db.repository import TransactionQuery, TransactionRepository
from features import ExtractionWindow, FeatureVector, extract


# =============================================================================
# Repository-backed feature extraction
# =============================================================================

def extract_from_repository(
    repo:         TransactionRepository,
    agent_wallet: str,
    window:       ExtractionWindow,
) -> FeatureVector:
    """
    Extract an agent's 100-feature vector for a window, reading the
    transactions from `repo` (the TimescaleDB hypertable in production).

    The fetch is one bounded window query; the extraction is the unchanged
    pure `extract`. Deterministic given (repo contents, agent, window).
    """
    query = TransactionQuery.for_extraction_window(agent_wallet, window)
    transactions = repo.fetch_transactions(query)
    return extract(transactions, window)


# =============================================================================
# Repository-backed baseline computation
# =============================================================================

def compute_baseline_from_repository(
    repo:         TransactionRepository,
    agent_wallet: str,
    window:       ExtractionWindow,
    *,
    computed_at:  datetime | None = None,
) -> BaselineStats:
    """
    Compute an agent's baseline for a window, reading the transactions from
    `repo`.

    The fetch is one window query; the computation is the unchanged pure
    `compute_baseline`. Raises the same `InsufficientDataError` as the pure
    function when the window is too thin.
    """
    query = TransactionQuery.for_extraction_window(agent_wallet, window)
    transactions = repo.fetch_transactions(query)
    return compute_baseline(
        agent_wallet, transactions, window, computed_at=computed_at,
    )
