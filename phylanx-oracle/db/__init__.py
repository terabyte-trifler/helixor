"""
phylanx-oracle / db — the data-access layer.

Day 15 (Phase 2) introduces the repository abstraction that the feature
extractor and baseline engine read transactions through.

Public API:
    TransactionRepository       the read interface (a Protocol)
    InMemoryTransactionRepo     a pure in-memory implementation (tests, replay)
    TimescaleTransactionRepo    the TimescaleDB-backed implementation
    TransactionQuery            a typed (agent, time-window) query
"""

from __future__ import annotations

from db.repository import (
    InMemoryTransactionRepo,
    TransactionQuery,
    TransactionRepository,
)
from db.timescale_repo import TimescaleTransactionRepo
from db.pipeline import (
    compute_baseline_from_repository,
    extract_from_repository,
)

__all__ = [
    "TransactionRepository",
    "InMemoryTransactionRepo",
    "TimescaleTransactionRepo",
    "TransactionQuery",
    "extract_from_repository",
    "compute_baseline_from_repository",
]
