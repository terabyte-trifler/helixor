"""
api/score_repo.py — the score-read repository.

A read-side abstraction over the agent score history. Production reads
from the indexer's `agent_score_history` TimescaleDB hypertable; tests
use `InMemoryScoreRepo`.

WHY A SEPARATE REPO FROM TRANSACTIONS
-------------------------------------
helixor-oracle's `TransactionRepository` reads raw on-chain transactions
— the input to detection. This repo reads the OUTPUT — the per-epoch
score certificates that the cluster wrote on-chain and the indexer
mirrored into the database.

Different shape, different table, different access pattern (transactions
are time-series; scores are per-(agent, epoch) records), so a separate
protocol. Both follow the same protocol-then-implementation discipline
the rest of the codebase uses.

NO ON-CHAIN FALLBACK HERE
-------------------------
This repo reads ONLY from the indexer's database. The on-chain SDK
(helixor-sdk/HelixorClient) is the authoritative read; this is the
accelerated cache. A score that hasn't yet been indexed is a 404 — the
client falls back to the SDK if they need a strictly-on-chain read.
That separation is deliberate: it keeps the API stateless w.r.t. Solana
RPC, so the API can serve 10K req/h without holding RPC connections.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


# =============================================================================
# The shape — one score record per (agent, epoch)
# =============================================================================

@dataclass(frozen=True, slots=True)
class ScoreRecord:
    """
    One agent's score for one epoch — the same fields the on-chain
    HealthCertificate carries, plus the per-cert observed signer count.
    """
    agent_wallet:    str
    epoch:           int
    score:           int            # 0..1000
    alert_tier:      int            # 0 GREEN, 1 YELLOW, 2 RED
    flags:           int            # u32 aggregated detection flags
    immediate_red:   bool
    signer_count:    int            # how many cluster keys signed this cert
    computed_at:     datetime       # when the cluster computed it

    def __post_init__(self) -> None:
        if not (0 <= self.score <= 1000):
            raise ValueError(f"score out of range: {self.score}")
        if self.alert_tier not in (0, 1, 2):
            raise ValueError(f"alert_tier invalid: {self.alert_tier}")
        if self.epoch < 1:
            raise ValueError(f"epoch must be >= 1, got {self.epoch}")
        if self.signer_count < 1:
            raise ValueError(f"signer_count must be >= 1, got {self.signer_count}")


# =============================================================================
# The protocol
# =============================================================================

class ScoreRepository(Protocol):
    """The read interface the API depends on. Implemented in-memory for
    tests and against TimescaleDB in production."""

    def latest_score(self, agent_wallet: str) -> ScoreRecord | None: ...

    def score_at_epoch(
        self, agent_wallet: str, epoch: int,
    ) -> ScoreRecord | None: ...

    def score_history(
        self,
        agent_wallet: str,
        *,
        from_epoch: int | None = None,
        to_epoch:   int | None = None,
        limit:      int = 100,
    ) -> list[ScoreRecord]: ...

    def known_agents(self) -> list[str]: ...


# =============================================================================
# In-memory implementation — for tests, dev, and the test fixtures
# =============================================================================

class InMemoryScoreRepo:
    """A deterministic, pure-Python score repo for tests."""

    def __init__(self, records: Iterable[ScoreRecord] | None = None) -> None:
        self._by_agent: dict[str, list[ScoreRecord]] = {}
        if records:
            for r in records:
                self.add(r)

    def add(self, record: ScoreRecord) -> None:
        bucket = self._by_agent.setdefault(record.agent_wallet, [])
        # Replace any existing record for the same (agent, epoch) — the
        # newest write wins, matching the on-chain certificate's
        # write-once semantics (a re-insert is the same cert).
        bucket[:] = [r for r in bucket if r.epoch != record.epoch]
        bucket.append(record)
        bucket.sort(key=lambda r: r.epoch)

    def add_many(self, records: Iterable[ScoreRecord]) -> None:
        for r in records:
            self.add(r)

    def latest_score(self, agent_wallet: str) -> ScoreRecord | None:
        bucket = self._by_agent.get(agent_wallet)
        return bucket[-1] if bucket else None

    def score_at_epoch(
        self, agent_wallet: str, epoch: int,
    ) -> ScoreRecord | None:
        for r in self._by_agent.get(agent_wallet, ()):
            if r.epoch == epoch:
                return r
        return None

    def score_history(
        self,
        agent_wallet: str,
        *,
        from_epoch: int | None = None,
        to_epoch:   int | None = None,
        limit:      int = 100,
    ) -> list[ScoreRecord]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if limit > 1000:
            raise ValueError("limit must be <= 1000")
        bucket = self._by_agent.get(agent_wallet, ())
        out = [
            r for r in bucket
            if (from_epoch is None or r.epoch >= from_epoch)
            and (to_epoch   is None or r.epoch <= to_epoch)
        ]
        # Newest first — the typical client wants the most recent epochs.
        out.sort(key=lambda r: r.epoch, reverse=True)
        return out[:limit]

    def known_agents(self) -> list[str]:
        return sorted(self._by_agent)
