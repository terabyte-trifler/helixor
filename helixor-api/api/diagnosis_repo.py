"""
api/diagnosis_repo.py — the off-chain diagnosis-read repository (Day 34).

WHAT THIS SERVES
----------------
`GET /agents/{wallet}/diagnosis` and `…/diagnosis/{epoch}` return the
per-(agent, epoch) diagnosis the oracle computes alongside the
composite score. The shape mirrors `oracle.diagnosis.DiagnosisRecord`
verbatim — the API does not re-derive anything.

WHY A SEPARATE REPO FROM SCORE
------------------------------
Same separation rationale as `score_repo` vs `byzantine_repo`: a
different read shape lives behind a different protocol. A score record
carries the *single composite number*. A diagnosis record carries the
*structured breakdown* — per-dimension `{score, max_score, sub_scores,
flags}` plus weighted contributions, gaming + confidence signals, and
the provenance chain (`baseline_stats_hash`,
`scoring_schema_fingerprint`).

PHASE-1 vs PHASE-2 ATTESTATION
------------------------------
Phase-1 (Day 34, this file): off-chain. Records are populated by the
indexer from the oracle's epoch_runner output. The API marks each
response `attestation: "off_chain_v1"` so a consumer cannot mistake it
for a threshold-signed value.

Phase-2 (cert v2): the same field set lifts into a threshold-signed
certificate. The Protocol here is the seam that change slots into:
the `DiagnosisRecord` shape stays stable; only the production
implementation (TimescaleDiagnosisRepo) starts reading from the
attested-cert table instead of the off-chain mirror.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

# `DiagnosisRecord` and `DimensionBreakdown` are owned by the oracle's
# diagnosis package — single source of truth shared across the API,
# the indexer, and the web app's regenerator. We re-export them so
# api.* consumers don't have to reach into the oracle package directly.
from diagnosis.record import DiagnosisRecord, DimensionBreakdown


__all__ = (
    "DiagnosisRecord",
    "DimensionBreakdown",
    "DiagnosisRepository",
    "InMemoryDiagnosisRepo",
)


# =============================================================================
# The protocol
# =============================================================================

class DiagnosisRepository(Protocol):
    """The read interface the API depends on. Implemented in-memory for
    tests and against the indexer's `agent_diagnosis_history` hypertable
    in production (Phase-1) or against the attested-cert table once cert
    v2 ships (Phase-2)."""

    def latest_diagnosis(self, agent_wallet: str) -> DiagnosisRecord | None: ...

    def diagnosis_at_epoch(
        self, agent_wallet: str, epoch: int,
    ) -> DiagnosisRecord | None: ...

    def known_agents(self) -> list[str]: ...


# =============================================================================
# In-memory implementation — for tests and the empty-repo fallback
# =============================================================================

class InMemoryDiagnosisRepo:
    """A deterministic, pure-Python diagnosis repo. Same write-once
    semantics as `InMemoryScoreRepo`: re-adding the same (agent, epoch)
    replaces the prior record, matching the on-chain certificate's
    single-writer-per-epoch contract."""

    def __init__(self, records: Iterable[DiagnosisRecord] | None = None) -> None:
        self._by_agent: dict[str, list[DiagnosisRecord]] = {}
        if records:
            for r in records:
                self.add(r)

    def add(self, record: DiagnosisRecord) -> None:
        bucket = self._by_agent.setdefault(record.agent_wallet, [])
        bucket[:] = [r for r in bucket if r.epoch != record.epoch]
        bucket.append(record)
        bucket.sort(key=lambda r: r.epoch)

    def add_many(self, records: Iterable[DiagnosisRecord]) -> None:
        for r in records:
            self.add(r)

    def latest_diagnosis(self, agent_wallet: str) -> DiagnosisRecord | None:
        bucket = self._by_agent.get(agent_wallet)
        return bucket[-1] if bucket else None

    def diagnosis_at_epoch(
        self, agent_wallet: str, epoch: int,
    ) -> DiagnosisRecord | None:
        for r in self._by_agent.get(agent_wallet, ()):
            if r.epoch == epoch:
                return r
        return None

    def known_agents(self) -> list[str]:
        return sorted(self._by_agent)
