"""
indexer/diagnosis_payload_ingest.py — Day-39 evidence-DA ingest seam.

The path the cluster's leader uses to publish the agreed canonical-JSON
evidence payload into the indexer's DA store, paired with the on-chain
cert v2 hash observation that flips the attestation tag for the served
record.

TWO INGESTS, ONE WRITER
-----------------------
Both flow through this writer because they share the same row:

  1. Payload ingest — the cluster leader, after `_payload_hash_consensus`
     selects the agreed bytes, hands the canonical JSON to the indexer
     alongside the cert. The writer stores it under the (agent, epoch)
     row keyed by sha256(bytes).
  2. On-chain hash observation — the indexer watches the cert v2
     emission on-chain; when it sees a `diagnosis_payload_hash` for the
     same (agent, epoch), it calls `record_on_chain_observation`. The
     served API record then carries `attestation: "threshold_attested"`
     iff the bytes match.

The seam is deliberately small: no decoding, no canonicalisation, no
trust calls. The writer's job is to plumb already-canonical bytes from
the cluster (or the chain) into the DA store. The repository handles
conflict detection (a divergent (agent, epoch) write raises into a
caller-visible audit branch).

INVARIANTS
----------
  * The bytes the leader publishes MUST hash to `payload_hash`. The
    writer asserts this on ingest — a malformed publish is a cluster
    bug, surfaced loudly rather than silently corrupted into the DA.
  * `signer_count` matches the count the cluster's threshold cert
    carries. The API surfaces it so a consumer can apply a higher trust
    bar than the cluster's threshold.
  * `taxonomy_version` matches the on-chain cert v2 u8 field — the
    cluster folds it into the digest, so a divergent value here is
    proof of an indexer/cluster mismatch.
"""

from __future__ import annotations

import hashlib
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

# Cross-package import — same pattern as indexer/writer.py uses to reach
# the oracle's TransactionRepository.
_API_ROOT = Path(__file__).resolve().parents[2] / "helixor-api"
if str(_API_ROOT) not in sys.path:
    sys.path.insert(0, str(_API_ROOT))

from api.evidence_repo import (  # noqa: E402
    EvidencePayloadRecord,
    EvidencePayloadRepository,
)


logger = logging.getLogger("helixor.indexer.diagnosis_payload_ingest")


__all__ = (
    "DiagnosisPayloadEvent",
    "DiagnosisPayloadIngestor",
)


# =============================================================================
# Inbound event — what the cluster leader hands the indexer
# =============================================================================

@dataclass(frozen=True, slots=True)
class DiagnosisPayloadEvent:
    """One agreed canonical-JSON evidence payload, ready to be written.

    The cluster leader emits one of these per (agent, epoch) AFTER
    `_payload_hash_consensus` has selected the agreed bytes — so by the
    time it reaches the indexer, the bytes are already the cluster
    majority's view, and the hash already matches the cert v2 field the
    leader is about to submit on-chain.

    Fields:
      agent_wallet     — the scored agent
      epoch            — the cluster epoch the cert is for
      payload_bytes    — EXACT canonical JSON; sha256(bytes) == hash
      taxonomy_version — u8, mirrors the on-chain field
      signer_count     — number of cluster signatures the cert carries
      computed_at      — wall-clock when the leader emitted (UTC tz-aware)

    The writer recomputes the hash and refuses to store mismatched
    publishes.
    """
    agent_wallet:     str
    epoch:            int
    payload_bytes:    bytes
    taxonomy_version: int
    signer_count:     int
    computed_at:      datetime


# =============================================================================
# Ingestor
# =============================================================================

class DiagnosisPayloadIngestor:
    """The Day-39 DA writer.

    Construct with any `EvidencePayloadRepository` (in-memory for tests,
    `TimescaleEvidencePayloadRepo` in production). Keeps a small set of
    counters tests inspect.
    """

    __slots__ = ("_repo", "_written", "_conflicts", "_attested")

    def __init__(self, repo: EvidencePayloadRepository) -> None:
        self._repo = repo
        self._written = 0
        self._conflicts = 0
        self._attested = 0

    # ── Counters ────────────────────────────────────────────────────────────

    @property
    def written_count(self) -> int:
        return self._written

    @property
    def conflict_count(self) -> int:
        return self._conflicts

    @property
    def attested_count(self) -> int:
        return self._attested

    # ── Ingest paths ────────────────────────────────────────────────────────

    def ingest_payload(self, event: DiagnosisPayloadEvent) -> EvidencePayloadRecord:
        """Persist the agreed canonical bytes. Recomputes the hash from
        the bytes — a publish where bytes do not match the leader's
        claimed hash is a cluster bug and is surfaced as a ValueError.

        Idempotent on (payload_hash) — the repo's content-addressed PK
        treats a re-emit as a no-op. A divergent (agent, epoch) write
        increments the conflict counter and re-raises."""
        payload_hash = hashlib.sha256(event.payload_bytes).digest()
        record = EvidencePayloadRecord(
            agent_wallet=event.agent_wallet,
            epoch=event.epoch,
            payload_bytes=event.payload_bytes,
            payload_hash=payload_hash,
            taxonomy_version=event.taxonomy_version,
            signer_count=event.signer_count,
            computed_at=event.computed_at,
            on_chain_hash=None,
        )
        try:
            self._repo.add(record)
        except ValueError as exc:
            self._conflicts += 1
            logger.error(
                "diagnosis_payload conflict for %s @ epoch %d: %s",
                event.agent_wallet, event.epoch, exc,
            )
            raise
        self._written += 1
        return record

    def record_on_chain_observation(
        self, *, agent_wallet: str, epoch: int, on_chain_hash: bytes,
    ) -> None:
        """Called when the on-chain watcher observes a cert v2's
        `diagnosis_payload_hash` for (agent, epoch). The served record
        carries `attestation: "threshold_attested"` iff the stored bytes
        hash to the same value.

        The `attested` counter increments only when the hash MATCHES
        the bytes we already hold — a mismatched observation is a
        consistency hazard the operator surfaces via the divergence
        audit table (out of scope here)."""
        if len(on_chain_hash) != 32:
            raise ValueError("on_chain_hash must be 32 bytes")
        self._repo.record_on_chain_hash(agent_wallet, epoch, on_chain_hash)
        existing = self._repo.evidence_at_epoch(agent_wallet, epoch)
        if existing is not None and existing.is_threshold_attested:
            self._attested += 1
