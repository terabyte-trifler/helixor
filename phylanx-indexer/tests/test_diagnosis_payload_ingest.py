"""
tests/test_diagnosis_payload_ingest.py — Day-39 evidence-DA ingest seam.

Covers the indexer-side ingestor end-to-end against the in-memory repo:

  * ingest_payload writes a record whose hash matches sha256(payload_bytes)
  * idempotent re-emit is a no-op (same content, same hash)
  * divergent (agent, epoch) write raises and the conflict counter ticks
  * record_on_chain_observation flips the attestation tag iff the bytes
    hash to the observed value
  * counters increment as expected
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from api.evidence_repo import InMemoryEvidencePayloadRepo
from indexer.diagnosis_payload_ingest import (
    DiagnosisPayloadEvent,
    DiagnosisPayloadIngestor,
)


# =============================================================================
# Helpers
# =============================================================================

WALLET_A = "A1" * 22
WALLET_B = "B2" * 22
REF_TS = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _event(*, wallet=WALLET_A, epoch=29, payload=None, signers=5) -> DiagnosisPayloadEvent:
    payload = payload if payload is not None else {
        "taxonomy_version": "1",
        "kernel_manifest":  "a" * 64,
        "dimensions": [],
        "findings": [],
    }
    return DiagnosisPayloadEvent(
        agent_wallet=wallet,
        epoch=epoch,
        payload_bytes=_canonical(payload),
        taxonomy_version=1,
        signer_count=signers,
        computed_at=REF_TS,
    )


# =============================================================================
# A — payload ingest
# =============================================================================

class TestIngestPayload:

    def test_writes_record_with_sha256_hash(self):
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        event = _event()
        record = ing.ingest_payload(event)
        assert record.payload_hash == hashlib.sha256(event.payload_bytes).digest()
        assert record.agent_wallet == event.agent_wallet
        assert record.epoch == event.epoch
        assert record.signer_count == event.signer_count
        assert record.on_chain_hash is None
        assert ing.written_count == 1

    def test_record_lookup_round_trips_through_repo(self):
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        event = _event()
        ing.ingest_payload(event)
        rec = repo.evidence_at_epoch(WALLET_A, 29)
        assert rec is not None
        assert rec.payload_bytes == event.payload_bytes

    def test_idempotent_re_emit_no_op(self):
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        event = _event()
        ing.ingest_payload(event)
        ing.ingest_payload(event)  # same hash, no-op
        # written_count is per-ingest call by design — the repo's
        # content-addressed dedup happens inside.
        assert ing.written_count == 2
        assert ing.conflict_count == 0
        rec = repo.evidence_at_epoch(WALLET_A, 29)
        assert rec.payload_hash == hashlib.sha256(event.payload_bytes).digest()

    def test_divergent_agent_epoch_raises_and_counts(self):
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        ing.ingest_payload(_event())
        # A different payload under the same (agent, epoch).
        divergent = _event(payload={
            "taxonomy_version": "1",
            "kernel_manifest":  "b" * 64,
            "dimensions": [],
            "findings": [],
        })
        with pytest.raises(ValueError, match="conflicting"):
            ing.ingest_payload(divergent)
        assert ing.conflict_count == 1


# =============================================================================
# B — on-chain hash observation flips attestation
# =============================================================================

class TestOnChainObservation:

    def test_matching_hash_flips_to_threshold_attested(self):
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        event = _event()
        ing.ingest_payload(event)

        on_chain = hashlib.sha256(event.payload_bytes).digest()
        ing.record_on_chain_observation(
            agent_wallet=WALLET_A, epoch=29, on_chain_hash=on_chain,
        )
        rec = repo.evidence_at_epoch(WALLET_A, 29)
        assert rec.is_threshold_attested is True
        assert ing.attested_count == 1

    def test_mismatched_hash_does_not_attest(self):
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        ing.ingest_payload(_event())

        ing.record_on_chain_observation(
            agent_wallet=WALLET_A, epoch=29, on_chain_hash=b"\xff" * 32,
        )
        rec = repo.evidence_at_epoch(WALLET_A, 29)
        assert rec.is_threshold_attested is False
        assert ing.attested_count == 0
        # The bytes are still surfaced — the operator inspects both
        # sides via the diagnostic API.
        assert rec.on_chain_hash == b"\xff" * 32

    def test_observation_with_no_payload_is_noop(self):
        """The indexer may see a cert v2 before its payload arrives —
        the in-memory shim drops the observation. The production
        Timescale impl persists it in a separate pending audit table."""
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        # No ingest_payload yet — observation has no row to flip.
        ing.record_on_chain_observation(
            agent_wallet=WALLET_A, epoch=29, on_chain_hash=b"\xab" * 32,
        )
        assert repo.evidence_at_epoch(WALLET_A, 29) is None
        assert ing.attested_count == 0


# =============================================================================
# C — invariants
# =============================================================================

class TestInvariants:

    def test_on_chain_hash_must_be_32_bytes(self):
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        ing.ingest_payload(_event())
        with pytest.raises(ValueError, match="32 bytes"):
            ing.record_on_chain_observation(
                agent_wallet=WALLET_A, epoch=29, on_chain_hash=b"\xab" * 16,
            )

    def test_multiple_agents_independent(self):
        """In practice every agent produces distinct canonical bytes
        because the kernel result depends on agent-specific findings —
        pin that both rows land independently and the per-agent reads
        return the correct row."""
        repo = InMemoryEvidencePayloadRepo()
        ing = DiagnosisPayloadIngestor(repo)
        payload_a = {
            "taxonomy_version": "1", "kernel_manifest": "a" * 64,
            "dimensions": [], "findings": [],
        }
        payload_b = {
            "taxonomy_version": "1", "kernel_manifest": "b" * 64,
            "dimensions": [], "findings": [],
        }
        ing.ingest_payload(_event(wallet=WALLET_A, epoch=29, payload=payload_a))
        ing.ingest_payload(_event(wallet=WALLET_B, epoch=29, payload=payload_b))
        rec_a = repo.evidence_at_epoch(WALLET_A, 29)
        rec_b = repo.evidence_at_epoch(WALLET_B, 29)
        assert rec_a is not None and rec_b is not None
        assert rec_a.agent_wallet == WALLET_A
        assert rec_b.agent_wallet == WALLET_B
        assert rec_a.payload_hash != rec_b.payload_hash
        assert ing.written_count == 2
