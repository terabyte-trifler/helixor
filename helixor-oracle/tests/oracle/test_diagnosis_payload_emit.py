"""
tests/oracle/test_diagnosis_payload_emit.py — Day-39 leader-emit helper.

Covers the post-aggregation seam that turns an `AggregatedScore` plus
the leader's local canonical-JSON bytes into a `DiagnosisPayloadEvent`
ready for the indexer's DA writer.

Pinned guarantees:
  * sha256(bytes) == aggregated.diagnosis_payload_hash — divergent
    leader bytes raise PayloadHashMismatch.
  * `signer_count` is the number of nodes in
    aggregated.payload_hash_signers (the cert v2 signing set).
  * Score-only mode (no payload-hash consensus) refuses to emit.
  * Wire fields (epoch, taxonomy_version, computed_at) are pinned
    one-to-one onto the event.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from oracle.cluster.aggregation import AggregatedScore
from oracle.cluster.diagnosis_payload_emit import (
    PayloadHashMismatch,
    cluster_emit_diagnosis_payload,
)


WALLET = "A1" * 22
REF_TS = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def _canonical_bytes() -> bytes:
    return json.dumps(
        {"taxonomy_version": "1", "kernel_manifest": "a" * 64,
         "dimensions": [], "findings": []},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _aggregated(*, hash_value: bytes, signers=("n1", "n2", "n3")) -> AggregatedScore:
    return AggregatedScore(
        agent_wallet=WALLET,
        score=920, alert_tier=0, flags=0, immediate_red=False, confidence=900,
        contributing_nodes=signers,
        node_count=len(signers),
        quorum=2,
        score_spread=0,
        label_bitmask=0,
        diagnosis_payload_hash=hash_value,
        payload_hash_signers=signers,
        payload_hash_dissenters=(),
    )


# =============================================================================
# A — happy path
# =============================================================================

class TestHappyPath:

    def test_returns_event_with_matching_hash(self):
        bytes_ = _canonical_bytes()
        agg = _aggregated(hash_value=hashlib.sha256(bytes_).digest())
        event = cluster_emit_diagnosis_payload(
            agg, bytes_,
            epoch=29, taxonomy_version=1, computed_at=REF_TS,
        )
        assert event.agent_wallet == WALLET
        assert event.epoch == 29
        assert event.payload_bytes == bytes_
        assert event.taxonomy_version == 1
        assert event.signer_count == 3
        assert event.computed_at == REF_TS

    def test_signer_count_matches_signing_set_size(self):
        bytes_ = _canonical_bytes()
        agg = _aggregated(
            hash_value=hashlib.sha256(bytes_).digest(),
            signers=("n1", "n2", "n3", "n4", "n5"),
        )
        event = cluster_emit_diagnosis_payload(
            agg, bytes_,
            epoch=29, taxonomy_version=1, computed_at=REF_TS,
        )
        assert event.signer_count == 5


# =============================================================================
# B — divergence refusal
# =============================================================================

class TestDivergenceRefusal:

    def test_divergent_bytes_raise_mismatch(self):
        bytes_ = _canonical_bytes()
        # Cluster agreed on hash X, leader's local bytes hash to Y.
        agg = _aggregated(hash_value=b"\xff" * 32)
        with pytest.raises(PayloadHashMismatch, match="refusing"):
            cluster_emit_diagnosis_payload(
                agg, bytes_,
                epoch=29, taxonomy_version=1, computed_at=REF_TS,
            )

    def test_no_payload_consensus_refuses(self):
        """Score-only mode: aggregated.diagnosis_payload_hash is b"".
        The leader must not emit a DA payload."""
        agg = _aggregated(hash_value=b"")
        with pytest.raises(ValueError, match="no payload-hash consensus"):
            cluster_emit_diagnosis_payload(
                agg, _canonical_bytes(),
                epoch=29, taxonomy_version=1, computed_at=REF_TS,
            )


# =============================================================================
# C — invariant guards
# =============================================================================

class TestInvariantGuards:

    def test_epoch_must_be_positive(self):
        bytes_ = _canonical_bytes()
        agg = _aggregated(hash_value=hashlib.sha256(bytes_).digest())
        with pytest.raises(ValueError, match="epoch"):
            cluster_emit_diagnosis_payload(
                agg, bytes_,
                epoch=0, taxonomy_version=1, computed_at=REF_TS,
            )

    def test_taxonomy_version_must_fit_u8(self):
        bytes_ = _canonical_bytes()
        agg = _aggregated(hash_value=hashlib.sha256(bytes_).digest())
        with pytest.raises(ValueError, match="u8"):
            cluster_emit_diagnosis_payload(
                agg, bytes_,
                epoch=29, taxonomy_version=256, computed_at=REF_TS,
            )

    def test_computed_at_must_be_tz_aware(self):
        bytes_ = _canonical_bytes()
        agg = _aggregated(hash_value=hashlib.sha256(bytes_).digest())
        with pytest.raises(ValueError, match="UTC"):
            cluster_emit_diagnosis_payload(
                agg, bytes_,
                epoch=29, taxonomy_version=1,
                computed_at=datetime(2026, 5, 1),  # naive
            )
