"""
oracle/cluster/diagnosis_payload_emit.py — Day-39 leader emit helper.

The seam between the cluster's aggregator and the DA store. After
`aggregate_scores` produces an `AggregatedScore` with a non-empty
`diagnosis_payload_hash`, the cluster's leader hands the canonical-JSON
bytes (which it can reproduce from its own kernel inputs, because every
honest node's bytes are byte-identical by construction) to this
helper. The helper:

  1. Verifies sha256(bytes) matches the cluster's agreed hash. A
     mismatch means the leader's kernel diverged from the cluster's —
     a node-side bug, not a cluster-side one, and the leader MUST NOT
     publish.
  2. Wraps the bytes + metadata into a `DiagnosisPayloadEvent` shape
     the indexer's `DiagnosisPayloadIngestor` accepts.

The helper does NOT call the indexer itself — the cluster runner owns
the I/O boundary. Keeping this pure means tests can drive it without a
fake indexer in the picture.

WHY VERIFY ON EMIT
------------------
The cluster already proved an honest majority agreed on the hash via
`_payload_hash_consensus`. If the leader's local bytes don't hash to
that value, the leader is the divergent node — its kernel result didn't
match what the rest of the cluster produced. Publishing those bytes
would land them in the DA store with a hash that NO cert v2 attests to,
permanently breaking the round-trip seam for this (agent, epoch). The
guard forces a loud failure instead.
"""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime
from pathlib import Path

# Cross-package import — pull the indexer event type. Same sys.path
# pattern timescale_evidence_repo.py uses to reach helixor-api.
_INDEXER_ROOT = Path(__file__).resolve().parents[3] / "helixor-indexer"
if str(_INDEXER_ROOT) not in sys.path:
    sys.path.insert(0, str(_INDEXER_ROOT))

from indexer.diagnosis_payload_ingest import DiagnosisPayloadEvent  # noqa: E402

from oracle.cluster.aggregation import AggregatedScore


__all__ = (
    "PayloadHashMismatch",
    "cluster_emit_diagnosis_payload",
)


class PayloadHashMismatch(ValueError):
    """Raised when the leader's local canonical bytes do NOT hash to the
    cluster's agreed `diagnosis_payload_hash`. Carries both hashes so
    the operator can attribute the divergence."""


def cluster_emit_diagnosis_payload(
    aggregated:       AggregatedScore,
    payload_bytes:    bytes,
    *,
    epoch:            int,
    taxonomy_version: int,
    computed_at:      datetime,
) -> DiagnosisPayloadEvent:
    """Build the event the leader will ship to the indexer's DA writer.

    Pre-condition: `sha256(payload_bytes) == aggregated.diagnosis_payload_hash`.
    Without this, the leader publishes bytes the cluster did not attest
    to — a hard error.

    `signer_count` is derived from `payload_hash_signers` — the same
    set the cert v2 collects threshold signatures from, so a consumer
    that reads `signer_count` off the API record is reading a value
    that matches the on-chain field.

    Pure. The caller owns the actual I/O (sending the event to the
    indexer's ingest path).
    """
    if not aggregated.has_payload_hash_consensus:
        raise ValueError(
            f"cluster has no payload-hash consensus for "
            f"{aggregated.agent_wallet}: leader must not emit a DA payload"
        )
    expected = bytes(aggregated.diagnosis_payload_hash)
    observed = hashlib.sha256(payload_bytes).digest()
    if observed != expected:
        raise PayloadHashMismatch(
            f"leader's local canonical bytes for {aggregated.agent_wallet} "
            f"hash to {observed.hex()}, but cluster agreed on "
            f"{expected.hex()} — refusing to publish divergent bytes"
        )
    if epoch < 1:
        raise ValueError(f"epoch must be >= 1, got {epoch}")
    if not (0 <= taxonomy_version <= 0xFF):
        raise ValueError(
            f"taxonomy_version must fit in u8, got {taxonomy_version}"
        )
    if computed_at.tzinfo is None:
        raise ValueError("computed_at must be timezone-aware UTC")

    return DiagnosisPayloadEvent(
        agent_wallet=aggregated.agent_wallet,
        epoch=epoch,
        payload_bytes=payload_bytes,
        taxonomy_version=taxonomy_version,
        signer_count=len(aggregated.payload_hash_signers),
        computed_at=computed_at,
    )
