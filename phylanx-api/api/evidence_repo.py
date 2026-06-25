"""
api/evidence_repo.py — Day-39 off-chain evidence DA repository.

WHAT THIS SERVES
----------------
`GET /agents/{wallet}/diagnosis/{epoch}/evidence` returns the canonical-
JSON diagnosis payload whose SHA-256 == the on-chain `diagnosis_payload_hash`
field of the (Day-38, cert v2) HealthCertificate. The bytes here are the
DA (data-availability) tier for the threshold-attested hash: cert v2
attests to the hash; this table stores the bytes.

WHY A SEPARATE REPO FROM DIAGNOSIS
----------------------------------
The Day-34 `DiagnosisRepository` returns the Phase-1 off-chain breakdown
(`DiagnosisRecord` — per-dimension scores, decoded labels, gaming
signals). That surface is `attestation: "off_chain_v1"` because nothing
on-chain attests to it.

Day 39 introduces a DIFFERENT surface: the threshold-attested evidence
payload. A single (agent, epoch) can have either or both — the off-chain
breakdown AND the threshold-attested evidence — so the read shapes are
distinct, and the repos are distinct.

STORAGE PATTERN
---------------
Mirrors the Day-26 `baseline_hash` pattern: hash is the primary key,
the payload bytes are the value, and (agent, epoch) is a secondary
index. The bytes are immutable once written — re-storing the same hash
is a no-op (same bytes), and re-storing under the same (agent, epoch)
with a DIFFERENT hash is also a no-op (the indexer treats the first-
recorded hash as the truth and surfaces the conflict via a separate
audit table — Day 39 does not re-implement that).

PHASE-2 ATTESTATION
-------------------
When the indexer sees an on-chain `diagnosis_payload_hash` for the
(agent, epoch) AND the bytes here hash to the same value, the served
record carries `attestation: "threshold_attested"`. Until either side
shows up (no cert, no payload, or mismatch), the record carries
`attestation: "off_chain_v1"` — same wire seam the Day-34 diagnosis
surface uses.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


__all__ = (
    "EvidencePayloadRecord",
    "EvidencePayloadRepository",
    "InMemoryEvidencePayloadRepo",
)


# =============================================================================
# The record
# =============================================================================

@dataclass(frozen=True, slots=True)
class EvidencePayloadRecord:
    """One (agent, epoch) evidence payload.

    `payload_bytes` is the EXACT canonical-JSON bytes the cluster
    threshold-signed against. Storing the raw bytes (rather than
    re-serialising at read time) is what lets a consumer recompute the
    hash and match the on-chain field without trusting the API to
    canonicalise identically.

    `payload_hash` is sha256(payload_bytes), raw 32 bytes. Carried
    redundantly so the read path can hand it back without re-hashing.

    `on_chain_hash` is the threshold-attested cert v2 field for the
    same (agent, epoch), when known. None when the indexer has not yet
    seen the cert. The API surfaces `attestation: "threshold_attested"`
    iff this is set AND equals `payload_hash`.

    `taxonomy_version` mirrors the on-chain Day-38 field — folded into
    the digest by the cluster, exposed here so a consumer reading the
    served bytes can pre-validate against an expected schema before
    decoding the labels.

    `signer_count` is how many cluster signatures the cert v2 collected.
    Surfaced so a consumer can apply a higher trust bar than the
    cluster's threshold.
    """
    agent_wallet:      str
    epoch:             int
    payload_bytes:     bytes
    payload_hash:      bytes              # 32 raw bytes
    taxonomy_version:  int                # u8 — Day-38 field
    signer_count:      int                # cluster signers (Day-37)
    computed_at:       datetime
    on_chain_hash:     bytes | None = None  # None until the cert is observed

    def __post_init__(self) -> None:
        if not self.agent_wallet:
            raise ValueError("agent_wallet must be non-empty")
        if self.epoch < 1:
            raise ValueError(f"epoch must be >= 1, got {self.epoch}")
        if not self.payload_bytes:
            raise ValueError("payload_bytes must be non-empty")
        if len(self.payload_hash) != 32:
            raise ValueError(
                f"payload_hash must be 32 bytes, got {len(self.payload_hash)}"
            )
        recomputed = hashlib.sha256(self.payload_bytes).digest()
        if recomputed != self.payload_hash:
            raise ValueError(
                "payload_hash does not match sha256(payload_bytes) — "
                "refusing to store an inconsistent record"
            )
        if not (0 <= self.taxonomy_version <= 0xFF):
            raise ValueError(
                f"taxonomy_version must fit in u8, got {self.taxonomy_version}"
            )
        if self.signer_count < 0:
            raise ValueError(f"signer_count must be >= 0, got {self.signer_count}")
        if self.computed_at.tzinfo is None:
            raise ValueError("computed_at must be timezone-aware UTC")
        if self.on_chain_hash is not None and len(self.on_chain_hash) != 32:
            raise ValueError(
                f"on_chain_hash must be 32 bytes when set, got {len(self.on_chain_hash)}"
            )

    @property
    def is_threshold_attested(self) -> bool:
        """True iff the indexer has seen the cert v2 AND the bytes here
        hash to the same on-chain value. The API attestation tag flips
        on this property."""
        return (
            self.on_chain_hash is not None
            and self.on_chain_hash == self.payload_hash
        )


# =============================================================================
# Protocol — the read interface the API depends on
# =============================================================================

class EvidencePayloadRepository(Protocol):
    """The read+write interface the API depends on. Implemented in-memory
    for tests, against the indexer's `diagnosis_payloads` table in
    production."""

    def add(self, record: EvidencePayloadRecord) -> None: ...

    def evidence_at_epoch(
        self, agent_wallet: str, epoch: int,
    ) -> EvidencePayloadRecord | None: ...

    def by_hash(self, payload_hash: bytes) -> EvidencePayloadRecord | None: ...

    def record_on_chain_hash(
        self, agent_wallet: str, epoch: int, on_chain_hash: bytes,
    ) -> None:
        """Called by the indexer when it observes the cert v2 hash for
        an (agent, epoch). A subsequent read returns the record with
        `attestation: "threshold_attested"` iff the bytes match."""


# =============================================================================
# In-memory implementation
# =============================================================================

class InMemoryEvidencePayloadRepo:
    """A deterministic, pure-Python evidence-payload repo.

    Storage discipline:
      * Primary key on `payload_hash` — re-storing the same bytes is a
        no-op (content-addressed).
      * Secondary index on `(agent_wallet, epoch)` — the API read path.
      * `record_on_chain_hash` is idempotent — re-recording the same
        on-chain hash for the same (agent, epoch) is a no-op.
      * A conflicting `(agent, epoch)` write (a different hash for an
        already-known agent+epoch) is REFUSED with ValueError. The
        in-memory repo cannot store divergent histories — the indexer's
        Timescale impl is what surfaces the conflict via a separate
        audit table.
    """

    def __init__(self, records: Iterable[EvidencePayloadRecord] | None = None) -> None:
        # Content-addressed primary store.
        self._by_hash: dict[bytes, EvidencePayloadRecord] = {}
        # Secondary (agent, epoch) index — maps to a hash.
        self._by_agent_epoch: dict[tuple[str, int], bytes] = {}
        if records:
            for r in records:
                self.add(r)

    def add(self, record: EvidencePayloadRecord) -> None:
        key = (record.agent_wallet, record.epoch)
        existing_hash = self._by_agent_epoch.get(key)
        if existing_hash is not None and existing_hash != record.payload_hash:
            raise ValueError(
                f"conflicting evidence payload for "
                f"{record.agent_wallet} @ epoch {record.epoch}: "
                f"already stored {existing_hash.hex()}, refusing to "
                f"overwrite with {record.payload_hash.hex()}"
            )
        # Content-addressed dedup — re-storing the same hash is fine,
        # but we update on_chain_hash if the new record carries one and
        # the old did not.
        prev = self._by_hash.get(record.payload_hash)
        if prev is not None and prev.on_chain_hash is None and record.on_chain_hash is not None:
            self._by_hash[record.payload_hash] = record
        else:
            self._by_hash.setdefault(record.payload_hash, record)
        self._by_agent_epoch[key] = record.payload_hash

    def evidence_at_epoch(
        self, agent_wallet: str, epoch: int,
    ) -> EvidencePayloadRecord | None:
        h = self._by_agent_epoch.get((agent_wallet, epoch))
        if h is None:
            return None
        return self._by_hash.get(h)

    def by_hash(self, payload_hash: bytes) -> EvidencePayloadRecord | None:
        return self._by_hash.get(payload_hash)

    def record_on_chain_hash(
        self, agent_wallet: str, epoch: int, on_chain_hash: bytes,
    ) -> None:
        if len(on_chain_hash) != 32:
            raise ValueError("on_chain_hash must be 32 bytes")
        h = self._by_agent_epoch.get((agent_wallet, epoch))
        if h is None:
            # No payload yet — record the on-chain hash for later
            # reconciliation by the indexer. The in-memory repo does
            # not implement a separate "pending" table; the production
            # Timescale impl does.
            return
        rec = self._by_hash[h]
        if rec.on_chain_hash == on_chain_hash:
            return  # idempotent
        # Build a fresh frozen record (cannot mutate a frozen dataclass).
        updated = EvidencePayloadRecord(
            agent_wallet=rec.agent_wallet,
            epoch=rec.epoch,
            payload_bytes=rec.payload_bytes,
            payload_hash=rec.payload_hash,
            taxonomy_version=rec.taxonomy_version,
            signer_count=rec.signer_count,
            computed_at=rec.computed_at,
            on_chain_hash=on_chain_hash,
        )
        self._by_hash[rec.payload_hash] = updated

    def known_pairs(self) -> list[tuple[str, int]]:
        return sorted(self._by_agent_epoch.keys())
