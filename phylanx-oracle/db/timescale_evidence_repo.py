"""
db/timescale_evidence_repo.py — Timescale-backed diagnosis-payload DA store.

The production-side `EvidencePayloadRepository`. Reads/writes the Day-39
`diagnosis_payloads` table (migration 0010), serving the same Protocol the
phylanx-api in-memory impl does (`api/evidence_repo.InMemoryEvidencePayloadRepo`)
so the API route handler is repo-agnostic.

DRIVER INDEPENDENCE
-------------------
Same pattern as `TimescaleTransactionRepo`: the module is written against
a minimal `DBConnection` Protocol (`execute(sql, params) -> rows`). The
deployment chooses the driver (psycopg 3 sync, asyncpg, a pool); the
determinism-critical code path does not transitively import a database
driver. A reference adapter lives in `timescale_repo.py`.

STORAGE INVARIANTS
------------------
The migration (`0010_diagnosis_payloads.sql`) enforces:

  * `payload_hash` is the primary key — re-storing the same bytes is the
    expected idempotent re-emit and the INSERT uses ON CONFLICT DO NOTHING.
  * UNIQUE (agent_wallet, epoch) — a divergent payload under the same
    (agent, epoch) fails the constraint, surfacing the conflict. The
    repo translates the constraint violation into a Python `ValueError`
    so the indexer's ingest path can audit it via the divergence table.

  * Byte invariants (32-byte hashes, non-empty payload, taxonomy in u8
    range) are enforced both by the table constraints AND by the dataclass
    `__post_init__` — defense in depth, since a future caller might
    bypass the dataclass when binding raw rows.

WHY NO RE-CANONICALISATION ON READ
----------------------------------
`payload` is BYTEA. A read returns the bytes verbatim — what the cluster
threshold-signed against, no JSONB round-trip. A re-canonicalisation by
the database would silently break the sha256 contract.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

# The Day-39 record dataclass + Protocol live in phylanx-api. We import
# the record only — the Protocol is satisfied structurally so a re-import
# is unnecessary. Keeping the cross-package import surface to one symbol
# means a future split of the two packages stays a small move.
import sys
from pathlib import Path

_API_ROOT = Path(__file__).resolve().parents[2] / "phylanx-api"
if str(_API_ROOT) not in sys.path:
    sys.path.insert(0, str(_API_ROOT))

from api.evidence_repo import EvidencePayloadRecord  # noqa: E402


__all__ = (
    "DBConnection",
    "TimescaleEvidencePayloadRepo",
    "EvidenceConflictError",
)


# =============================================================================
# DBConnection — minimal interface, matching timescale_repo.py
# =============================================================================

@runtime_checkable
class DBConnection(Protocol):
    def execute(self, sql: str, params: Sequence[Any]) -> Sequence[tuple]: ...


# =============================================================================
# Conflict surface
# =============================================================================

class EvidenceConflictError(ValueError):
    """Raised when an (agent, epoch) write would overwrite a different
    payload_hash. The ingest path translates this into an audit row in
    the divergence table — the in-memory shim raises ValueError with the
    same message."""


# =============================================================================
# SQL — single source of truth for the queries
# =============================================================================

_INSERT_SQL = """
    INSERT INTO diagnosis_payloads
        (payload_hash, agent_wallet, epoch, payload,
         taxonomy_version, signer_count, on_chain_hash, computed_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (payload_hash) DO NOTHING
"""

# Resolve a (agent, epoch) read to the canonical bytes + metadata.
_FETCH_BY_AGENT_EPOCH_SQL = """
    SELECT payload_hash, agent_wallet, epoch, payload,
           taxonomy_version, signer_count, on_chain_hash, computed_at
      FROM diagnosis_payloads
     WHERE agent_wallet = %s
       AND epoch        = %s
     LIMIT 1
"""

_FETCH_BY_HASH_SQL = """
    SELECT payload_hash, agent_wallet, epoch, payload,
           taxonomy_version, signer_count, on_chain_hash, computed_at
      FROM diagnosis_payloads
     WHERE payload_hash = %s
     LIMIT 1
"""

# Indexer flips the on-chain hash field once the cert v2 is observed.
# The WHERE filter scopes the update to the (agent, epoch) row.
_UPDATE_ON_CHAIN_HASH_SQL = """
    UPDATE diagnosis_payloads
       SET on_chain_hash = %s
     WHERE agent_wallet  = %s
       AND epoch         = %s
"""


# =============================================================================
# Row -> EvidencePayloadRecord
# =============================================================================

def _row_to_record(row: tuple) -> EvidencePayloadRecord:
    """Map a `diagnosis_payloads` row to the wire record.

    Column order MUST match the SELECT list above:
      0 payload_hash  1 agent_wallet  2 epoch  3 payload
      4 taxonomy_version  5 signer_count  6 on_chain_hash  7 computed_at
    """
    return EvidencePayloadRecord(
        payload_hash=bytes(row[0]),
        agent_wallet=str(row[1]),
        epoch=int(row[2]),
        payload_bytes=bytes(row[3]),
        taxonomy_version=int(row[4]),
        signer_count=int(row[5]),
        on_chain_hash=bytes(row[6]) if row[6] is not None else None,
        computed_at=row[7],
    )


# =============================================================================
# TimescaleEvidencePayloadRepo
# =============================================================================

class TimescaleEvidencePayloadRepo:
    """An `EvidencePayloadRepository` backed by the Day-39 table.

    Construct with any `DBConnection`. Satisfies the same Protocol as
    `InMemoryEvidencePayloadRepo` (structural — Python's Protocol is
    duck-typed) so the phylanx-api route handler reads through it
    without conditional imports.
    """

    __slots__ = ("_conn",)

    def __init__(self, connection: DBConnection) -> None:
        self._conn = connection

    # ── EvidencePayloadRepository interface ─────────────────────────────────

    def add(self, record: EvidencePayloadRecord) -> None:
        """Insert the canonical bytes. Idempotent on `payload_hash` —
        re-storing the same hash hits ON CONFLICT DO NOTHING.

        A divergent (agent, epoch) write trips the UNIQUE constraint;
        the driver raises an IntegrityError we re-raise as
        `EvidenceConflictError` so the ingest path can audit it.
        """
        try:
            self._conn.execute(_INSERT_SQL, (
                record.payload_hash,
                record.agent_wallet,
                record.epoch,
                record.payload_bytes,
                record.taxonomy_version,
                record.signer_count,
                record.on_chain_hash,
                record.computed_at,
            ))
        except Exception as exc:  # noqa: BLE001
            # The driver-specific IntegrityError surface varies; we sniff
            # the message rather than import psycopg.errors so this
            # module stays driver-agnostic.
            msg = str(exc)
            if "uq_diagnosis_payloads_agent_epoch" in msg or "duplicate key" in msg:
                raise EvidenceConflictError(
                    f"conflicting evidence payload for "
                    f"{record.agent_wallet} @ epoch {record.epoch}: "
                    f"refusing to overwrite with {record.payload_hash.hex()}"
                ) from exc
            raise

    def evidence_at_epoch(
        self, agent_wallet: str, epoch: int,
    ) -> EvidencePayloadRecord | None:
        rows = self._conn.execute(
            _FETCH_BY_AGENT_EPOCH_SQL, (agent_wallet, epoch),
        )
        rows = list(rows)
        if not rows:
            return None
        return _row_to_record(rows[0])

    def by_hash(self, payload_hash: bytes) -> EvidencePayloadRecord | None:
        if len(payload_hash) != 32:
            raise ValueError("payload_hash must be 32 bytes")
        rows = self._conn.execute(_FETCH_BY_HASH_SQL, (payload_hash,))
        rows = list(rows)
        if not rows:
            return None
        return _row_to_record(rows[0])

    def record_on_chain_hash(
        self, agent_wallet: str, epoch: int, on_chain_hash: bytes,
    ) -> None:
        """Flip the on-chain hash for (agent, epoch). No-op if the row
        does not exist yet — the indexer will reconcile when the payload
        arrives via a separate pending-cert audit table (not modelled
        in this minimal seam)."""
        if len(on_chain_hash) != 32:
            raise ValueError("on_chain_hash must be 32 bytes")
        self._conn.execute(
            _UPDATE_ON_CHAIN_HASH_SQL,
            (on_chain_hash, agent_wallet, epoch),
        )
