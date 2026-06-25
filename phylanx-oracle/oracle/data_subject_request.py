"""
oracle/data_subject_request.py — DP-1: DSAR (data subject access + erasure).

GDPR Art. 15 (right of access) and Art. 17 (right of erasure), DPDP
s.11 (right to information) and s.12 (right to erasure), CCPA
§1798.110 / §1798.105 — every regime requires a mechanical path for
a data subject to (a) discover what is stored about them and (b)
have the erasable subset removed on request. This module implements
that path for the Phylanx oracle.

CONTRACT
--------
Two operations:

  * `query_data_subject(wallet, ...)` — returns a
    `DataSubjectQueryReport` enumerating, per (category, storage)
    pair, the row counts / record counts currently stored for the
    given wallet. The report includes BOTH the erasable slices
    (where erasure will succeed) and the non-erasable slices (the
    on-chain audit trail + the OFAC-1 transparency carve-out) so a
    data subject sees the full picture before deciding whether to
    file an erasure request.

  * `erase_data_subject(wallet, justification, ...)` — purges the
    erasable off-chain stores for the given wallet. Returns a
    `DataSubjectErasureReport` enumerating rows-deleted per slice
    plus the non-erasable carve-outs (refusal_log, on-chain) the
    operation explicitly did NOT touch.

Both operations route every DB write through the same
`DBConnection` Protocol the rest of the oracle uses, with the same
VULN-20 base58 wallet guard for defense-in-depth (every wallet is
validated as base58-shaped before it reaches a `%s` placeholder).

WHAT THIS MODULE DOES NOT DO
----------------------------
It does NOT touch on-chain accounts. The on-chain `HealthCertificate`
/ `AgentRegistration` / `ChallengeRecord` PDAs are immutable by
construction — the privacy notice (`launch/legal/privacy_notice.md`)
discloses this as a documented technical constraint BEFORE
registration. The DSAR report names them so the data subject can
see what remains; the DSAR erase explicitly refuses to issue an
on-chain transaction against them.

It does NOT touch the OFAC-1 refusal log (`Topic.CERT_REFUSED`).
That stream is the operator-side transparency record (DP-1
declares its lawful basis as `LEGAL_OBLIGATION_SANCTIONS`); erasing
a refusal record would defeat the silent-delist transparency
invariant. The DSAR report names it; the DSAR erase carves it out.

It does NOT push events to Kafka or Prometheus. Erasure on those
substrates is by RETENTION (Kafka rotates within 7 days,
Prometheus drops beyond 30 days); the report surfaces this so a
data subject can correlate.

EVERY DSAR EMITS AN AUDIT EVENT
-------------------------------
`serialize_dsar_audit_event(...)` produces a canonical JSON record
the operator appends to the DSAR audit log. The record carries
the wallet, the operation (`query` / `erase`), the justification
(required for erase, optional for query), the per-slice outcome,
and the UTC timestamp. The operator-of-record runbook
(`launch/runbooks/data_subject_request_response.md`) pins where
the log lives and the retention floor.

DETERMINISM
-----------
Pure stdlib + the existing `DBConnection` Protocol. The audit-
event canonical bytes are byte-identical across operators given
the same input (sorted keys, fixed key order, UTC-normalised
timestamp), so two operators independently running the same
DSAR produce verifiable parallel audit logs.
"""

from __future__ import annotations

import enum
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from oracle.data_protection_policy import (
    DataCategory,
    RETENTION_POLICIES,
    RetentionPolicy,
    StorageLocation,
    is_on_chain,
)


# =============================================================================
# VULN-20 wallet guard — mirrored from db/timescale_repo.py.
# Kept local so this module has no cross-file import on the repo.
# =============================================================================

_BASE58_ALPHABET = frozenset(
    "123456789"
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
)
_MIN_WALLET_LEN = 32
_MAX_WALLET_LEN = 44


class WalletValidationError(ValueError):
    """Raised when a wallet handed to the DSAR is not base58-shaped."""


def _ensure_wallet_safe(wallet: str) -> None:
    if not isinstance(wallet, str):
        raise WalletValidationError("wallet must be a string")
    n = len(wallet)
    if n < _MIN_WALLET_LEN or n > _MAX_WALLET_LEN:
        raise WalletValidationError(
            f"wallet length {n} outside {_MIN_WALLET_LEN}..{_MAX_WALLET_LEN}"
        )
    for c in wallet:
        if c not in _BASE58_ALPHABET:
            raise WalletValidationError(
                f"wallet contains non-base58 character {c!r}"
            )


# =============================================================================
# DBConnection — the minimal driver-independent interface
# =============================================================================

@runtime_checkable
class DBConnection(Protocol):
    """The DBConnection Protocol from db.timescale_repo.

    Re-declared here so this module has no hard import on the repo
    module; in production both modules are satisfied by the same
    `Psycopg3Connection` adapter.
    """

    def execute(self, sql: str, params: Sequence[Any]) -> Sequence[tuple]:
        ...


# =============================================================================
# DSAROperation — closed set
# =============================================================================

class DSAROperation(str, enum.Enum):
    QUERY = "query"
    ERASE = "erase"


# =============================================================================
# Per-slice outcome records
# =============================================================================

@dataclass(frozen=True, slots=True)
class SliceOutcome:
    """
    Outcome for one (category, storage_location) slice.

    `record_count`        — for a QUERY, the number of stored rows
                            for this wallet. For an ERASE, the number
                            of rows that WERE present before erasure
                            (i.e. the deletion count).
    `erasure_applied`     — True iff this DSAR erased rows from this
                            slice. False for QUERY ops and for slices
                            carved out of erasure (on-chain +
                            refusal_log).
    `carve_out_reason`    — set iff the slice was not erased because
                            of a policy carve-out. None otherwise.
    """
    category:         DataCategory
    storage_location: StorageLocation
    record_count:     int
    erasure_applied:  bool
    carve_out_reason: str | None

    def __post_init__(self) -> None:
        if self.record_count < 0:
            raise ValueError(
                f"SliceOutcome.record_count must be >= 0, got "
                f"{self.record_count}"
            )
        if self.erasure_applied and self.carve_out_reason is not None:
            raise ValueError(
                "SliceOutcome cannot both apply erasure AND carry a "
                "carve_out_reason — these are mutually exclusive"
            )


@dataclass(frozen=True, slots=True)
class DataSubjectQueryReport:
    """A QUERY op's full report."""
    wallet:      str
    slices:      tuple[SliceOutcome, ...]
    detected_at: datetime

    def __post_init__(self) -> None:
        if self.detected_at.tzinfo is None:
            raise ValueError(
                "DataSubjectQueryReport.detected_at must be tz-aware UTC"
            )

    @property
    def total_records(self) -> int:
        return sum(s.record_count for s in self.slices)


@dataclass(frozen=True, slots=True)
class DataSubjectErasureReport:
    """An ERASE op's full report."""
    wallet:         str
    justification:  str
    slices:         tuple[SliceOutcome, ...]
    detected_at:    datetime

    def __post_init__(self) -> None:
        if not self.justification or not self.justification.strip():
            raise ValueError(
                "DataSubjectErasureReport.justification must be non-empty — "
                "an erasure with no recorded reason is structurally "
                "suspect"
            )
        if self.detected_at.tzinfo is None:
            raise ValueError(
                "DataSubjectErasureReport.detected_at must be tz-aware UTC"
            )

    @property
    def total_erased(self) -> int:
        return sum(
            s.record_count for s in self.slices if s.erasure_applied
        )


# =============================================================================
# Slice descriptors — which (category, storage) pairs the DSAR
# physically interacts with, plus the SQL templates.
# =============================================================================
#
# A category may be present in RETENTION_POLICIES but require no
# physical action (e.g. Kafka rotates by retention, not by delete).
# These descriptors enumerate ONLY the slices the DSAR actually
# touches at query/erase time. Non-touched slices are still reported
# (with a carve_out_reason) so the data subject sees them.

# (category, storage) -> (count_sql, delete_sql)
_SQL_TEMPLATES: dict[
    tuple[DataCategory, StorageLocation], tuple[str, str]
] = {
    (DataCategory.TRANSACTION_HISTORY, StorageLocation.OFF_CHAIN_TIMESCALE): (
        "SELECT COUNT(*) FROM agent_transactions WHERE agent_wallet = %s",
        "DELETE FROM agent_transactions WHERE agent_wallet = %s",
    ),
    (DataCategory.SCORE_HISTORY, StorageLocation.OFF_CHAIN_TIMESCALE): (
        "SELECT COUNT(*) FROM agent_scores WHERE agent_wallet = %s",
        "DELETE FROM agent_scores WHERE agent_wallet = %s",
    ),
}


# Carve-out reasons surfaced in the report.
CARVE_OUT_ON_CHAIN = (
    "on-chain audit trail (immutable by construction; disclosed in "
    "privacy notice)"
)
CARVE_OUT_REFUSAL_LOG = (
    "OFAC-1 silent-delist transparency record (legal-obligation "
    "basis; erasing would defeat the transparency invariant)"
)
CARVE_OUT_KAFKA_RETENTION = (
    "Kafka topic — erasure by retention rotation only (not "
    "selectively deletable by key)"
)
CARVE_OUT_PROMETHEUS_RETENTION = (
    "Prometheus TSDB — erasure by retention rotation only; today "
    "no per-agent label cardinality is emitted"
)


def _carve_out_reason_for(policy: RetentionPolicy) -> str | None:
    """Return the carve-out reason for a non-touched slice, or None if
    the slice has actionable SQL (and thus should not be carved out)."""
    if (policy.category, policy.storage_location) in _SQL_TEMPLATES:
        return None
    if is_on_chain(policy.storage_location):
        return CARVE_OUT_ON_CHAIN
    if policy.category is DataCategory.REFUSAL_LOG:
        return CARVE_OUT_REFUSAL_LOG
    if policy.storage_location is StorageLocation.OFF_CHAIN_KAFKA:
        return CARVE_OUT_KAFKA_RETENTION
    if policy.storage_location is StorageLocation.OFF_CHAIN_PROMETHEUS:
        return CARVE_OUT_PROMETHEUS_RETENTION
    return None


# =============================================================================
# query_data_subject
# =============================================================================

def query_data_subject(
    wallet: str,
    *,
    db:          DBConnection,
    detected_at: datetime,
) -> DataSubjectQueryReport:
    """
    Discover what is stored about `wallet` and return a report.

    The report enumerates every policy slice in DP-1, with row counts
    where the slice is physically queryable and a carve-out reason
    otherwise. The data subject reading the report sees the FULL
    picture (erasable + non-erasable) so they can decide whether to
    file an erasure request.
    """
    _ensure_wallet_safe(wallet)
    if detected_at.tzinfo is None:
        raise ValueError("detected_at must be tz-aware UTC")

    slices: list[SliceOutcome] = []
    for key, policy in RETENTION_POLICIES.items():
        cat, loc = key
        if (cat, loc) in _SQL_TEMPLATES:
            count_sql, _ = _SQL_TEMPLATES[(cat, loc)]
            rows = db.execute(count_sql, (wallet,))
            count = int(rows[0][0]) if rows else 0
            slices.append(SliceOutcome(
                category=cat,
                storage_location=loc,
                record_count=count,
                erasure_applied=False,
                carve_out_reason=None,
            ))
        else:
            slices.append(SliceOutcome(
                category=cat,
                storage_location=loc,
                record_count=0,
                erasure_applied=False,
                carve_out_reason=_carve_out_reason_for(policy),
            ))

    return DataSubjectQueryReport(
        wallet=wallet,
        slices=tuple(slices),
        detected_at=detected_at.astimezone(timezone.utc),
    )


# =============================================================================
# erase_data_subject
# =============================================================================

def erase_data_subject(
    wallet: str,
    justification: str,
    *,
    db:          DBConnection,
    detected_at: datetime,
) -> DataSubjectErasureReport:
    """
    Purge `wallet`'s erasable off-chain stores. Returns a report.

    Empty `justification` is rejected — an erasure without a recorded
    reason is structurally suspect and would defeat the audit-log
    rationale.

    On-chain slices and the OFAC-1 refusal log are explicitly NOT
    touched; the report names them with the carve-out reason so the
    data subject can see what remains.
    """
    _ensure_wallet_safe(wallet)
    if not justification or not justification.strip():
        raise ValueError(
            "erase_data_subject: justification must be non-empty"
        )
    if detected_at.tzinfo is None:
        raise ValueError("detected_at must be tz-aware UTC")

    slices: list[SliceOutcome] = []
    for key, policy in RETENTION_POLICIES.items():
        cat, loc = key
        if (cat, loc) in _SQL_TEMPLATES:
            count_sql, delete_sql = _SQL_TEMPLATES[(cat, loc)]
            rows = db.execute(count_sql, (wallet,))
            count_before = int(rows[0][0]) if rows else 0
            db.execute(delete_sql, (wallet,))
            slices.append(SliceOutcome(
                category=cat,
                storage_location=loc,
                record_count=count_before,
                erasure_applied=True,
                carve_out_reason=None,
            ))
        else:
            slices.append(SliceOutcome(
                category=cat,
                storage_location=loc,
                record_count=0,
                erasure_applied=False,
                carve_out_reason=_carve_out_reason_for(policy),
            ))

    return DataSubjectErasureReport(
        wallet=wallet,
        justification=justification,
        slices=tuple(slices),
        detected_at=detected_at.astimezone(timezone.utc),
    )


# =============================================================================
# Audit-event canonical bytes
# =============================================================================

DSAR_AUDIT_WIRE_VERSION = 1


def serialize_dsar_audit_event(
    *,
    operation:     DSAROperation,
    wallet:        str,
    justification: str | None,
    slices:        Sequence[SliceOutcome],
    detected_at:   datetime,
) -> bytes:
    """
    Canonical JSON bytes for one DSAR audit-log entry.

    Sorted keys, fixed key order, UTC-normalised timestamp — two
    operators producing the same event get byte-identical output.
    The privacy-notice runbook pins the audit log file path and
    retention floor; this function is the serializer it uses.
    """
    if detected_at.tzinfo is None:
        raise ValueError("detected_at must be tz-aware UTC")
    payload = {
        "wire_version":  DSAR_AUDIT_WIRE_VERSION,
        "operation":     operation.value,
        "wallet":        wallet,
        "justification": justification or "",
        "detected_at":   detected_at.astimezone(timezone.utc)
                                    .isoformat(timespec="seconds")
                                    .replace("+00:00", "Z"),
        "slices": [
            {
                "category":         s.category.value,
                "storage_location": s.storage_location.value,
                "record_count":     s.record_count,
                "erasure_applied":  s.erasure_applied,
                "carve_out_reason": s.carve_out_reason or "",
            }
            for s in slices
        ],
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


# =============================================================================
# CLI
# =============================================================================
#
# Operator invocation:
#
#   python -m oracle.data_subject_request query <wallet>
#   python -m oracle.data_subject_request erase <wallet> \
#       --justification "GDPR Art.17 request, ticket #DSAR-123"
#
# The CLI takes the DB connection string from the env var
# `PHYLANX_DB_DSN`. It writes the audit event to stdout (operator
# captures into the DSAR audit log).

def _build_argparser():
    import argparse
    parser = argparse.ArgumentParser(
        prog="dsar",
        description="Phylanx DP-1 DSAR (data subject access + erasure) CLI",
    )
    sub = parser.add_subparsers(dest="op", required=True)

    p_query = sub.add_parser(
        "query", help="enumerate stored records for a wallet",
    )
    p_query.add_argument("wallet", help="agent wallet (base58 pubkey)")

    p_erase = sub.add_parser(
        "erase", help="purge erasable off-chain stores for a wallet",
    )
    p_erase.add_argument("wallet", help="agent wallet (base58 pubkey)")
    p_erase.add_argument(
        "--justification", required=True,
        help="required non-empty reason for the erasure (ticket ref)",
    )

    return parser


def _connect_from_env():
    """Build a `Psycopg3Connection` from `PHYLANX_DB_DSN`. Deferred
    import so `psycopg` is not a hard dep of this module."""
    import os
    dsn = os.environ.get("PHYLANX_DB_DSN")
    if not dsn:
        raise SystemExit(
            "error: PHYLANX_DB_DSN env var must be set for DSAR CLI"
        )
    import psycopg  # type: ignore[import-untyped]
    from db.timescale_repo import Psycopg3Connection
    return Psycopg3Connection(psycopg.connect(dsn))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)

    db = _connect_from_env()
    now = datetime.now(timezone.utc)
    op = DSAROperation(args.op)

    if op is DSAROperation.QUERY:
        report = query_data_subject(args.wallet, db=db, detected_at=now)
        justification = None
        slices = report.slices
    else:
        report = erase_data_subject(
            args.wallet, args.justification,
            db=db, detected_at=now,
        )
        justification = args.justification
        slices = report.slices

    event = serialize_dsar_audit_event(
        operation=op,
        wallet=args.wallet,
        justification=justification,
        slices=slices,
        detected_at=now,
    )
    import sys
    sys.stdout.buffer.write(event + b"\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())


# =============================================================================
# Public surface
# =============================================================================

__all__ = [
    # Errors
    "WalletValidationError",
    # Op enum
    "DSAROperation",
    # Outcome records
    "SliceOutcome",
    "DataSubjectQueryReport",
    "DataSubjectErasureReport",
    # Core operations
    "query_data_subject",
    "erase_data_subject",
    # Audit event
    "DSAR_AUDIT_WIRE_VERSION",
    "serialize_dsar_audit_event",
    # Carve-out reasons (used in privacy notice rendering)
    "CARVE_OUT_ON_CHAIN",
    "CARVE_OUT_REFUSAL_LOG",
    "CARVE_OUT_KAFKA_RETENTION",
    "CARVE_OUT_PROMETHEUS_RETENTION",
]
