"""
oracle/operation_freshness.py — SOL-3: per-operation freshness floor
for Scenario C step 5 ("mass defaults with no warning").

THE CATASTROPHIC FAILURE SCENARIO (audit Scenario C, step 5)
------------------------------------------------------------
    "Mass defaults with no warning."

SOL-1 catches CLUSTER-WIDE silence. SOL-2 degrades the effective tier
of an individual cert as it ages. What neither closes is the
ASYMMETRIC consumer behaviour: opening a new collateralised loan
against a 6-hour-old cert is fundamentally riskier than reading a
status display from the same cert, but the consumer pre-SOL-3 had no
canonical way to distinguish the two. TA-6's 48h ceiling is one
number for both.

SOL-3 reifies a PER-OPERATION freshness contract: each operation type
declares its own max-cert-age, and a consumer running
`enforce_operation_freshness` for `LOAN_ISSUE` against a 6-hour-old
cert is REFUSED even though the same cert would pass `STATUS_READ`.

    LOAN_ISSUE / NEW_POSITION_OPEN          4h max
    LOAN_INCREASE / POSITION_ADJUST         8h max
    LIQUIDATION_CHECK                       12h max
    STATUS_READ / DISPLAY                   48h max (matches TA-6)

The mapping is calibrated for risk-asymmetry: high-stakes write
operations require fresher data than read-only ones. A consumer that
ONLY ever calls `STATUS_READ` keeps TA-6's existing behaviour;
consumers gating real money (loan issuance, collateral changes) now
have to refresh the cert more often or refuse the operation.

CALIBRATION
-----------
- `LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600` — 4h. Two full canonical
  cluster cadences. The cluster has had ample opportunity to refresh
  for a high-stakes new loan; if it hasn't, refuse.
- `LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 3600` — 8h. Adjusting an
  existing collateralised position is risk-mid: more permissive than
  a brand-new loan but less than a passive read.
- `LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 3600` — 12h. A
  liquidation IN PROGRESS already implies the operator has decided
  the position is at risk; a 12h-old cert is acceptable evidence.
- `STATUS_READ_MAX_AGE_SECONDS = 48 * 3600` — 48h. Matches TA-6's
  `MAX_AGE_SECONDS`. The most-permissive operation in the table.

INTERACTION WITH SOL-1 / SOL-2 / TA-6
-------------------------------------
- SOL-3 checks AGE only. SOL-2 has already computed the EFFECTIVE
  tier; SOL-3 sits orthogonally on the seconds axis.
- SOL-3's floors are STRICTLY LOOSER than SOL-2's
  `REFUSE_AFTER_SECONDS = 24h` for every operation, so a cert refused
  by SOL-2 is also refused by SOL-3 transitively. The two are not
  redundant: SOL-2 governs WHICH TIER the consumer treats the cert
  as; SOL-3 governs WHETHER THE OPERATION may proceed at all.
- TA-6 (48h) is the OUTER ring. SOL-3's `STATUS_READ` floor matches
  TA-6 exactly so SOL-3 never refuses a cert that TA-6 would accept
  for a passive read.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(issued_at_unix, current_unix)`
+ operation enum lookup. No clock, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


# =============================================================================
# Constants
# =============================================================================

#: Maximum cert age in seconds for high-stakes loan issuance.
LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600

#: Maximum cert age in seconds for adjusting an existing position.
LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 3600

#: Maximum cert age in seconds for liquidation checks.
LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 3600

#: Maximum cert age in seconds for passive status reads. Matches
#: TA-6's `MAX_AGE_SECONDS` so SOL-3 never refuses a cert TA-6 accepts
#: for the lowest-stakes operation.
STATUS_READ_MAX_AGE_SECONDS = 48 * 3600

#: Future-skew tolerance (60s of clock skew on `issued_at_unix`).
OPERATION_FUTURE_TOLERANCE_SECONDS = 60

#: Reason codes — stable strings for the consumer logs.
REASON_OPERATION_CERT_TOO_OLD = "OPERATION_CERT_TOO_OLD"
REASON_OPERATION_TIME_TRAVEL = "OPERATION_CERT_IN_FUTURE"


class Operation(str, Enum):
    """
    Enumerated operations with risk-asymmetric freshness floors.

    The string value is the stable wire label the consumer logs and
    the audit gate cross-references.
    """
    LOAN_ISSUE = "LOAN_ISSUE"
    LOAN_INCREASE = "LOAN_INCREASE"
    LIQUIDATION_CHECK = "LIQUIDATION_CHECK"
    STATUS_READ = "STATUS_READ"


#: Operation -> max cert age mapping. Frozen at module load so the
#: audit gate can grep both the operation name and the constant.
OPERATION_MAX_AGE_SECONDS: dict[Operation, int] = {
    Operation.LOAN_ISSUE:        LOAN_ISSUE_MAX_AGE_SECONDS,
    Operation.LOAN_INCREASE:     LOAN_INCREASE_MAX_AGE_SECONDS,
    Operation.LIQUIDATION_CHECK: LIQUIDATION_CHECK_MAX_AGE_SECONDS,
    Operation.STATUS_READ:       STATUS_READ_MAX_AGE_SECONDS,
}


# =============================================================================
# Errors
# =============================================================================

class StaleForOperationError(RuntimeError):
    """
    Raised by `enforce_operation_freshness` when the cert is too old
    for the requested operation.

    `.report` carries the verdict (`cert_age_seconds`,
    `max_age_seconds`, `operation`) so the consumer can present a
    structured message and the operator can correlate against
    cluster-liveness telemetry.
    """

    def __init__(self, message: str, report: "OperationFreshnessReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class OperationFreshnessReport:
    """
    Verdict of one SOL-3 check.

    `operation`          the operation the consumer requested.
    `cert_age_seconds`   `current_unix - issued_at_unix` (clamped to
                         0 on time-travel).
    `max_age_seconds`    the operation's freshness floor.
    `is_allowed`         True iff age <= max_age AND no time-travel.
    `reasons`            reason codes when refused.
    """
    operation:         Operation
    cert_age_seconds:  int
    max_age_seconds:   int
    is_allowed:        bool
    reasons:           tuple[str, ...]


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_operation_freshness(
    *,
    operation:      Operation,
    issued_at_unix: int,
    current_unix:   int,
) -> OperationFreshnessReport:
    """
    Decide whether an operation may proceed given the cert's age.

    The rule:
      * `issued_at_unix > current_unix + OPERATION_FUTURE_TOLERANCE_SECONDS`
        -> refused, reason TIME_TRAVEL.
      * `cert_age_seconds > OPERATION_MAX_AGE_SECONDS[operation]`
        -> refused, reason CERT_TOO_OLD.
      * Else -> allowed.

    Pure: no logging, no I/O.
    """
    reasons: list[str] = []
    max_age = OPERATION_MAX_AGE_SECONDS[operation]

    delta = current_unix - issued_at_unix
    if delta < -OPERATION_FUTURE_TOLERANCE_SECONDS:
        reasons.append(REASON_OPERATION_TIME_TRAVEL)
        return OperationFreshnessReport(
            operation=operation,
            cert_age_seconds=0,
            max_age_seconds=max_age,
            is_allowed=False,
            reasons=tuple(reasons),
        )

    age = max(delta, 0)
    if age > max_age:
        reasons.append(REASON_OPERATION_CERT_TOO_OLD)

    return OperationFreshnessReport(
        operation=operation,
        cert_age_seconds=age,
        max_age_seconds=max_age,
        is_allowed=not reasons,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_operation_freshness(
    *,
    operation:      Operation,
    issued_at_unix: int,
    current_unix:   int,
) -> OperationFreshnessReport:
    """
    Run `verify_operation_freshness` and raise on refusal.

    Returns the report on success; raises `StaleForOperationError`
    (with the report attached) when the operation MUST NOT proceed.
    """
    report = verify_operation_freshness(
        operation=operation,
        issued_at_unix=issued_at_unix,
        current_unix=current_unix,
    )
    if report.is_allowed:
        return report
    raise StaleForOperationError(
        f"SOL-3: operation {operation.value!r} refused — "
        f"cert_age={report.cert_age_seconds}s, "
        f"max_age={report.max_age_seconds}s, "
        f"reasons={list(report.reasons)!r}. The consumer MUST refuse "
        f"this operation or wait for a fresher cert — Scenario C step "
        f"5 substrate (mass defaults with no warning).",
        report,
    )


__all__ = [
    "LIQUIDATION_CHECK_MAX_AGE_SECONDS",
    "LOAN_INCREASE_MAX_AGE_SECONDS",
    "LOAN_ISSUE_MAX_AGE_SECONDS",
    "OPERATION_FUTURE_TOLERANCE_SECONDS",
    "OPERATION_MAX_AGE_SECONDS",
    "REASON_OPERATION_CERT_TOO_OLD",
    "REASON_OPERATION_TIME_TRAVEL",
    "STATUS_READ_MAX_AGE_SECONDS",
    "Operation",
    "OperationFreshnessReport",
    "StaleForOperationError",
    "enforce_operation_freshness",
    "verify_operation_freshness",
]
