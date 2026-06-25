"""
oracle/cert_reissue_cadence.py — FRP-3: cert-reissue cadence floor
for red-team Path 3 sub-leaf 3c ("Target DeFi protocol that doesn't
check cert freshness").

THE ATTACK PATH (Freeze-Cert-at-High-Score Path 3, sub-leaf 3c)
---------------------------------------------------------------
Sub-leaf 3c is the asymmetric defence problem: a DeFi consumer that
DOES NOT call `is_fresh_default(now_unix)` on the on-chain cert
continues to lend against the last cert it saw, even if the cluster
has stalled (Path 3a / 3b). The existing defences:

  * On-chain TA-6: `MAX_AGE_SECONDS = 48 * 60 * 60` in
    `programs/certificate-issuer/src/state/health_certificate.rs`.
    Caps cert freshness — but only fires if the consumer calls
    `is_fresh_default`.
  * SOL-3 (`operation_freshness.py`): per-operation freshness
    floors (LOAN_ISSUE 4h, LIQUIDATION_CHECK 12h, STATUS_READ 48h).
    Enforced at the SDK layer; bypassable by a consumer that
    integrates directly with the on-chain account.

What neither defence handles: a CLUSTER-side guarantee that the
cert ON CHAIN cannot be older than a small bounded window. If the
cluster's cert-reissue cadence drifts (cluster is overloaded,
partially-stalled, or under attack), the on-chain cert ages without
the cluster noticing — and a blind consumer keeps lending against
it until TA-6's 48h ceiling expires.

FRP-3 closes the cluster-side reissue-cadence substrate:

  * `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600` — 4 hours. The
    cluster commits to reissuing every active agent's cert at most
    4h apart. This is the LOAN_ISSUE-tier floor from SOL-3,
    promoted from "consumer-side check" to "cluster-side
    self-discipline".
  * If a cert's `last_reissue_unix` is more than
    MAX_CERT_REISSUE_INTERVAL_SECONDS old, the cluster REFUSES to
    declare it valid for high-tier consumer operations. The
    cluster either reissues immediately or marks the cert
    DEGRADED. Either way, the cluster does NOT continue minting
    high-tier certs against a stalled reissue pipeline.
  * Cross-checked against TA-6's on-chain 48h ceiling — the
    cluster's 4h floor leaves a 12× safety margin. A consumer that
    DOES call `is_fresh_default` will see freshness violations
    long before TA-6's ceiling fires; a consumer that does NOT
    will at least eventually see the on-chain cert age past TA-6.

CALIBRATION
-----------
- `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600`. 4 hours mirrors
  SOL-3's LOAN_ISSUE freshness floor — the cluster commits to
  keeping all certs as fresh as the most demanding consumer
  operation requires. Lower (1h) burdens the cluster with
  unnecessary work; higher (12h, matching LIQUIDATION_CHECK)
  leaves consumers exposed to a stale baseline.
- `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60`. Standard 60s
  clock-skew tolerance.
- TA-6 cross-check: 48h on-chain ceiling = 12× the 4h cluster
  floor. The cluster MUST reissue 12 times before the on-chain
  ceiling fires — gives the cluster 11 retry attempts before any
  consumer sees on-chain staleness.

INTERACTION WITH TA-6 / SOL-3 / FRP-1 / FRP-2
---------------------------------------------
- TA-6 (`health_certificate.rs`) is the on-chain ceiling. FRP-3 is
  the cluster-side promise that the cluster will never let the
  on-chain cert get within 12× of that ceiling without an
  explicit refusal.
- SOL-3 (`operation_freshness.py`) is the CONSUMER-side per-
  operation floor. FRP-3 is the CLUSTER-side cadence floor that
  makes SOL-3's per-operation floors practically achievable —
  if the cluster reissues every <4h, the LOAN_ISSUE 4h floor will
  never fire under healthy operation.
- FRP-1 (`cluster_participation_floor.py`) refuses NEW cert
  issuance when round-level participation is sustained-barely-
  quorate. FRP-3 refuses HIGH-TIER cert declaration when the
  cluster's cert-reissue cadence has slipped. The two are
  layered: FRP-1 catches the issuance moment; FRP-3 catches the
  cadence pattern across many issuance moments.
- FRP-2 (`epoch_advance_liveness.py`) refuses ALL new cert
  issuance when the epoch hasn't advanced. FRP-3 catches the
  per-agent residual: even with epoch advance, individual agent
  certs must be refreshed at least every 4h.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(current_unix,
last_reissue_unix)`. No clock, no network, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Maximum tolerated seconds between consecutive cert reissues for
#: a given agent. 4h = mirror of SOL-3's LOAN_ISSUE floor.
MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600

#: Single-minute clock-skew tolerance for the reissue timestamp.
CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60

#: The on-chain TA-6 ceiling we cross-check against (mirrored from
#: `programs/certificate-issuer/src/state/health_certificate.rs`).
#: Pinned here so the audit gate can verify the two have not drifted.
TA6_ONCHAIN_MAX_AGE_SECONDS = 48 * 3600

#: Status labels.
CERT_REISSUE_OK = "OK"
CERT_REISSUE_REFUSED = "REFUSED"

#: Reason codes.
REASON_CERT_REISSUE_OVERDUE = "CERT_REISSUE_OVERDUE"
REASON_CERT_REISSUE_TIMESTAMP_IN_FUTURE = (
    "CERT_REISSUE_TIMESTAMP_IN_FUTURE"
)
REASON_CERT_REISSUE_TIMESTAMP_INVALID = (
    "CERT_REISSUE_TIMESTAMP_INVALID"
)
REASON_CERT_REISSUE_AGENT_WALLET_MISSING = (
    "CERT_REISSUE_AGENT_WALLET_MISSING"
)


# =============================================================================
# Errors
# =============================================================================

class CertReissueCadenceError(RuntimeError):
    """
    Raised by `enforce_cert_reissue_cadence` when the cluster's
    per-agent cert reissue cadence has slipped past the floor.
    """

    def __init__(
        self, message: str, report: "CertReissueCadenceReport"
    ):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class CertReissueSample:
    """
    One per-agent cert reissue observation.

    `agent_wallet`         the agent whose cert is the subject.
    `last_reissue_unix`    unix-seconds of the most recent cluster-
                           signed reissue of this agent's cert.
    `current_unix`         unix-seconds NOW (wall clock at the
                           coordinator).
    """
    agent_wallet:      str
    last_reissue_unix: int
    current_unix:      int


@dataclass(frozen=True, slots=True)
class CertReissueCadenceReport:
    """
    Verdict of one FRP-3 check.

    `status`               CERT_REISSUE_OK / CERT_REISSUE_REFUSED.
    `agent_wallet`         echoed.
    `seconds_since_last`   current_unix - last_reissue_unix.
    `reissue_floor`        MAX_CERT_REISSUE_INTERVAL_SECONDS.
    `ta6_onchain_ceiling`  TA6_ONCHAIN_MAX_AGE_SECONDS.
    `safety_margin_factor` ta6 / reissue (12× by construction).
    `current_unix`         echoed.
    `last_reissue_unix`    echoed.
    `reasons`              reason codes; empty when OK.
    """
    status:                str
    agent_wallet:          str
    seconds_since_last:    int
    reissue_floor:         int
    ta6_onchain_ceiling:   int
    safety_margin_factor:  int
    current_unix:          int
    last_reissue_unix:     int
    reasons:               tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == CERT_REISSUE_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_cert_reissue_cadence(
    sample: CertReissueSample,
) -> CertReissueCadenceReport:
    """
    Decide whether a given agent's cert reissue cadence respects
    the floor.

    Rules:
      * `agent_wallet` empty -> REFUSED,
        CERT_REISSUE_AGENT_WALLET_MISSING.
      * `last_reissue_unix < 1` -> REFUSED,
        CERT_REISSUE_TIMESTAMP_INVALID (agent has never had a cert
        issued — the cluster should never declare such a cert
        valid for any operation).
      * `last_reissue_unix > current_unix +
        CERT_REISSUE_FUTURE_TOLERANCE_SECONDS` -> REFUSED,
        CERT_REISSUE_TIMESTAMP_IN_FUTURE.
      * `current_unix - last_reissue_unix >
        MAX_CERT_REISSUE_INTERVAL_SECONDS` -> REFUSED,
        CERT_REISSUE_OVERDUE.

    Pure: no logging, no I/O.
    """
    reasons: list[str] = []

    last = sample.last_reissue_unix
    now = sample.current_unix

    if not sample.agent_wallet:
        reasons.append(REASON_CERT_REISSUE_AGENT_WALLET_MISSING)
    if last < 1:
        reasons.append(REASON_CERT_REISSUE_TIMESTAMP_INVALID)
    if last > now + CERT_REISSUE_FUTURE_TOLERANCE_SECONDS:
        reasons.append(REASON_CERT_REISSUE_TIMESTAMP_IN_FUTURE)

    seconds_since = max(now - last, 0)
    if seconds_since > MAX_CERT_REISSUE_INTERVAL_SECONDS:
        reasons.append(REASON_CERT_REISSUE_OVERDUE)

    status = (
        CERT_REISSUE_OK if not reasons else CERT_REISSUE_REFUSED
    )

    return CertReissueCadenceReport(
        status=status,
        agent_wallet=sample.agent_wallet,
        seconds_since_last=seconds_since,
        reissue_floor=MAX_CERT_REISSUE_INTERVAL_SECONDS,
        ta6_onchain_ceiling=TA6_ONCHAIN_MAX_AGE_SECONDS,
        safety_margin_factor=(
            TA6_ONCHAIN_MAX_AGE_SECONDS
            // MAX_CERT_REISSUE_INTERVAL_SECONDS
        ),
        current_unix=now,
        last_reissue_unix=last,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_cert_reissue_cadence(
    sample: CertReissueSample,
) -> CertReissueCadenceReport:
    """
    Run `verify_cert_reissue_cadence` and raise on any violation.
    Returns the report when status == CERT_REISSUE_OK.
    """
    report = verify_cert_reissue_cadence(sample)
    if report.is_allowed:
        return report
    raise CertReissueCadenceError(
        f"FRP-3: cert reissue cadence refused — "
        f"agent={report.agent_wallet!r}, "
        f"seconds_since_last_reissue={report.seconds_since_last} "
        f"(floor {report.reissue_floor}, TA-6 on-chain ceiling "
        f"{report.ta6_onchain_ceiling} = "
        f"{report.safety_margin_factor}× the floor), "
        f"reasons={list(report.reasons)!r}. "
        f"The cluster MUST reissue each agent's cert every "
        f"{MAX_CERT_REISSUE_INTERVAL_SECONDS}s or refuse to declare "
        f"its cert valid for high-tier consumer operations — this "
        f"closes the residual where a freshness-blind DeFi consumer "
        f"continues to lend against a frozen cert.",
        report,
    )


__all__ = [
    "CERT_REISSUE_FUTURE_TOLERANCE_SECONDS",
    "CERT_REISSUE_OK",
    "CERT_REISSUE_REFUSED",
    "CertReissueCadenceError",
    "CertReissueCadenceReport",
    "CertReissueSample",
    "MAX_CERT_REISSUE_INTERVAL_SECONDS",
    "REASON_CERT_REISSUE_AGENT_WALLET_MISSING",
    "REASON_CERT_REISSUE_OVERDUE",
    "REASON_CERT_REISSUE_TIMESTAMP_INVALID",
    "REASON_CERT_REISSUE_TIMESTAMP_IN_FUTURE",
    "TA6_ONCHAIN_MAX_AGE_SECONDS",
    "enforce_cert_reissue_cadence",
    "verify_cert_reissue_cadence",
]
