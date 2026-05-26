"""
oracle/cluster_liveness.py — SOL-1: cluster-liveness signal for
Scenario C step 1+2 ("all 5 oracle nodes are disrupted simultaneously;
no new certs are issued").

THE CATASTROPHIC FAILURE SCENARIO (audit Scenario C, steps 1-3)
---------------------------------------------------------------
    "All 5 oracle nodes are disrupted simultaneously (coordinated DDoS
    or infrastructure failure). No new certs are issued. DeFi protocols
    continue to use last-issued certs (stale data)."

TA-6 already ships a 48-hour cert-freshness contract — every consumer
that calls `SafeCertReader.getSafeScore()` refuses certs older than
`MAX_AGE_SECONDS = 172800`. What TA-6 does NOT close is the FIRST 48
HOURS of an outage: during that window every cert is still "fresh" by
TA-6's clock even though no new cert has been signed for hours, and a
DeFi protocol acting on the cert has no signal that the cluster is
silent.

SOL-1 reifies a SEPARATE liveness clock that runs from the
CLUSTER-WIDE-LAST-SIGNATURE, not from the per-agent cert. The signal
goes "stale" hours before TA-6's hard ceiling, so a consumer that
reads both signals can:

    * Treat the cluster as alive while certs are flowing.
    * Treat the cluster as DEGRADED when the last cluster-wide
      signature is older than `WARN_QUIET_SECONDS`.
    * Treat the cluster as SILENT when the last signature is older
      than `SILENT_QUIET_SECONDS` — at which point new high-stakes
      operations (loan issuance, large position opens) should be
      refused even though individual per-agent certs are still
      individually fresh.

CALIBRATION
-----------
- `WARN_QUIET_SECONDS = 2 * 3600` (2 hours) — one full canonical
  cluster cadence has elapsed without a new cert. The cluster MIGHT
  just have skipped one epoch; consumers should treat the signal as
  degraded but not refuse routine reads.
- `SILENT_QUIET_SECONDS = 4 * 3600` (4 hours) — two full epochs have
  passed in silence. This is the operational threshold below which a
  consumer-side circuit breaker (SOL-3) refuses new loans. The
  cluster has either failed or is being actively disrupted.
- `LIVENESS_FUTURE_TOLERANCE_SECONDS = 60` — a single epoch's worth of
  clock skew tolerance for `last_cert_unix > current_unix`.

INTERACTION WITH SOL-2 / SOL-3 AND TA-6
---------------------------------------
- SOL-1 is the CLUSTER-WIDE clock. It cares about THE LATEST cert
  anywhere in the system, not about any specific agent.
- SOL-2 is the PER-AGENT clock. It degrades GREEN -> YELLOW -> RED
  on a single agent's cert as that agent's cert ages, even while the
  cluster as a whole is still alive.
- SOL-3 is the OPERATION clock. It enforces a per-operation maximum
  cert age (loan_issue = 4h, status_read = 48h) so a high-stakes new
  position cannot be opened against a cert that is "fresh" by TA-6
  but already "silent" by SOL-1.
- TA-6's 48h `MAX_AGE_SECONDS` is the BACKSTOP. SOL-1 fires hours
  earlier and gives the consumer a structured, operation-aware
  decision point.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(latest_cert_unix, current_unix)`
+ a count of `nodes_recently_active`. No clock (timestamps are
arguments), no network, no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Seconds of cluster-wide silence after which the signal turns DEGRADED.
#: One full canonical cluster cadence (2h at 2h epoch cadence).
WARN_QUIET_SECONDS = 2 * 3600

#: Seconds of cluster-wide silence after which the signal turns SILENT.
#: Two full cadences — the cluster has either failed or is being
#: actively disrupted. Consumer-side circuit breaker (SOL-3) refuses
#: new loans past this threshold.
SILENT_QUIET_SECONDS = 4 * 3600

#: Seconds of future-skew tolerance for `last_cert_unix > current_unix`.
#: A single epoch's clock skew is tolerated; anything beyond that is a
#: structural failure (REASON_LIVENESS_TIME_TRAVEL).
LIVENESS_FUTURE_TOLERANCE_SECONDS = 60

#: Minimum number of distinct nodes that must have produced a heartbeat
#: in the most recent epoch for the cluster to be considered alive
#: even if a cert was emitted. Below this floor the cluster is
#: structurally below-quorum and the signal is forced to SILENT.
MIN_RECENT_NODES_FOR_ALIVE = 3

#: Liveness band labels. Stable strings the consumer SDK + boot logs
#: grep for.
LIVENESS_ALIVE = "ALIVE"
LIVENESS_DEGRADED = "DEGRADED"
LIVENESS_SILENT = "SILENT"

#: Reason codes — stable strings the consumer logs and the audit gate
#: cross-reference.
REASON_LIVENESS_QUIET_WARN = "CLUSTER_QUIET_WARN"
REASON_LIVENESS_QUIET_SILENT = "CLUSTER_QUIET_SILENT"
REASON_LIVENESS_TIME_TRAVEL = "CLUSTER_LAST_CERT_IN_FUTURE"
REASON_LIVENESS_BELOW_QUORUM = "CLUSTER_NODES_BELOW_QUORUM"
REASON_LIVENESS_NO_CERTS_EVER = "CLUSTER_NO_CERTS_EVER"


# =============================================================================
# Errors
# =============================================================================

class ClusterSilentError(RuntimeError):
    """
    Raised by `enforce_cluster_alive` when the cluster has gone silent.

    `.report` carries the verdict (`seconds_since_last_cert`, band,
    reasons) so the consumer can present a structured message to the
    end user and the operator can correlate against
    `cluster_health.NodeHeartbeat` rows.
    """

    def __init__(self, message: str, report: "ClusterLivenessReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class ClusterLivenessContext:
    """
    One snapshot of cluster-wide signing activity.

    `last_cert_unix`        Unix seconds at which the cluster emitted
                            its most recent threshold-signed cert
                            (the MAX across all agents). `None` when
                            the cluster has never signed.
    `last_cert_epoch`       Helixor epoch of the most recent cert.
    `nodes_recently_active` Count of distinct cluster nodes that
                            produced an off-chain heartbeat in the
                            current OR previous epoch. Drawn from the
                            `oracle_node_heartbeat` table consumed by
                            `helixor-api/api/cluster_health.py`.
    """
    last_cert_unix:        int | None
    last_cert_epoch:       int | None
    nodes_recently_active: int


@dataclass(frozen=True, slots=True)
class ClusterLivenessReport:
    """
    Verdict of one SOL-1 check.

    `band`                     LIVENESS_ALIVE / DEGRADED / SILENT.
    `is_alive`                 True iff band == ALIVE.
    `seconds_since_last_cert`  current_unix - last_cert_unix (clamped
                               to 0 on time-travel; -1 if the cluster
                               has never signed).
    `last_cert_epoch`          echoed from the input.
    `nodes_recently_active`    echoed from the input.
    `warn_seconds`             threshold below which band stays ALIVE.
    `silent_seconds`           threshold above which band becomes SILENT.
    `reasons`                  reason codes; empty when ALIVE.
    """
    band:                     str
    seconds_since_last_cert:  int
    last_cert_epoch:          int | None
    nodes_recently_active:    int
    warn_seconds:             int
    silent_seconds:           int
    reasons:                  tuple[str, ...]

    @property
    def is_alive(self) -> bool:
        return self.band == LIVENESS_ALIVE


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_cluster_liveness(
    context:      ClusterLivenessContext,
    *,
    current_unix: int,
) -> ClusterLivenessReport:
    """
    Decide whether the cluster is currently alive, degraded, or silent.

    The rule:
      * `nodes_recently_active < MIN_RECENT_NODES_FOR_ALIVE`
        -> band = SILENT, reason BELOW_QUORUM. A structurally
        below-quorum cluster cannot have produced a fresh cert even
        if `last_cert_unix` looks recent.
      * `last_cert_unix is None`
        -> band = SILENT, reason NO_CERTS_EVER. Bootstrap or total
        cluster failure.
      * `last_cert_unix > current_unix + LIVENESS_FUTURE_TOLERANCE_SECONDS`
        -> band = SILENT, reason TIME_TRAVEL. A future-dated cert
        is structurally suspect; refuse rather than guess.
      * `seconds_since_last_cert <= WARN_QUIET_SECONDS` -> ALIVE.
      * `WARN_QUIET_SECONDS < seconds_since_last_cert <= SILENT_QUIET_SECONDS`
        -> DEGRADED, reason QUIET_WARN.
      * `seconds_since_last_cert > SILENT_QUIET_SECONDS` -> SILENT,
        reason QUIET_SILENT.

    Pure: no logging, no environment reads, no I/O.
    """
    reasons: list[str] = []

    if context.nodes_recently_active < MIN_RECENT_NODES_FOR_ALIVE:
        reasons.append(REASON_LIVENESS_BELOW_QUORUM)

    if context.last_cert_unix is None:
        reasons.append(REASON_LIVENESS_NO_CERTS_EVER)
        return ClusterLivenessReport(
            band=LIVENESS_SILENT,
            seconds_since_last_cert=-1,
            last_cert_epoch=context.last_cert_epoch,
            nodes_recently_active=context.nodes_recently_active,
            warn_seconds=WARN_QUIET_SECONDS,
            silent_seconds=SILENT_QUIET_SECONDS,
            reasons=tuple(reasons),
        )

    delta = current_unix - context.last_cert_unix

    if delta < -LIVENESS_FUTURE_TOLERANCE_SECONDS:
        reasons.append(REASON_LIVENESS_TIME_TRAVEL)
        seconds_since = 0
        band = LIVENESS_SILENT
    else:
        # Clamp small negatives (within tolerance) to zero so the
        # report's elapsed field stays non-negative.
        seconds_since = max(delta, 0)
        if seconds_since > SILENT_QUIET_SECONDS:
            reasons.append(REASON_LIVENESS_QUIET_SILENT)
            band = LIVENESS_SILENT
        elif seconds_since > WARN_QUIET_SECONDS:
            reasons.append(REASON_LIVENESS_QUIET_WARN)
            band = LIVENESS_DEGRADED
        else:
            band = LIVENESS_ALIVE

    # Below-quorum forces SILENT regardless of cert recency — a cluster
    # that lost K-of-N capability cannot produce honest certs.
    if REASON_LIVENESS_BELOW_QUORUM in reasons:
        band = LIVENESS_SILENT

    return ClusterLivenessReport(
        band=band,
        seconds_since_last_cert=seconds_since,
        last_cert_epoch=context.last_cert_epoch,
        nodes_recently_active=context.nodes_recently_active,
        warn_seconds=WARN_QUIET_SECONDS,
        silent_seconds=SILENT_QUIET_SECONDS,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_cluster_alive(
    context:      ClusterLivenessContext,
    *,
    current_unix: int,
) -> ClusterLivenessReport:
    """
    Run `verify_cluster_liveness` and raise on SILENT.

    Returns the report when band is ALIVE or DEGRADED. Raises
    `ClusterSilentError` when the cluster has gone silent — the
    consumer-side circuit breaker (SOL-3) catches this and refuses
    high-stakes operations.
    """
    report = verify_cluster_liveness(context, current_unix=current_unix)
    if report.band != LIVENESS_SILENT:
        return report
    raise ClusterSilentError(
        f"SOL-1: cluster is SILENT — "
        f"seconds_since_last_cert={report.seconds_since_last_cert}, "
        f"last_cert_epoch={report.last_cert_epoch}, "
        f"nodes_recently_active={report.nodes_recently_active}, "
        f"reasons={list(report.reasons)!r}. "
        f"New high-stakes operations MUST be refused until cluster "
        f"liveness is restored — Scenario C step 3 substrate "
        f"(DeFi protocols using stale certs).",
        report,
    )


__all__ = [
    "LIVENESS_ALIVE",
    "LIVENESS_DEGRADED",
    "LIVENESS_FUTURE_TOLERANCE_SECONDS",
    "LIVENESS_SILENT",
    "MIN_RECENT_NODES_FOR_ALIVE",
    "REASON_LIVENESS_BELOW_QUORUM",
    "REASON_LIVENESS_NO_CERTS_EVER",
    "REASON_LIVENESS_QUIET_SILENT",
    "REASON_LIVENESS_QUIET_WARN",
    "REASON_LIVENESS_TIME_TRAVEL",
    "SILENT_QUIET_SECONDS",
    "WARN_QUIET_SECONDS",
    "ClusterLivenessContext",
    "ClusterLivenessReport",
    "ClusterSilentError",
    "enforce_cluster_alive",
    "verify_cluster_liveness",
]
