"""
oracle/staleness_escalator.py — SOL-2: per-agent age-based tier
degradation escalator for Scenario C step 3+4.

THE CATASTROPHIC FAILURE SCENARIO (audit Scenario C, steps 3-4)
---------------------------------------------------------------
    "DeFi protocols continue to use last-issued certs (stale data).
    Agents whose behavior degrades never get updated certs."

SOL-1 closes the CLUSTER-WIDE silence visibility. What SOL-1 does NOT
close is the PER-AGENT case: even when the cluster is healthy, an
individual agent's cert can age silently between successful refreshes.
If agent X received a GREEN cert at hour 0, the cluster signs other
agents at hours 1, 2, 3 (so SOL-1's cluster-wide clock stays ALIVE),
and agent X's behaviour begins to deteriorate at hour 12 — agent X
still carries a 12-hour-old GREEN cert that says "this agent is
collateral-grade." TA-6's 48h backstop is too coarse: a degrading
agent acting on a 12-hour-old GREEN is a real-world hazard for the
DeFi protocol that gates a new loan on it.

SOL-2 reifies a PER-AGENT staleness escalator: as a cert ages, the
EFFECTIVE alert tier is downgraded.

    GREEN cert older than `GREEN_TO_YELLOW_AFTER_SECONDS` (6h)
                -> EFFECTIVE tier YELLOW.
    YELLOW cert older than `YELLOW_TO_RED_AFTER_SECONDS` (12h)
                -> EFFECTIVE tier RED.
    Cert older than `REFUSE_AFTER_SECONDS` (24h)
                -> EFFECTIVE tier REFUSE — the consumer MUST refuse
                   to act on the cert regardless of its issued tier.

Note SOL-2 sits BELOW TA-6's 48h ceiling: by the time a cert hits
SOL-2's 24h REFUSE, the consumer is already declining new operations
even though TA-6 would still mark the cert as "fresh." The
defence-in-depth chain is:

    SOL-2 6h  -> downgrade GREEN -> YELLOW
    SOL-2 12h -> downgrade YELLOW -> RED
    SOL-2 24h -> REFUSE
    TA-6 48h  -> hard STALE (last backstop)

CALIBRATION
-----------
- `GREEN_TO_YELLOW_AFTER_SECONDS = 6 * 3600` — three full canonical
  cluster cadences (2h cadence × 3). A cert that's been stale for
  three epochs is suspicious enough that we no longer want to extend
  a GREEN endorsement against it.
- `YELLOW_TO_RED_AFTER_SECONDS = 12 * 3600` — six full cadences. The
  cluster has had ample opportunity to refresh; the silence on this
  particular agent is unusual.
- `REFUSE_AFTER_SECONDS = 24 * 3600` — twelve cadences. The cert is
  half-life-of-TA-6 old. Any new high-stakes operation against this
  cert is structurally unsafe regardless of the original tier.

INTERACTION WITH SOL-1 / SOL-3 / TA-6
-------------------------------------
- SOL-1 sees CLUSTER-WIDE silence; SOL-2 sees PER-AGENT silence under
  a healthy cluster.
- SOL-3 uses SOL-2's effective tier (post-escalation) when applying
  per-operation freshness floors.
- TA-6 (48h) is the OUTER ring; SOL-2 sits inside it.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(issued_at_unix, current_unix)`
+ tier string. No clock, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Tier strings — match the on-chain `AlertTier` ordinal labels.
TIER_GREEN = "GREEN"
TIER_YELLOW = "YELLOW"
TIER_RED = "RED"

#: A pseudo-tier emitted when the cert is too old to act on at all.
TIER_REFUSE = "REFUSE"

#: Seconds at which a GREEN cert is downgraded to YELLOW.
GREEN_TO_YELLOW_AFTER_SECONDS = 6 * 3600

#: Seconds at which a YELLOW (effective) cert is downgraded to RED.
YELLOW_TO_RED_AFTER_SECONDS = 12 * 3600

#: Seconds at which ANY cert is refused outright.
REFUSE_AFTER_SECONDS = 24 * 3600

#: Tolerance for `issued_at > current_unix` (60s of clock skew).
ESCALATOR_FUTURE_TOLERANCE_SECONDS = 60

#: Reason codes.
REASON_AGE_DOWNGRADE_GREEN_TO_YELLOW = "AGE_DOWNGRADE_GREEN_TO_YELLOW"
REASON_AGE_DOWNGRADE_YELLOW_TO_RED = "AGE_DOWNGRADE_YELLOW_TO_RED"
REASON_AGE_REFUSE = "AGE_REFUSE"
REASON_ESCALATOR_TIME_TRAVEL = "CERT_ISSUED_IN_FUTURE"


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class CertSnapshot:
    """
    One agent's most recent cert summary, as the SDK consumer sees it.

    `agent_wallet`     the agent's base58 pubkey.
    `issued_tier`      the alert tier the cluster originally stamped
                       (GREEN / YELLOW / RED).
    `issued_at_unix`   Unix seconds at which the cluster signed.
    """
    agent_wallet:   str
    issued_tier:    str
    issued_at_unix: int


@dataclass(frozen=True, slots=True)
class StalenessReport:
    """
    Verdict of one SOL-2 escalation.

    `agent_wallet`        echoed from the input.
    `issued_tier`         the cluster's original tier.
    `effective_tier`      the tier the consumer should ACT ON after
                          age-based escalation. May be REFUSE.
    `cert_age_seconds`    `current_unix - issued_at_unix` (clamped to
                          0 on time-travel).
    `green_to_yellow_at`  seconds floor at which GREEN -> YELLOW.
    `yellow_to_red_at`    seconds floor at which YELLOW -> RED.
    `refuse_at`           seconds floor above which any tier is refused.
    `reasons`             reason codes when escalation fired.
    """
    agent_wallet:        str
    issued_tier:         str
    effective_tier:      str
    cert_age_seconds:    int
    green_to_yellow_at:  int
    yellow_to_red_at:    int
    refuse_at:           int
    reasons:             tuple[str, ...]

    @property
    def is_refused(self) -> bool:
        return self.effective_tier == TIER_REFUSE

    @property
    def was_downgraded(self) -> bool:
        return self.effective_tier != self.issued_tier


# =============================================================================
# Escalator (pure)
# =============================================================================

def _normalise_tier(tier: str) -> str:
    return tier.strip().upper()


def escalate_for_age(
    snapshot:     CertSnapshot,
    *,
    current_unix: int,
) -> StalenessReport:
    """
    Compute the EFFECTIVE alert tier after age-based downgrade.

    The escalation is one-directional: a tier may only be downgraded,
    never upgraded. A cert whose issued tier is already RED is left
    at RED until it hits `REFUSE_AFTER_SECONDS` and is REFUSED outright.

    Future-dated certs (issued_at_unix > current_unix + tolerance) are
    REFUSED with `REASON_ESCALATOR_TIME_TRAVEL` — a structural failure
    that cannot be resolved by the consumer; report it and refuse to act.
    """
    reasons: list[str] = []
    issued = _normalise_tier(snapshot.issued_tier)
    delta = current_unix - snapshot.issued_at_unix

    if delta < -ESCALATOR_FUTURE_TOLERANCE_SECONDS:
        reasons.append(REASON_ESCALATOR_TIME_TRAVEL)
        return StalenessReport(
            agent_wallet=snapshot.agent_wallet,
            issued_tier=issued,
            effective_tier=TIER_REFUSE,
            cert_age_seconds=0,
            green_to_yellow_at=GREEN_TO_YELLOW_AFTER_SECONDS,
            yellow_to_red_at=YELLOW_TO_RED_AFTER_SECONDS,
            refuse_at=REFUSE_AFTER_SECONDS,
            reasons=tuple(reasons),
        )

    age = max(delta, 0)
    effective = issued

    if age > REFUSE_AFTER_SECONDS:
        reasons.append(REASON_AGE_REFUSE)
        effective = TIER_REFUSE
    else:
        if issued == TIER_GREEN and age > GREEN_TO_YELLOW_AFTER_SECONDS:
            reasons.append(REASON_AGE_DOWNGRADE_GREEN_TO_YELLOW)
            effective = TIER_YELLOW
        # After the GREEN -> YELLOW transition, a sufficiently aged
        # cert may continue downgrading to RED.
        if effective == TIER_YELLOW and age > YELLOW_TO_RED_AFTER_SECONDS:
            reasons.append(REASON_AGE_DOWNGRADE_YELLOW_TO_RED)
            effective = TIER_RED

    return StalenessReport(
        agent_wallet=snapshot.agent_wallet,
        issued_tier=issued,
        effective_tier=effective,
        cert_age_seconds=age,
        green_to_yellow_at=GREEN_TO_YELLOW_AFTER_SECONDS,
        yellow_to_red_at=YELLOW_TO_RED_AFTER_SECONDS,
        refuse_at=REFUSE_AFTER_SECONDS,
        reasons=tuple(reasons),
    )


__all__ = [
    "ESCALATOR_FUTURE_TOLERANCE_SECONDS",
    "GREEN_TO_YELLOW_AFTER_SECONDS",
    "REASON_AGE_DOWNGRADE_GREEN_TO_YELLOW",
    "REASON_AGE_DOWNGRADE_YELLOW_TO_RED",
    "REASON_AGE_REFUSE",
    "REASON_ESCALATOR_TIME_TRAVEL",
    "REFUSE_AFTER_SECONDS",
    "TIER_GREEN",
    "TIER_RED",
    "TIER_REFUSE",
    "TIER_YELLOW",
    "YELLOW_TO_RED_AFTER_SECONDS",
    "CertSnapshot",
    "StalenessReport",
    "escalate_for_age",
]
