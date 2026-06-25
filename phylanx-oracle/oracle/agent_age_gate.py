"""
oracle/agent_age_gate.py — NSS-3: agent-registration-age floor for
GREEN-band certs.

THE CATASTROPHIC FAILURE SCENARIO (audit Scenario B, steps 4 and 5)
-------------------------------------------------------------------
    "Nation-state holds 3 oracle keys and uses them to issue GREEN
    certs for state-controlled AI agents. These agents use DeFi
    protocols to accumulate large positions."

The on-chain `certificate_issuer::issue_certificate` handler validates
score-vs-tier consistency (`score >= 700 -> GREEN`) but does NOT gate
on the AGE of the agent. An attacker who controls cluster keys can
register a fresh wallet at epoch N and issue a GREEN cert at epoch
N+1. The SDK's `SafeCertReader` already enforces
`MIN_HISTORY_REQUIRED = 2` epochs of recent score data, but TWO
epochs is 4 hours at a 2h cadence — well inside the "set up and
borrow" window for a state actor.

NSS-3 reifies a STRONGER history contract on the CERT-ISSUANCE side:

    A cert with `tier == GREEN` MUST come from an agent whose
    `agent_registration.registered_at` is older than
    `MIN_AGENT_AGE_SECONDS_FOR_GREEN`. The cluster's pre-issue gate
    refuses to sign a GREEN cert for a fresh wallet.

The floor is calibrated for a state-controlled-agent attack: 14 days
is long enough that a coordinated "set up state agents, wait, borrow"
operation is detectable by external observers (any agent that registers
and immediately ranks GREEN is conspicuous). It is short enough that
honest new entrants are not locked out of the protocol forever —
their first GREEN cert simply has to wait until their wallet has
accumulated visible on-chain history.

THE MITIGATION (this file)
--------------------------
A pure, deterministic helper:

  * `verify_agent_age_for_tier(context, *, current_unix, current_epoch,
    tier)` — returns an `AgentAgeReport` describing whether the
    requested tier is allowed for this agent's registration age.
  * `enforce_agent_age_for_tier(...)` — fail-closed wrapper, raises
    `InsufficientAgentAgeError` (with the report attached).

The cluster's pre-issue hook calls `enforce_agent_age_for_tier` on
every cert about to be signed. A refusal means the cluster either
(a) downgrades the cert tier to YELLOW (one rank below GREEN) and
re-signs, OR (b) refuses to issue the cert at all this epoch and
re-tries next epoch when the agent has aged further.

The downgrade path is intentionally NOT in this module — the policy
choice (downgrade-vs-defer) lives at the call site in
`oracle/cluster/cert_signing.py`. NSS-3 only answers the binary
question: is this agent old enough for this tier?

CALIBRATION
-----------
- `MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14 * 24 * 3600` — 14 days. The
  empirical floor below which a registration-and-borrow operation
  becomes operationally invisible (the wallet has no public history
  to inspect).
- `MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168` — equivalent epoch count
  assuming a 2h cadence (12 epochs/day * 14 days). Both floors must
  be satisfied; the seconds floor catches a cluster that boosted its
  epoch rate, the epochs floor catches a cluster running at slower-
  than-expected cadence.
- `YELLOW` and `RED` tiers are not gated — only GREEN. NSS-3 is
  specifically about the collateral-grade tier.

DETERMINISM
-----------
Pure stdlib. Integer arithmetic on `(registered_at_unix, current_unix)`
and `(registered_at_epoch, current_epoch)`. No clock (the timestamps
arrive as arguments), no network, no randomness.

INTERACTION WITH VULN-23 (SafeCertReader) / TA-6 (cert freshness)
-----------------------------------------------------------------
VULN-23's `MIN_HISTORY_REQUIRED = 2` is a CONSUMER-SIDE freshness
contract — the DeFi reader refuses a cert with too few historical
samples. NSS-3 is a CLUSTER-SIDE issuance contract — the cluster
refuses to STAMP GREEN onto a wallet without enough wall-clock age.
The two are complementary: a cluster captured by a state actor that
ignored NSS-3 would still produce certs the consumer-side gate
refuses, but defence-in-depth wants both sides to enforce the same
contract.

TA-6's 48h freshness contract is about cert AGE; NSS-3 is about
AGENT REGISTRATION age. The two clocks are independent.
"""

from __future__ import annotations

from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Minimum wall-clock seconds between agent registration and the first
#: GREEN-band cert. 14 days. This is the headline NSS-3 floor.
MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14 * 24 * 3600

#: Minimum epoch count between agent registration and the first
#: GREEN-band cert. 168 epochs at the canonical 2h cadence = 14 days.
#: Both this AND the seconds floor must be satisfied so a cluster that
#: drifts its cadence cannot use the drift to evade NSS-3.
MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168

#: The tier the gate cares about. Matches the on-chain
#: `certificate_issuer::AlertTier::Green` ordinal.
GATED_TIER_GREEN = "GREEN"

#: Reason codes — stable strings the cluster boot log greps for.
REASON_SECONDS_TOO_YOUNG = "AGENT_SECONDS_TOO_YOUNG"
REASON_EPOCHS_TOO_YOUNG = "AGENT_EPOCHS_TOO_YOUNG"
REASON_TIME_TRAVEL = "AGENT_REGISTERED_IN_FUTURE"


# =============================================================================
# Errors
# =============================================================================

class InsufficientAgentAgeError(RuntimeError):
    """
    Raised by `enforce_agent_age_for_tier` when the agent's wallet is
    too young for the requested tier.

    `.report` carries the verdict — `agent_age_seconds`,
    `agent_age_epochs`, the floors, and the reason codes — so the
    cluster's pre-issue hook can either downgrade the cert tier or
    defer issuance to a later epoch.
    """

    def __init__(self, message: str, report: "AgentAgeReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class AgentAgeContext:
    """
    One agent's identity and registration timestamps.

    `agent_wallet`              the base58 pubkey of the agent.
    `registered_at_unix`        Unix seconds at which the
                                `AgentRegistration` PDA was created.
    `registered_at_epoch`       Phylanx epoch at which the
                                `AgentRegistration` PDA was created.
    """
    agent_wallet:        str
    registered_at_unix:  int
    registered_at_epoch: int


@dataclass(frozen=True, slots=True)
class AgentAgeReport:
    """
    Verdict of one NSS-3 check.

    `agent_wallet`         echoed from the input.
    `tier_requested`       the alert-tier string the cluster wanted
                           to sign (GREEN / YELLOW / RED).
    `agent_age_seconds`    `current_unix - registered_at_unix` (or 0
                           if the registration is in the future).
    `agent_age_epochs`     `current_epoch - registered_at_epoch` (or
                           0 if the registration is in the future).
    `min_seconds_required` the seconds floor for the requested tier.
    `min_epochs_required`  the epochs floor for the requested tier.
    `is_allowed`           True iff the tier is permitted for this age.
    `reasons`              reason codes when not allowed.
    """
    agent_wallet:          str
    tier_requested:        str
    agent_age_seconds:     int
    agent_age_epochs:      int
    min_seconds_required:  int
    min_epochs_required:   int
    reasons:               tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return not self.reasons


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_agent_age_for_tier(
    context:        AgentAgeContext,
    *,
    current_unix:   int,
    current_epoch:  int,
    tier:           str,
) -> AgentAgeReport:
    """
    Decide whether the cluster may issue a cert at `tier` for this
    agent given its registration age.

    Only `GREEN` is gated. YELLOW / RED / any other tier is permitted
    immediately — those tiers represent risk SIGNALS, not collateral-
    grade endorsements, so a fresh wallet may receive them.

    Parameters
    ----------
    context
        The agent's registration timestamps.
    current_unix
        Wall-clock Unix seconds at the time of cert issuance.
    current_epoch
        Phylanx epoch at the time of cert issuance.
    tier
        The alert tier string the cluster wants to stamp on the cert.

    Returns
    -------
    AgentAgeReport
        Verdict including age-deltas, the floors, and reason codes.
    """
    reasons: list[str] = []

    age_seconds = current_unix - context.registered_at_unix
    age_epochs = current_epoch - context.registered_at_epoch

    # Defend against clock-rewind / time-travel: a registration whose
    # timestamp lies in the future is structurally suspect.
    if age_seconds < 0 or age_epochs < 0:
        reasons.append(REASON_TIME_TRAVEL)
        # Clamp to zero so the report's age fields stay non-negative.
        age_seconds = max(age_seconds, 0)
        age_epochs = max(age_epochs, 0)

    requested = tier.strip().upper()
    if requested == GATED_TIER_GREEN:
        if age_seconds < MIN_AGENT_AGE_SECONDS_FOR_GREEN:
            reasons.append(REASON_SECONDS_TOO_YOUNG)
        if age_epochs < MIN_AGENT_AGE_EPOCHS_FOR_GREEN:
            reasons.append(REASON_EPOCHS_TOO_YOUNG)
        min_seconds = MIN_AGENT_AGE_SECONDS_FOR_GREEN
        min_epochs = MIN_AGENT_AGE_EPOCHS_FOR_GREEN
    else:
        # Non-GREEN tiers are not gated by NSS-3. The report still
        # reflects the inputs for telemetry.
        min_seconds = 0
        min_epochs = 0

    return AgentAgeReport(
        agent_wallet=context.agent_wallet,
        tier_requested=requested,
        agent_age_seconds=age_seconds,
        agent_age_epochs=age_epochs,
        min_seconds_required=min_seconds,
        min_epochs_required=min_epochs,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_agent_age_for_tier(
    context:        AgentAgeContext,
    *,
    current_unix:   int,
    current_epoch:  int,
    tier:           str,
) -> AgentAgeReport:
    """
    Run `verify_agent_age_for_tier` and raise on a refusal.

    Returns the report on success; raises `InsufficientAgentAgeError`
    (with the report attached) when the agent is too young for the
    requested tier.
    """
    report = verify_agent_age_for_tier(
        context,
        current_unix=current_unix,
        current_epoch=current_epoch,
        tier=tier,
    )
    if report.is_allowed:
        return report
    raise InsufficientAgentAgeError(
        f"NSS-3: agent {context.agent_wallet!r} is too young for tier "
        f"{report.tier_requested!r} "
        f"(age = {report.agent_age_seconds}s / {report.agent_age_epochs} "
        f"epochs; floor = {report.min_seconds_required}s / "
        f"{report.min_epochs_required} epochs; reasons = "
        f"{list(report.reasons)!r}). The cluster MUST downgrade the "
        f"cert tier or defer issuance until the wallet has accumulated "
        f"enough on-chain age — a fresh wallet receiving a GREEN cert "
        f"is the substrate of audit Scenario B step 4.",
        report,
    )


__all__ = [
    "GATED_TIER_GREEN",
    "MIN_AGENT_AGE_EPOCHS_FOR_GREEN",
    "MIN_AGENT_AGE_SECONDS_FOR_GREEN",
    "REASON_EPOCHS_TOO_YOUNG",
    "REASON_SECONDS_TOO_YOUNG",
    "REASON_TIME_TRAVEL",
    "AgentAgeContext",
    "AgentAgeReport",
    "InsufficientAgentAgeError",
    "enforce_agent_age_for_tier",
    "verify_agent_age_for_tier",
]
