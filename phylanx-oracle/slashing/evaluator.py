"""
slashing/evaluator.py — the tiered slash decision.

Connects the V2 detection engine to the slash-authority program. Given an
agent's `ScoreResult`, it answers two questions:

  1. Is this a SLASHABLE offense, or merely a degrading agent?
  2. If slashable, at what TIER (Minor / Major / Compromise)?

THE TIERING — drift is not a crime
----------------------------------
The spec is explicit: a merely-degrading agent must NOT be slashed. A low
score from statistical drift is information, not an offense — the agent's
certificate already reflects it. Slashing is reserved for CONFIRMED
adversarial behaviour:

  no slash      — the agent is GREEN/YELLOW, or RED purely from drift /
                  anomaly / performance / consistency degradation. The low
                  score IS the consequence; no stake is taken.

  Compromise    — the SECURITY dimension (dimension 5) tripped the
                  IMMEDIATE_RED fast-path AND the oracle cluster CONFIRMED
                  it. This is a confirmed compromise — the terminal slash.

  Minor / Major — reserved for confirmed-but-not-terminal security
                  offenses (a confirmed attack pattern that is not a full
                  compromise). The tier is driven by how severe the
                  security finding is. These exist so the slash-authority
                  program's three tiers are all reachable from detection;
                  Day 22's done-when exercises the no-slash and Compromise
                  paths specifically.

The decision is PURE — no clock, no chain, no randomness. It takes a
ScoreResult and a ConsensusResult and returns a SlashDecision. The epoch
runner is what turns a SlashDecision into an on-chain execute_slash call.

WHY immediate_red ALONE IS NOT ENOUGH
-------------------------------------
A single oracle node setting immediate_red is a strong signal, but a slash
moves real SOL — so the evaluator requires the oracle CLUSTER to have
confirmed the offense (see slashing/consensus.py). immediate_red without
consensus is a low score, not a slash. This is the "confirmed across the
oracle cluster" requirement from the brief, made concrete.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from detection.types import DimensionId, FlagBit
from scoring import AlertTier, ScoreResult

from slashing.consensus import ConsensusResult


# =============================================================================
# OffenseTier — mirrors the on-chain slash_authority OffenseTier enum
# =============================================================================

class OffenseTier(enum.IntEnum):
    """
    The slash tier. The integer values are the WIRE CODES — they must match
    the on-chain `OffenseTier` enum in slash-authority exactly
    (slash_record.rs: Minor=0, Major=1, Compromise=2), because the epoch
    runner passes this code straight into the execute_slash instruction.
    """
    MINOR      = 0
    MAJOR      = 1
    COMPROMISE = 2

    @property
    def slash_bps(self) -> int:
        """
        The slash fraction in basis points — mirrors the on-chain
        `OffenseTier::slash_bps`. Kept here so the off-chain runner can
        PREVIEW the slash amount with the exact same arithmetic the chain
        will use (see compute_slash_amount below).
        """
        return {
            OffenseTier.MINOR:      500,     # 5%
            OffenseTier.MAJOR:      5_000,   # 50%
            OffenseTier.COMPROMISE: 10_000,  # 100%
        }[self]

    @property
    def is_terminal(self) -> bool:
        return self is OffenseTier.COMPROMISE


# =============================================================================
# SlashDecision — the evaluator's output
# =============================================================================

@dataclass(frozen=True, slots=True)
class SlashDecision:
    """
    The decision for one agent: slash or not, and if so at what tier.

    `should_slash` False  → the agent is not slashed (degradation only).
    `should_slash` True   → `tier` is set; the runner will execute_slash.
    `reason` is a human-readable audit string explaining the decision.
    """
    agent_wallet:   str
    should_slash:   bool
    tier:           OffenseTier | None
    reason:         str
    # The inputs that drove the decision — carried for the audit trail.
    score:          int
    immediate_red:  bool
    security_immediate_red: bool
    consensus_confirmed:    bool
    consensus_summary:      str

    def __post_init__(self) -> None:
        if self.should_slash and self.tier is None:
            raise ValueError("should_slash is True but tier is None")
        if not self.should_slash and self.tier is not None:
            raise ValueError("should_slash is False but tier is set")


# =============================================================================
# The decision function
# =============================================================================

def evaluate_slash(
    score_result: ScoreResult,
    consensus:    ConsensusResult,
    *,
    agent_wallet: str,
) -> SlashDecision:
    """
    Decide whether `agent_wallet` should be slashed this epoch.

    The rule, in order:

      1. The SECURITY dimension must have tripped IMMEDIATE_RED. If the
         security dimension did not flag a compromise, there is NO slash —
         no matter how low the score. Drift / anomaly / performance /
         consistency degradation is not a slashable offense.

      2. The oracle cluster must have CONFIRMED the offense. A security
         IMMEDIATE_RED that the cluster did not confirm is a low score,
         not a slash.

      3. Both true → a confirmed compromise → OffenseTier.COMPROMISE.

    Pure and deterministic.
    """
    # Did the SECURITY dimension specifically trip IMMEDIATE_RED?
    # ScoreResult.immediate_red is the OR across all dimensions; for a
    # slash we require the SECURITY dimension itself to have raised it,
    # so a drift-driven immediate_red (if one ever occurred) cannot slash.
    security_immediate_red = _security_tripped_immediate_red(score_result)

    # ── Rule 1: no security compromise → no slash ───────────────────────────
    if not security_immediate_red:
        return SlashDecision(
            agent_wallet=agent_wallet,
            should_slash=False,
            tier=None,
            reason=(
                f"no slash: security dimension did not flag a compromise "
                f"(score={score_result.score}, alert={score_result.alert.value}) "
                f"— degradation is not a slashable offense"
            ),
            score=score_result.score,
            immediate_red=score_result.immediate_red,
            security_immediate_red=False,
            consensus_confirmed=consensus.confirmed,
            consensus_summary=consensus.vote_summary,
        )

    # ── Rule 2: security flagged, but the cluster must confirm ──────────────
    if not consensus.confirmed:
        return SlashDecision(
            agent_wallet=agent_wallet,
            should_slash=False,
            tier=None,
            reason=(
                f"no slash: security flagged a compromise but the oracle "
                f"cluster did not confirm it ({consensus.vote_summary} "
                f"via {consensus.policy}) — unconfirmed, treated as a low score"
            ),
            score=score_result.score,
            immediate_red=score_result.immediate_red,
            security_immediate_red=True,
            consensus_confirmed=False,
            consensus_summary=consensus.vote_summary,
        )

    # ── Rule 3: security compromise + cluster consensus → SLASH ─────────────
    return SlashDecision(
        agent_wallet=agent_wallet,
        should_slash=True,
        tier=OffenseTier.COMPROMISE,
        reason=(
            f"slash (COMPROMISE): security dimension flagged IMMEDIATE_RED "
            f"and the oracle cluster confirmed it ({consensus.vote_summary} "
            f"via {consensus.policy})"
        ),
        score=score_result.score,
        immediate_red=score_result.immediate_red,
        security_immediate_red=True,
        consensus_confirmed=True,
        consensus_summary=consensus.vote_summary,
    )


def _security_tripped_immediate_red(score_result: ScoreResult) -> bool:
    """
    True iff the SECURITY dimension (dimension 5) raised the IMMEDIATE_RED
    flag. Inspects the security dimension's own flags — NOT the aggregated
    flags — so only a security-driven compromise qualifies for a slash.
    """
    security = score_result.dimension_results.get(DimensionId.SECURITY)
    if security is None:
        return False
    return (security.flags & int(FlagBit.IMMEDIATE_RED)) == int(FlagBit.IMMEDIATE_RED)


# =============================================================================
# Bridge: a node's ScoreResult -> its NodeVerdict
# =============================================================================

def verdict_from_score(
    node_id:      str,
    score_result: ScoreResult,
) -> "NodeVerdict":
    """
    Derive one oracle node's `NodeVerdict` from the `ScoreResult` that node
    computed.

    A node CONFIRMS a compromise iff its own scoring tripped a
    security-dimension IMMEDIATE_RED. This is the per-node finding that the
    `ConsensusPolicy` then tallies across the cluster.

    In the Phase-4 cluster each node runs the (deterministic) detection
    engine independently and produces its own ScoreResult; this function
    is how each node's result becomes its vote. Today there is one node,
    so there is one verdict — but the bridge is identical either way.
    """
    from slashing.consensus import NodeVerdict

    return NodeVerdict(
        node_id=node_id,
        confirms_compromise=_security_tripped_immediate_red(score_result),
        score=score_result.score,
        immediate_red=score_result.immediate_red,
    )


# =============================================================================
# Slash-amount preview — byte-identical to the on-chain math
# =============================================================================

def compute_slash_amount(staked_lamports: int, tier: OffenseTier) -> int:
    """
    Compute the lamports a slash of `tier` takes from `staked_lamports`.

    This MIRRORS the on-chain `compute_slash_amount` in slash-authority
    (slash_record.rs) EXACTLY — same basis-point integer math, same
    terminal-tier guard. The off-chain runner uses it to preview /
    cross-check the amount; the chain remains the source of truth, but a
    mismatch between this and the chain would be a determinism bug, so the
    arithmetic is kept identical.

    THE u128 INTERMEDIATE
    ---------------------
    On-chain, `staked_lamports * slash_bps` could overflow a u64, so the
    Rust uses a u128 intermediate. Python ints are arbitrary-precision so
    they cannot overflow — but to stay byte-identical to the chain we
    perform the SAME operation in the SAME order: full-width multiply,
    then integer-divide by 10_000. A terminal tier takes the whole stake
    exactly (the guard, not the bps math), so no rounding leaves dust.
    """
    if staked_lamports < 0:
        raise ValueError(f"staked_lamports must be >= 0, got {staked_lamports}")

    # Full-width multiply then floor-divide — mirrors the Rust u128 path.
    product = staked_lamports * tier.slash_bps          # the "u128" intermediate
    amount = product // 10_000

    if tier.is_terminal:
        # A terminal (Compromise) slash takes the ENTIRE remaining stake,
        # exactly — the same defensive guard as the on-chain code.
        return staked_lamports
    return min(amount, staked_lamports)
