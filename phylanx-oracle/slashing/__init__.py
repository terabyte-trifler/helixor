"""
phylanx-oracle / slashing — connects the V2 detection engine to the
slash-authority program.

The epoch runner scores agents; this package decides which scores warrant
a slash. The rule is tiered and conservative: a merely-degrading agent is
NOT slashed (its low score is the consequence); only a CONFIRMED security
compromise — the security dimension's IMMEDIATE_RED, confirmed by the
oracle cluster — triggers a slash.

Public API:
    NodeVerdict, ConsensusResult                  consensus types
    ConsensusPolicy                               the consensus interface
    SingleNodeConsensus, ThresholdConsensus       the two policies
    OffenseTier, SlashDecision                    the evaluator types
    evaluate_slash                                the tiered decision
    verdict_from_score                            ScoreResult -> NodeVerdict
    compute_slash_amount                          on-chain-identical math
"""

from __future__ import annotations

from slashing.consensus import (
    ConsensusPolicy,
    ConsensusResult,
    NodeVerdict,
    SingleNodeConsensus,
    ThresholdConsensus,
)
from slashing.evaluator import (
    OffenseTier,
    SlashDecision,
    compute_slash_amount,
    evaluate_slash,
    verdict_from_score,
)

__all__ = [
    "NodeVerdict", "ConsensusResult", "ConsensusPolicy",
    "SingleNodeConsensus", "ThresholdConsensus",
    "OffenseTier", "SlashDecision", "evaluate_slash",
    "verdict_from_score", "compute_slash_amount",
]
