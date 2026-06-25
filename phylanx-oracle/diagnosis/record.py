"""
diagnosis/record.py — the off-chain DiagnosisRecord (Day 34, Phase-1).

WHAT THIS IS
------------
The composite scorer produces a `ScoreResult` that already carries the
full per-dimension breakdown. The Day-19 on-chain stack writes a
`ScoreComponentsAccount` (AW-04 payload) with the canonical-JSON form
of that breakdown, but the public API has been throwing it away —
returning only the `score` + `alert_tier` + opaque flag token.

`DiagnosisRecord` is the *off-chain* persistence shape that the API
serves until the Phase-2 certificate schema bump lands. It is:

    a structured, per-(agent, epoch) record holding every field the
    diagnosis surface needs — per-dimension `{score, max_score,
    sub_scores, flags}`, the weighted contributions that sum to the
    composite, the aggregated u32 legacy flag bitmask, plus the
    Day-13 gaming + confidence signals.

It is deliberately:

  - NOT threshold-attested. The Day-34 API marks this tier
    `attestation: "off_chain_v1"`. Phase-2 lifts the same shape into a
    threshold-signed certificate field.
  - NOT a u64 FailureMode bitmask. The Day-33 taxonomy v1 is the
    `FailureMode` *for the long-form labels*; the legacy `flags: u32`
    half is what the oracle scorer actually emits today. The API
    decodes legacy flags through the Day-33 `decode.py` (low-32-bit
    legacy passthrough) so the response carries both raw and decoded
    forms.
  - DERIVED, not stored separately. `record_from_score_result(...)`
    reads a `ScoreResult` and packs it. No new pipeline state.

PROVENANCE LINK
---------------
Every record carries the `baseline_stats_hash` and
`scoring_schema_fingerprint` from the underlying ScoreResult so a
consumer can trace the diagnosis back to the same baseline and scoring
kernel that produced the on-chain score. The hash chain is unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Avoid a hard import cycle: scoring imports detection imports
    # diagnosis is not in either path. This local import keeps it clean.
    from scoring import ScoreResult


@dataclass(frozen=True, slots=True)
class DimensionBreakdown:
    """One dimension's slice of the diagnosis — pulled verbatim from
    the corresponding `DimensionResult` in the scorer output.

    `sub_scores` is an immutable mapping (str → float in [0, 1]); the
    keys are the diagnostic outputs the detector chose to expose. The
    composite scorer's `score` field is the integer score in
    [0, max_score]; `score_normalised` recovers the [0, 1] form.
    """
    dimension:   str                       # "drift" | "anomaly" | …
    score:       int                       # [0, max_score]
    max_score:   int
    flags:       int                       # u32, per-dimension + universal
    sub_scores:  Mapping[str, float]
    algo_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.score, int) or isinstance(self.score, bool):
            raise TypeError("score must be int")
        if not (0 <= self.score <= self.max_score):
            raise ValueError(
                f"score {self.score} outside [0, {self.max_score}] for "
                f"{self.dimension}"
            )
        if not (0 <= self.flags <= 0xFFFFFFFF):
            raise ValueError(f"flags {self.flags} does not fit in u32")
        if not isinstance(self.sub_scores, MappingProxyType):
            object.__setattr__(
                self, "sub_scores",
                MappingProxyType(dict(self.sub_scores)),
            )

    @property
    def score_normalised(self) -> float:
        if self.max_score == 0:
            return 0.0
        return self.score / self.max_score


@dataclass(frozen=True, slots=True)
class DiagnosisRecord:
    """The off-chain diagnosis payload for one (agent, epoch).

    Stable across the Phase-1 → Phase-2 boundary: the Phase-2 cert v2
    fields (`failure_mode_bitmask: u64`, `remediation_codes: u32`)
    *derive* from this record; the field set here is a superset of
    what cert v2 will threshold-sign.
    """
    agent_wallet:               str
    epoch:                      int
    score:                      int            # 0..1000 composite
    alert_tier:                 int            # 0 GREEN | 1 YELLOW | 2 RED
    immediate_red:              bool

    dimensions:                 Mapping[str, DimensionBreakdown]
    weighted_contributions:     Mapping[str, int]   # sums to `score` (± rounding)
    flags:                      int            # u32, aggregated legacy bitmask

    confidence:                 int            # 0..1000
    gaming_detected:            bool
    gaming_drop_fraction:       float
    delta_clamped:              bool

    # Provenance — keep the chain visible for the audit story.
    scoring_algo_version:       int
    scoring_weights_version:    int
    scoring_schema_fingerprint: str
    baseline_stats_hash:        str

    computed_at:                datetime

    def __post_init__(self) -> None:
        if not (0 <= self.score <= 1000):
            raise ValueError(f"score {self.score} out of [0, 1000]")
        if self.alert_tier not in (0, 1, 2):
            raise ValueError(f"alert_tier invalid: {self.alert_tier}")
        if self.epoch < 1:
            raise ValueError(f"epoch must be >= 1, got {self.epoch}")
        if not (0 <= self.flags <= 0xFFFFFFFF):
            raise ValueError(f"flags {self.flags} does not fit in u32")
        if not (0 <= self.confidence <= 1000):
            raise ValueError(f"confidence {self.confidence} out of [0, 1000]")
        if not (0.0 <= self.gaming_drop_fraction <= 1.0):
            raise ValueError(
                f"gaming_drop_fraction {self.gaming_drop_fraction} out of [0, 1]"
            )
        if self.computed_at.tzinfo is None:
            raise ValueError("computed_at must be timezone-aware UTC")
        if not isinstance(self.dimensions, MappingProxyType):
            object.__setattr__(
                self, "dimensions",
                MappingProxyType(dict(self.dimensions)),
            )
        if not isinstance(self.weighted_contributions, MappingProxyType):
            object.__setattr__(
                self, "weighted_contributions",
                MappingProxyType(dict(self.weighted_contributions)),
            )


# =============================================================================
# Builder — ScoreResult -> DiagnosisRecord
# =============================================================================

def record_from_score_result(
    *,
    agent_wallet: str,
    epoch:        int,
    score_result: "ScoreResult",
    computed_at:  datetime | None = None,
) -> DiagnosisRecord:
    """
    Construct a `DiagnosisRecord` from a Phase-1 `ScoreResult`.

    Pure. Same inputs → byte-identical record.

    `computed_at` defaults to the `ScoreResult.computed_at` — keeping
    the timestamp anchored to *when the score was computed*, not when
    the record was materialised, so a downstream re-export of the same
    score doesn't drift.
    """
    alert_tier_code = {"GREEN": 0, "YELLOW": 1, "RED": 2}[score_result.alert.value]

    dimensions = {
        dim.value: DimensionBreakdown(
            dimension=dim.value,
            score=result.score,
            max_score=result.max_score,
            flags=result.flags,
            sub_scores=dict(result.sub_scores),
            algo_version=result.algo_version,
        )
        for dim, result in score_result.dimension_results.items()
    }

    weighted_contributions = {
        dim.value: int(value)
        for dim, value in score_result.weighted_contributions.items()
    }

    return DiagnosisRecord(
        agent_wallet=agent_wallet,
        epoch=epoch,
        score=score_result.score,
        alert_tier=alert_tier_code,
        immediate_red=score_result.immediate_red,
        dimensions=MappingProxyType(dimensions),
        weighted_contributions=MappingProxyType(weighted_contributions),
        flags=score_result.aggregated_flags,
        confidence=score_result.confidence,
        gaming_detected=score_result.gaming_detected,
        gaming_drop_fraction=score_result.gaming_drop_fraction,
        delta_clamped=score_result.delta_clamped,
        scoring_algo_version=score_result.scoring_algo_version,
        scoring_weights_version=score_result.scoring_weights_version,
        scoring_schema_fingerprint=score_result.scoring_schema_fingerprint,
        baseline_stats_hash=score_result.baseline_stats_hash,
        computed_at=computed_at or score_result.computed_at,
    )
