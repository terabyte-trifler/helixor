"""
baseline/types.py — the BaselineStats type and supporting structures.

A BaselineStats is the statistical fingerprint of an agent's "normal"
behaviour over a 30-day window. Every detector in Phase 1 measures the
agent's current behaviour AGAINST this baseline.

Design contract:
  - BaselineStats is FROZEN (immutable).
  - It carries its own algo version + feature schema fingerprint, so the
    scoring engine can REFUSE an incompatible baseline rather than silently
    producing a wrong score.
  - feature_means / feature_stds are always exactly 100 elements (the
    FeatureVector contract). Enforced at construction.
  - It knows how much data backed it (days_with_activity, transaction_count)
    so a thin baseline can be marked `provisional` instead of trusted.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

from features import FEATURE_SCHEMA_VERSION, TOTAL_FEATURES


BASELINE_ALGO_VERSION = 3

# A v2 baseline needs enough data to be meaningful. Below these bars the
# baseline is still computed but flagged `provisional` — the scoring engine
# treats provisional baselines with wide tolerance bands.
MIN_DAYS_WITH_ACTIVITY = 7      # at least 7 distinct active days in the window
MIN_TRANSACTION_COUNT  = 30     # at least 30 transactions in the window

# Float precision for the canonical hash. Every float in the hashed payload
# is rounded to this many decimal places BEFORE serialization. This is what
# makes the stats_hash reproducible across machines / Python versions:
# 0.1 + 0.2 may differ in the 17th digit, but never in the 9th.
HASH_FLOAT_PRECISION = 9


class BaselineError(Exception):
    """Base class for baseline-engine errors."""


class InsufficientDataError(BaselineError):
    """Raised when an agent has too little data to compute even a provisional baseline."""


class IncompatibleBaselineError(BaselineError):
    """Raised when a loaded baseline's algo/schema version doesn't match the current engine."""


@dataclass(frozen=True, slots=True)
class BaselineStats:
    """
    The statistical baseline for a single agent over a 30-day window.

    Immutable. Self-describing (carries its versions). The `stats_hash` is the
    on-chain commitment computed by `baseline.hashing.compute_stats_hash`.
    """
    # ─── Identity ────────────────────────────────────────────────────────────
    agent_wallet:              str

    # ─── Versioning — lets downstream refuse an incompatible baseline ────────
    baseline_algo_version:     int
    feature_schema_version:    int
    feature_schema_fingerprint:str           # sha256 of the ordered feature names
    scoring_schema_fingerprint:str           # sha256 of ordered dimensions + maxes + weights

    # ─── Window ──────────────────────────────────────────────────────────────
    window_start:              datetime      # tz-aware UTC
    window_end:                datetime      # tz-aware UTC

    # ─── The core baseline: per-feature mean + stddev over the daily series ──
    # Both are EXACTLY TOTAL_FEATURES (100) elements, in canonical feature order.
    feature_means:             tuple[float, ...]
    feature_stds:              tuple[float, ...]

    # ─── Scalar summary statistics ───────────────────────────────────────────
    txtype_distribution:       tuple[float, ...]   # 5 fractions: swap/lend/stake/transfer/other
    action_entropy:            float               # Shannon entropy of the action distribution
    success_rate_30d:          float               # overall success fraction over the window

    # ─── Time series (NEW in v3, Day 6) ──────────────────────────────────────
    # Per-active-day success rate, in chronological order. Used by drift
    # detectors (CUSUM / ADWIN / DDM) that operate on a sequential stream.
    # Length equals `days_with_activity` (NOT padded — a no-activity day is
    # not a 0% success day; it's absence of data).
    daily_success_rate_series: tuple[float, ...]

    # ─── Data-sufficiency metadata ───────────────────────────────────────────
    transaction_count:         int                 # txs in the window
    days_with_activity:        int                 # distinct calendar days with >=1 tx
    is_provisional:            bool                # True if below the data bars

    # ─── Provenance ──────────────────────────────────────────────────────────
    computed_at:               datetime            # tz-aware UTC — NOT part of stats_hash

    # ─── The commitment ──────────────────────────────────────────────────────
    # sha256 hex of the canonical payload. Set by the engine after construction
    # of everything above; see baseline.hashing. Stored separately so the hash
    # function is independently testable.
    stats_hash:                str

    def __post_init__(self) -> None:
        # Array-length contract: means + stds are exactly 100 elements.
        if len(self.feature_means) != TOTAL_FEATURES:
            raise ValueError(
                f"feature_means must have {TOTAL_FEATURES} elements, "
                f"got {len(self.feature_means)}"
            )
        if len(self.feature_stds) != TOTAL_FEATURES:
            raise ValueError(
                f"feature_stds must have {TOTAL_FEATURES} elements, "
                f"got {len(self.feature_stds)}"
            )
        if len(self.txtype_distribution) != 5:
            raise ValueError(
                f"txtype_distribution must have 5 elements, "
                f"got {len(self.txtype_distribution)}"
            )
        # Finiteness contract: no NaN / inf anywhere in the numeric payload.
        for name, seq in (
            ("feature_means", self.feature_means),
            ("feature_stds", self.feature_stds),
            ("txtype_distribution", self.txtype_distribution),
            ("daily_success_rate_series", self.daily_success_rate_series),
        ):
            for i, v in enumerate(seq):
                if not isinstance(v, float) or not math.isfinite(v):
                    raise ValueError(f"{name}[{i}] is not a finite float: {v!r}")
        # Each daily success rate is a fraction in [0, 1].
        for i, r in enumerate(self.daily_success_rate_series):
            if not (0.0 <= r <= 1.0):
                raise ValueError(
                    f"daily_success_rate_series[{i}] = {r} outside [0, 1]"
                )
        # Length contract: one rate per active day.
        if len(self.daily_success_rate_series) != self.days_with_activity:
            raise ValueError(
                f"daily_success_rate_series must have one entry per active day: "
                f"got {len(self.daily_success_rate_series)} entries vs "
                f"days_with_activity={self.days_with_activity}"
            )
        for name, v in (
            ("action_entropy", self.action_entropy),
            ("success_rate_30d", self.success_rate_30d),
        ):
            if not isinstance(v, float) or not math.isfinite(v):
                raise ValueError(f"{name} is not a finite float: {v!r}")
        # stddev cannot be negative.
        for i, s in enumerate(self.feature_stds):
            if s < 0.0:
                raise ValueError(f"feature_stds[{i}] is negative: {s}")
        # Timezone contract.
        for name, dt in (
            ("window_start", self.window_start),
            ("window_end", self.window_end),
            ("computed_at", self.computed_at),
        ):
            if dt.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware UTC")
        if self.window_end < self.window_start:
            raise ValueError("window_end must be >= window_start")
        if not isinstance(self.scoring_schema_fingerprint, str) or len(self.scoring_schema_fingerprint) != 64:
            raise ValueError("scoring_schema_fingerprint must be a 64-char hex string")
        try:
            int(self.scoring_schema_fingerprint, 16)
        except ValueError as e:
            raise ValueError("scoring_schema_fingerprint must be hex") from e

    # ─── Compatibility checks — used by the scoring engine ───────────────────

    def is_compatible_with_current_engine(self) -> bool:
        """
        True if this baseline was produced by the CURRENT algo + feature schema.
        The scoring engine calls this before using a baseline; an incompatible
        baseline must be recomputed, not used.
        """
        from features import FeatureVector
        from scoring.weights import scoring_schema_fingerprint
        return (
            self.baseline_algo_version == BASELINE_ALGO_VERSION
            and self.feature_schema_version == FEATURE_SCHEMA_VERSION
            and self.feature_schema_fingerprint == FeatureVector.feature_schema_fingerprint()
            and self.scoring_schema_fingerprint == scoring_schema_fingerprint()
        )

    def assert_compatible(self) -> None:
        """Raise IncompatibleBaselineError if not compatible with the current engine."""
        if not self.is_compatible_with_current_engine():
            raise IncompatibleBaselineError(
                f"baseline for {self.agent_wallet} is algo v{self.baseline_algo_version} / "
                f"schema v{self.feature_schema_version} "
                f"(fp {self.feature_schema_fingerprint[:12]}...); "
                f"current engine is algo v{BASELINE_ALGO_VERSION} / "
                f"schema v{FEATURE_SCHEMA_VERSION}; "
                f"scoring fp {self.scoring_schema_fingerprint[:12]}..."
            )

    @property
    def window_days(self) -> float:
        return (self.window_end - self.window_start).total_seconds() / 86400.0
