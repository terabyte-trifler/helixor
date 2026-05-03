"""
scoring/signals.py — pure baseline signal computations.

NO I/O. NO database. NO config. Just math on dataclasses.

This separation is load-bearing:
  - Tests run in microseconds (no PG, no asyncio)
  - The signal algorithms can be reasoned about, audited, version-locked
  - Day 7's scoring engine can call these on rolling windows without
    touching baseline storage

The contract: feed in TransactionRecord[], get back a Signals struct.
Same input → same output, deterministically, byte-for-byte.

Design choices:

  - **MAD instead of stdev** for SOL volatility. Standard deviation is
    sensitive to outliers — one anomalous day with 10× normal flow doubles
    the std dev. Median absolute deviation is robust: a single outlier
    barely moves it. This matters because we're computing baselines from
    real on-chain data which has occasional spikes (airdrops, liquidations).

  - **Active days only** for median_daily_tx. If an agent runs Mon-Fri
    only, including Sat/Sun zeros would artificially halve the median.
    "Daily tx count" means "tx count on days the agent was active."

  - **Integer arithmetic for SOL** — lamports are u64 on-chain. We keep
    them as Python ints (arbitrary precision) and never convert to float
    until display. Floats are forbidden in the canonical hash.

  - **abs() on sol_change** for volatility — magnitude matters for
    stability detection, not direction. (Direction matters for scoring,
    but that's Day 6.)
"""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from typing import Iterable

# =============================================================================
# Algorithm version
# =============================================================================
# Bump this whenever the baseline computation changes meaningfully.
# Consumers store this number alongside the baseline so they know which
# algorithm produced it. Old baselines are not silently re-interpreted
# under new algorithm rules.
ALGO_VERSION = 1


# =============================================================================
# Data classes
# =============================================================================

@dataclass(frozen=True, slots=True)
class TransactionRecord:
    """One transaction's relevant fields, decoupled from DB row shape."""
    block_time: datetime          # tz-aware UTC
    success:    bool
    sol_change: int               # lamports, signed
    program_ids: tuple[str, ...] = ()
    fee:        int = 0


@dataclass(frozen=True, slots=True)
class Signals:
    """The three baseline signals — frozen contract for Day 6+ consumers."""

    # Fraction of transactions that succeeded, 0.0–1.0.
    # Stored as a string with fixed precision so the hash is stable
    # across architectures (Python float repr can vary by platform).
    success_rate: float

    # Median transactions per ACTIVE day (days with ≥1 tx).
    median_daily_tx: int

    # Median absolute deviation of |daily_sol_flow| in lamports.
    # Robust alternative to standard deviation.
    sol_volatility_mad: int


@dataclass(frozen=True, slots=True)
class BaselineResult:
    """
    Full output of a baseline computation. Includes the signals plus
    metadata needed for storage, hashing, and auditability.
    """
    signals:        Signals

    # Metadata
    tx_count:       int                    # transactions analysed
    active_days:    int                    # days with ≥1 tx
    window_start:   datetime               # tz-aware UTC
    window_end:     datetime               # tz-aware UTC
    window_days:    int

    # Cryptographic commitment (Day 7 may anchor this on-chain)
    baseline_hash:  str                    # 64-char lowercase hex SHA-256
    algo_version:   int = field(default=ALGO_VERSION)


# =============================================================================
# Errors
# =============================================================================

class BaselineError(Exception):
    """Base class for all baseline computation errors."""
    pass


class InsufficientData(BaselineError):
    """Not enough transactions to compute a meaningful baseline."""
    def __init__(self, observed: int, required: int):
        self.observed = observed
        self.required = required
        super().__init__(
            f"Insufficient data: {observed} transactions, need at least {required}",
        )


class InsufficientActiveDays(BaselineError):
    """Transactions exist but on too few distinct days."""
    def __init__(self, observed: int, required: int):
        self.observed = observed
        self.required = required
        super().__init__(
            f"Insufficient active days: {observed}, need at least {required}",
        )


# =============================================================================
# Constants — thresholds documented per signal
# =============================================================================

# Minimum transactions for the success_rate to be statistically meaningful.
# Rule of thumb: with 50 trials, margin of error on a binomial proportion
# is ±~14% at 95% confidence. Below 50, we'd be reporting noise.
DEFAULT_MIN_TX_COUNT = 50

# Minimum distinct active days for median_daily_tx to be a stable estimator.
# A median over fewer than 3 days is unstable (any single day's spike
# becomes the median).
DEFAULT_MIN_ACTIVE_DAYS = 3

# Default rolling window. 30 days balances:
#   - Long enough to smooth weekly cycles + occasional bad days
#   - Short enough that an agent's behavior change shows up within a month
DEFAULT_WINDOW_DAYS = 30


# =============================================================================
# Pure computation
# =============================================================================

def compute_signals(
    transactions:      Iterable[TransactionRecord],
    *,
    window_start:      datetime,
    window_end:        datetime,
    min_tx_count:      int = DEFAULT_MIN_TX_COUNT,
    min_active_days:   int = DEFAULT_MIN_ACTIVE_DAYS,
) -> BaselineResult:
    """
    Compute the three baseline signals from a transaction list.

    Args:
        transactions:    iterable of TransactionRecord (any order is fine)
        window_start:    inclusive lower bound of the window (UTC)
        window_end:      exclusive upper bound of the window (UTC)
        min_tx_count:    minimum total tx count
        min_active_days: minimum distinct days with ≥1 tx

    Raises:
        InsufficientData       if total tx count < min_tx_count
        InsufficientActiveDays if distinct active days < min_active_days

    Returns:
        BaselineResult with deterministic baseline_hash.
    """
    # Defensive copy — caller might pass a generator
    txs = list(transactions)

    # ── Threshold check 1: total transactions ────────────────────────────────
    if len(txs) < min_tx_count:
        raise InsufficientData(len(txs), min_tx_count)

    # ── Signal 1: success_rate ───────────────────────────────────────────────
    # Bool sum is well-defined (True == 1, False == 0).
    successes  = sum(1 for tx in txs if tx.success)
    success_rate = successes / len(txs)

    # ── Group by calendar day (UTC) ───────────────────────────────────────────
    daily_count: dict[date, int] = defaultdict(int)
    daily_sol_abs: dict[date, int] = defaultdict(int)

    for tx in txs:
        # Key on the UTC date so DST and time-zone shifts don't move
        # transactions across day boundaries.
        d = tx.block_time.date()
        daily_count[d]   += 1
        daily_sol_abs[d] += abs(tx.sol_change)

    active_days = len(daily_count)

    # ── Threshold check 2: distinct active days ──────────────────────────────
    if active_days < min_active_days:
        raise InsufficientActiveDays(active_days, min_active_days)

    # ── Signal 2: median_daily_tx ────────────────────────────────────────────
    # Median over ACTIVE days only. We don't include zero-tx days because
    # an agent that runs only on weekdays shouldn't have its median halved
    # by sleep days — that's a behavioral feature, not a problem.
    # int() to keep it integer; statistics.median of int list returns float
    # for even count.
    median_daily_tx = int(statistics.median(daily_count.values()))

    # ── Signal 3: sol_volatility via MAD ─────────────────────────────────────
    # MAD = median(|x - median(x)|) over the daily |sol_change| series.
    # For a single day, MAD = 0 (the threshold check above prevents this).
    daily_sol_values = list(daily_sol_abs.values())
    median_sol = statistics.median(daily_sol_values)
    deviations = [abs(v - median_sol) for v in daily_sol_values]
    sol_volatility_mad = int(statistics.median(deviations))

    signals = Signals(
        success_rate       = round(success_rate, 6),
        median_daily_tx    = median_daily_tx,
        sol_volatility_mad = sol_volatility_mad,
    )

    # ── Canonical baseline hash ──────────────────────────────────────────────
    # The hash is over the SIGNALS only (not metadata like timestamps).
    # That way: two computations of the same data produce the same hash,
    # even if computed_at differs.
    baseline_hash = _canonical_hash(signals, algo_version=ALGO_VERSION)

    return BaselineResult(
        signals       = signals,
        tx_count      = len(txs),
        active_days   = active_days,
        window_start  = window_start,
        window_end    = window_end,
        window_days   = (window_end - window_start).days,
        baseline_hash = baseline_hash,
        algo_version  = ALGO_VERSION,
    )


def _canonical_hash(signals: Signals, *, algo_version: int) -> str:
    """
    Stable SHA-256 over the signals + algo version.

    Why this is fiddly:
      - Python's `repr(float)` can vary across platforms in edge cases
      - JSON serialisation order matters
      - Whitespace matters

    We freeze on:
      - JSON with sort_keys=True
      - Compact separators (no spaces)
      - 6 decimal places for success_rate (matches Signals contract)
      - Integers passed through as-is
      - Algorithm version included (different algo → different hash even
        on identical signals)
    """
    canonical = {
        "algo_version":       int(algo_version),
        "median_daily_tx":    int(signals.median_daily_tx),
        "sol_volatility_mad": int(signals.sol_volatility_mad),
        "success_rate":       f"{signals.success_rate:.6f}",  # str avoids float repr drift
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# =============================================================================
# Convenience: serialise BaselineResult for logging / API
# =============================================================================

def baseline_to_dict(result: BaselineResult) -> dict:
    """Flatten BaselineResult into a plain dict (e.g. for JSON logging)."""
    return {
        "success_rate":       result.signals.success_rate,
        "median_daily_tx":    result.signals.median_daily_tx,
        "sol_volatility_mad": result.signals.sol_volatility_mad,
        "tx_count":           result.tx_count,
        "active_days":        result.active_days,
        "window_start":       result.window_start.isoformat(),
        "window_end":         result.window_end.isoformat(),
        "window_days":        result.window_days,
        "baseline_hash":      result.baseline_hash,
        "algo_version":       result.algo_version,
    }
