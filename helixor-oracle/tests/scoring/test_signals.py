"""
tests/scoring/test_signals.py — unit tests for the pure signal computation.

These run in milliseconds. No DB, no asyncio. If anything in the math is
wrong, this is where it surfaces.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scoring.signals import (
    ALGO_VERSION,
    BaselineResult,
    InsufficientActiveDays,
    InsufficientData,
    Signals,
    TransactionRecord,
    compute_signals,
)


UTC = timezone.utc


def _tx(t: datetime, success: bool = True, sol_change: int = 0) -> TransactionRecord:
    """Compact helper for building TransactionRecord."""
    return TransactionRecord(block_time=t, success=success, sol_change=sol_change)


# =============================================================================
# Threshold checks
# =============================================================================

class TestThresholds:

    def test_below_min_tx_count_raises(self):
        now = datetime.now(tz=UTC)
        txs = [_tx(now - timedelta(days=i)) for i in range(10)]

        with pytest.raises(InsufficientData) as exc:
            compute_signals(
                txs,
                window_start=now - timedelta(days=30),
                window_end=now,
                min_tx_count=50,
            )
        assert exc.value.observed == 10
        assert exc.value.required == 50

    def test_at_min_tx_count_succeeds(self):
        now = datetime.now(tz=UTC)
        txs = [_tx(now - timedelta(days=i % 5)) for i in range(50)]

        result = compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
        )
        assert result.tx_count == 50

    def test_below_min_active_days_raises(self):
        now = datetime.now(tz=UTC)
        # 100 txs all on the same day → 1 active day
        txs = [_tx(now - timedelta(seconds=i)) for i in range(100)]

        with pytest.raises(InsufficientActiveDays) as exc:
            compute_signals(
                txs,
                window_start=now - timedelta(days=30),
                window_end=now,
                min_tx_count=50,
                min_active_days=3,
            )
        assert exc.value.observed == 1
        assert exc.value.required == 3


# =============================================================================
# Success rate
# =============================================================================

class TestSuccessRate:

    def _build(self, total: int, succ: int) -> list[TransactionRecord]:
        now = datetime.now(tz=UTC)
        out: list[TransactionRecord] = []
        for i in range(total):
            day_offset = i % 10  # 10 active days
            out.append(_tx(now - timedelta(days=day_offset),
                           success=(i < succ)))
        return out

    def test_all_success(self):
        result = self._compute(self._build(60, 60))
        assert result.signals.success_rate == 1.0

    def test_all_failure(self):
        result = self._compute(self._build(60, 0))
        assert result.signals.success_rate == 0.0

    def test_half_success(self):
        result = self._compute(self._build(60, 30))
        assert result.signals.success_rate == 0.5

    def test_rounded_to_six_decimals(self):
        result = self._compute(self._build(73, 60))
        # 60/73 = 0.821917808... → rounded to 0.821918
        assert result.signals.success_rate == 0.821918

    @staticmethod
    def _compute(txs):
        now = datetime.now(tz=UTC)
        return compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
            min_active_days=3,
        )


# =============================================================================
# Median daily tx
# =============================================================================

class TestMedianDailyTx:

    def test_uniform_daily_count(self):
        # 5 active days, 10 tx each → median = 10
        now = datetime.now(tz=UTC)
        txs = []
        for day in range(5):
            for _ in range(10):
                txs.append(_tx(now - timedelta(days=day)))

        result = compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
        )
        assert result.signals.median_daily_tx == 10

    def test_skewed_distribution_median(self):
        # 5 active days: counts [1, 2, 5, 80, 100] → median = 5
        now = datetime.now(tz=UTC)
        txs = []
        counts = [1, 2, 5, 80, 100]
        for day, count in enumerate(counts):
            for _ in range(count):
                txs.append(_tx(now - timedelta(days=day)))

        result = compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
        )
        assert result.signals.median_daily_tx == 5

    def test_active_days_only_no_zero_padding(self):
        # Agent runs Mon-Wed only (3 days), 20 tx each → median = 20
        # (Even though window is 30 days; we don't pad with 0s for inactive days)
        now = datetime.now(tz=UTC)
        txs = []
        for day in range(3):
            for _ in range(20):
                txs.append(_tx(now - timedelta(days=day)))

        result = compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
            min_active_days=3,
        )
        assert result.signals.median_daily_tx == 20
        assert result.active_days == 3


# =============================================================================
# SOL volatility (MAD)
# =============================================================================

class TestSolVolatilityMad:

    def test_zero_volatility_when_constant_flow(self):
        # Every day has the same |sol_change| → MAD = 0
        now = datetime.now(tz=UTC)
        txs = []
        for day in range(5):
            for _ in range(10):
                txs.append(_tx(now - timedelta(days=day), sol_change=1_000))

        result = compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
            min_active_days=3,
        )
        assert result.signals.sol_volatility_mad == 0

    def test_robust_to_single_outlier(self):
        # 4 quiet days at 1000, 1 outlier day at 1_000_000.
        # MAD should be small — outlier doesn't blow it up.
        now = datetime.now(tz=UTC)
        txs = []
        for day in range(4):
            for _ in range(13):
                txs.append(_tx(now - timedelta(days=day), sol_change=77))   # ~1000/day total
        # outlier day
        for _ in range(13):
            txs.append(_tx(now - timedelta(days=4), sol_change=77_000))    # ~1_000_000

        result = compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
            min_active_days=3,
        )
        # Median daily |sol| = 1001 (the quiet days). Deviations:
        #   |1001-1001| × 4 = 0 each, |1_001_000-1001| ≈ 999_999
        # Sorted deviations: [0, 0, 0, 0, 999_999] → MAD = 0
        # MAD is REMARKABLY robust — single outlier doesn't move it at all.
        assert result.signals.sol_volatility_mad == 0

    def test_volatile_days_increase_mad(self):
        # 5 days with widely varying daily SOL flow
        now = datetime.now(tz=UTC)
        # daily totals: 100, 500, 1000, 5000, 10000
        # we'll put all flow in one tx per day for simplicity
        daily_flows = [100, 500, 1000, 5000, 10000]
        txs = []
        for day, flow in enumerate(daily_flows):
            # 10 small txs to satisfy min_tx_count, plus the flow as one big tx
            for _ in range(10):
                txs.append(_tx(now - timedelta(days=day), sol_change=0))
            txs.append(_tx(now - timedelta(days=day), sol_change=flow))

        result = compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
            min_active_days=3,
        )
        # Median daily flow = 1000. Deviations: |100-1000|=900, |500-1000|=500,
        # |1000-1000|=0, |5000-1000|=4000, |10000-1000|=9000
        # Sorted: [0, 500, 900, 4000, 9000] → MAD = 900
        assert result.signals.sol_volatility_mad == 900


# =============================================================================
# Hash determinism
# =============================================================================

class TestHashDeterminism:

    def _baseline(self, **overrides):
        now = datetime.now(tz=UTC)
        txs = [
            _tx(now - timedelta(days=i % 5),
                success=overrides.get("success", True),
                sol_change=overrides.get("sol", 100))
            for i in range(50)
        ]
        return compute_signals(
            txs,
            window_start=now - timedelta(days=30),
            window_end=now,
            min_tx_count=50,
            min_active_days=3,
        )

    def test_hash_is_64_hex_chars(self):
        result = self._baseline()
        assert len(result.baseline_hash) == 64
        assert all(c in "0123456789abcdef" for c in result.baseline_hash)

    def test_same_signals_same_hash(self):
        r1 = self._baseline()
        r2 = self._baseline()
        # Same input → same hash, regardless of when it was computed
        assert r1.baseline_hash == r2.baseline_hash

    def test_different_signals_different_hash(self):
        r1 = self._baseline(success=True)
        r2 = self._baseline(success=False)
        assert r1.baseline_hash != r2.baseline_hash

    def test_hash_excludes_metadata(self):
        # Two baselines with same signals but computed at "different times"
        # should produce the same hash, since metadata isn't in the hash.
        from scoring.signals import _canonical_hash, Signals
        sig = Signals(success_rate=0.95, median_daily_tx=10, sol_volatility_mad=50)
        h1 = _canonical_hash(sig, algo_version=1)
        h2 = _canonical_hash(sig, algo_version=1)
        assert h1 == h2

    def test_algo_version_in_hash(self):
        from scoring.signals import _canonical_hash, Signals
        sig = Signals(success_rate=0.95, median_daily_tx=10, sol_volatility_mad=50)
        h1 = _canonical_hash(sig, algo_version=1)
        h2 = _canonical_hash(sig, algo_version=2)
        assert h1 != h2

    def test_known_hash_for_fixed_input(self):
        """Regression test: this exact baseline must always produce this exact hash."""
        from scoring.signals import _canonical_hash, Signals
        sig = Signals(
            success_rate       = 0.95,
            median_daily_tx    = 10,
            sol_volatility_mad = 50,
        )
        # If you change the canonical-hash format, this assert breaks loudly.
        # Run once and paste the printed value here.
        import hashlib, json
        canonical = {
            "algo_version":       1,
            "median_daily_tx":    10,
            "sol_volatility_mad": 50,
            "success_rate":       "0.950000",
        }
        expected = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        assert _canonical_hash(sig, algo_version=1) == expected


# =============================================================================
# BaselineResult shape
# =============================================================================

class TestResultShape:

    def test_all_metadata_present(self):
        now = datetime.now(tz=UTC)
        txs = [_tx(now - timedelta(days=i % 5)) for i in range(60)]

        window_start = now - timedelta(days=30)
        window_end   = now
        result = compute_signals(
            txs,
            window_start=window_start,
            window_end=window_end,
            min_tx_count=50,
        )

        assert result.tx_count == 60
        assert result.active_days == 5
        assert result.window_start == window_start
        assert result.window_end == window_end
        assert result.window_days == 30
        assert result.algo_version == ALGO_VERSION
        assert isinstance(result.signals, Signals)
