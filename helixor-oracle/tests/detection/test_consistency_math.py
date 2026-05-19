"""
tests/detection/test_consistency_math.py — consistency primitives + domain profiles.
"""

from __future__ import annotations

import pytest

from detection._consistency_math import (
    counterparty_outcome_consistency,
    divergence_to_health,
    jensen_shannon_divergence,
    rhythm_divergence,
)
from detection.domain_profiles import (
    DOMAIN_PROFILES,
    TXTYPE_ORDER,
    domain_profile,
    known_domains,
)


APPROX = 1e-9


# =============================================================================
# Jensen-Shannon divergence
# =============================================================================

class TestJensenShannon:

    def test_identical_distributions_zero(self):
        d = [0.25, 0.25, 0.25, 0.25]
        assert jensen_shannon_divergence(d, d) == pytest.approx(0.0, abs=1e-9)

    def test_disjoint_support_is_one(self):
        # Fully disjoint distributions → JSD = 1.0 (base-2).
        a = [1.0, 0.0, 0.0, 0.0]
        b = [0.0, 0.0, 0.0, 1.0]
        assert jensen_shannon_divergence(a, b) == pytest.approx(1.0, abs=1e-6)

    def test_symmetric(self):
        a = [0.7, 0.1, 0.1, 0.1]
        b = [0.1, 0.1, 0.1, 0.7]
        assert jensen_shannon_divergence(a, b) == pytest.approx(
            jensen_shannon_divergence(b, a), abs=APPROX,
        )

    def test_bounded_0_1(self):
        a = [0.9, 0.05, 0.03, 0.02]
        b = [0.02, 0.03, 0.05, 0.9]
        jsd = jensen_shannon_divergence(a, b)
        assert 0.0 <= jsd <= 1.0

    def test_partial_overlap_intermediate(self):
        a = [0.5, 0.5, 0.0, 0.0]
        b = [0.5, 0.0, 0.5, 0.0]
        jsd = jensen_shannon_divergence(a, b)
        assert 0.0 < jsd < 1.0

    def test_unnormalised_inputs_handled(self):
        # Raw counts, not probabilities — normalised internally.
        a = [10, 10, 10, 10]
        b = [1, 1, 1, 1]
        assert jensen_shannon_divergence(a, b) == pytest.approx(0.0, abs=1e-9)

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError, match="length mismatch"):
            jensen_shannon_divergence([0.5, 0.5], [1.0])

    def test_all_zero_is_uniform(self):
        # All-zero vectors normalise to uniform → identical → JSD 0.
        assert jensen_shannon_divergence([0, 0, 0], [0, 0, 0]) == pytest.approx(0.0)


# =============================================================================
# divergence_to_health
# =============================================================================

class TestDivergenceToHealth:

    def test_zero_divergence_healthy(self):
        assert divergence_to_health(0.0, saturation=0.6) == 1.0

    def test_saturation_zero_health(self):
        assert divergence_to_health(0.6, saturation=0.6) == 0.0

    def test_midpoint(self):
        assert divergence_to_health(0.3, saturation=0.6) == pytest.approx(0.5)

    def test_beyond_saturation_clamped(self):
        assert divergence_to_health(99.0, saturation=0.6) == 0.0


# =============================================================================
# rhythm_divergence
# =============================================================================

class TestRhythmDivergence:

    def test_identical_rhythm_zero(self):
        means = [0.5] * 13
        stds = [0.1] * 13
        assert rhythm_divergence(means, means, stds) == 0.0

    def test_shifted_rhythm_positive(self):
        means = [0.5] * 13
        stds = [0.1] * 13
        shifted = [0.9] * 13          # 4σ shift on every feature
        assert rhythm_divergence(shifted, means, stds) == pytest.approx(4.0, abs=1e-6)

    def test_direction_agnostic(self):
        means = [0.5] * 13
        stds = [0.1] * 13
        up = [0.7] * 13
        down = [0.3] * 13
        assert rhythm_divergence(up, means, stds) == pytest.approx(
            rhythm_divergence(down, means, stds), abs=1e-9,
        )

    def test_zero_variance_features_ignored(self):
        means = [0.5] * 5
        stds = [0.0] * 5
        assert rhythm_divergence([9.0] * 5, means, stds) == 0.0

    def test_clamps_lone_corrupt_feature(self):
        means = [0.5] * 4
        stds = [0.1] * 4
        # one feature corrupt at z=10000 → clamped to 12 → mean stays bounded.
        cur = [0.5, 0.5, 0.5, 1000.0]
        d = rhythm_divergence(cur, means, stds)
        assert d <= 12.0 / 4 + APPROX


# =============================================================================
# counterparty_outcome_consistency
# =============================================================================

class TestCounterpartyConsistency:

    def test_high_repeat_low_volatility_consistent(self):
        # Knows its counterparties, stable outcomes → consistent.
        c = counterparty_outcome_consistency(repeat_ratio=0.9, success_volatility=0.0)
        assert c > 0.95

    def test_high_repeat_high_volatility_inconsistent(self):
        # Knows its counterparties, erratic outcomes → inconsistent.
        c = counterparty_outcome_consistency(repeat_ratio=0.9, success_volatility=0.5)
        assert c < 0.2

    def test_low_repeat_high_volatility_excused(self):
        # New counterparties — outcome variance is expected, not penalised.
        c = counterparty_outcome_consistency(repeat_ratio=0.05, success_volatility=0.5)
        assert c > 0.9

    def test_bounded(self):
        c = counterparty_outcome_consistency(repeat_ratio=99.0, success_volatility=99.0)
        assert 0.0 <= c <= 1.0


# =============================================================================
# Domain profiles
# =============================================================================

class TestDomainProfiles:

    def test_known_domains_nonempty(self):
        assert len(known_domains()) >= 5

    def test_every_profile_is_a_distribution(self):
        for name, profile in DOMAIN_PROFILES.items():
            assert len(profile) == len(TXTYPE_ORDER)
            assert sum(profile) == pytest.approx(1.0, abs=1e-6), name
            assert all(0.0 <= p <= 1.0 for p in profile), name

    def test_lending_profile_is_lend_dominated(self):
        p = domain_profile("lending")
        lend_idx = TXTYPE_ORDER.index("lend")
        assert p[lend_idx] == max(p)

    def test_defi_trading_is_swap_dominated(self):
        p = domain_profile("defi-trading")
        swap_idx = TXTYPE_ORDER.index("swap")
        assert p[swap_idx] == max(p)

    def test_lookup_case_insensitive(self):
        assert domain_profile("LENDING") == domain_profile("lending")
        assert domain_profile("defi_trading") == domain_profile("defi-trading")
        assert domain_profile("nft marketplace") == domain_profile("nft-marketplace")

    def test_unknown_domain_returns_none(self):
        assert domain_profile("quantum-underwriting") is None

    def test_empty_domain_returns_none(self):
        assert domain_profile("") is None
