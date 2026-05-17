"""
tests/detection/test_security_integrity.py — integrity + directed-threat checks.
"""

from __future__ import annotations

import pytest

from detection._security_integrity import (
    behavioural_fingerprint,
    check_integrity,
    directed_threat_score,
    fingerprint_divergence,
)


# =============================================================================
# behavioural_fingerprint
# =============================================================================

class TestBehaviouralFingerprint:

    def test_deterministic(self):
        v = [0.1, 0.2, 0.3]
        assert behavioural_fingerprint(v) == behavioural_fingerprint(v)

    def test_64_hex_chars(self):
        fp = behavioural_fingerprint([0.5] * 100)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_quantisation_absorbs_tiny_noise(self):
        # Noise below the 3rd decimal must not change the fingerprint.
        a = behavioural_fingerprint([0.1234, 0.5678])
        b = behavioural_fingerprint([0.1234 + 1e-7, 0.5678 - 1e-7])
        assert a == b

    def test_real_change_changes_fingerprint(self):
        a = behavioural_fingerprint([0.10, 0.20])
        b = behavioural_fingerprint([0.10, 0.99])
        assert a != b


# =============================================================================
# fingerprint_divergence
# =============================================================================

class TestFingerprintDivergence:

    def test_identical_is_zero(self):
        means = [0.5] * 10
        stds = [0.1] * 10
        assert fingerprint_divergence(means, means, stds) == 0.0

    def test_all_shifted_is_one(self):
        means = [0.5] * 10
        stds = [0.1] * 10
        shifted = [10.0] * 10           # far outside 3σ
        assert fingerprint_divergence(shifted, means, stds) == 1.0

    def test_partial_shift(self):
        means = [0.5] * 10
        stds = [0.1] * 10
        # 3 of 10 features shifted out of 3σ.
        cur = [0.5] * 7 + [10.0] * 3
        assert fingerprint_divergence(cur, means, stds) == pytest.approx(0.3)

    def test_zero_variance_features_ignored(self):
        means = [0.5] * 5
        stds = [0.0] * 5                # zero variance → no signal
        cur = [99.0] * 5
        assert fingerprint_divergence(cur, means, stds) == 0.0

    def test_length_mismatch_is_zero(self):
        assert fingerprint_divergence([0.5], [0.5, 0.5], [0.1, 0.1]) == 0.0


# =============================================================================
# check_integrity
# =============================================================================

class TestCheckIntegrity:

    def _clean_args(self, **over):
        args = dict(
            declared_code_hash="HASH_X",
            baseline_recorded_hash="HASH_X",
            current_values=[0.5] * 10,
            baseline_means=[0.5] * 10,
            baseline_stds=[0.1] * 10,
        )
        args.update(over)
        return args

    def test_matching_hash_clean_behaviour_intact(self):
        v = check_integrity(**self._clean_args())
        assert not v.violated
        assert v.health == 1.0

    def test_hash_mismatch_is_violation(self):
        v = check_integrity(**self._clean_args(
            declared_code_hash="HASH_A", baseline_recorded_hash="HASH_B",
        ))
        assert v.violated
        assert v.hash_mismatch
        assert v.health == 0.0

    def test_hidden_swap_detected(self):
        # Hash unchanged, but behaviour sharply diverged → hidden swap.
        v = check_integrity(**self._clean_args(
            current_values=[10.0] * 10,         # every feature far out
        ))
        assert v.violated
        assert v.behaviour_diverged
        assert v.health < 1.0

    def test_no_hashes_is_noop_on_hash_arm(self):
        # No code_hash declared at all → hash arm cannot fire.
        v = check_integrity(**self._clean_args(
            declared_code_hash="", baseline_recorded_hash="",
        ))
        assert not v.hash_mismatch

    def test_small_divergence_not_a_swap(self):
        # 1 of 10 features shifted — below the swap threshold.
        v = check_integrity(**self._clean_args(
            current_values=[0.5] * 9 + [10.0],
        ))
        assert not v.behaviour_diverged


# =============================================================================
# directed_threat_score
# =============================================================================

class TestDirectedThreatScore:

    def test_all_zero_is_zero(self):
        assert directed_threat_score(
            new_program_rate=0.0, counterparty_churn=0.0,
            net_outflow_fraction=0.0, authority_op_fraction=0.0,
        ) == 0.0

    def test_outflow_alone_is_benign(self):
        # High outflow but no new code / churn / authority → not a threat shape.
        s = directed_threat_score(
            new_program_rate=0.0, counterparty_churn=0.0,
            net_outflow_fraction=1.0, authority_op_fraction=0.0,
        )
        assert s == 0.0

    def test_new_programs_alone_is_benign(self):
        # Capability rollout with no outflow → benign.
        s = directed_threat_score(
            new_program_rate=1.0, counterparty_churn=0.0,
            net_outflow_fraction=0.0, authority_op_fraction=0.0,
        )
        assert s == 0.0

    def test_drain_shape_detected(self):
        # New programs + value outflow co-occurring → the drain shape.
        s = directed_threat_score(
            new_program_rate=0.9, counterparty_churn=0.0,
            net_outflow_fraction=0.9, authority_op_fraction=0.0,
        )
        assert s > 0.5

    def test_privilege_shape_detected(self):
        # Authority ops + outflow → privilege-then-drain.
        s = directed_threat_score(
            new_program_rate=0.0, counterparty_churn=0.0,
            net_outflow_fraction=0.9, authority_op_fraction=0.9,
        )
        assert s > 0.5

    def test_score_bounded(self):
        s = directed_threat_score(
            new_program_rate=99.0, counterparty_churn=99.0,
            net_outflow_fraction=99.0, authority_op_fraction=99.0,
        )
        assert 0.0 <= s <= 1.0

    def test_nan_handled(self):
        s = directed_threat_score(
            new_program_rate=float("nan"), counterparty_churn=0.5,
            net_outflow_fraction=0.5, authority_op_fraction=0.5,
        )
        assert 0.0 <= s <= 1.0
