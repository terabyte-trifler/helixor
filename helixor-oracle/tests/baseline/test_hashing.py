"""
tests/baseline/test_hashing.py — the stats_hash commitment.

The stats_hash goes ON-CHAIN. It must be a true commitment: identical
statistical content -> identical 32 bytes, on every machine. These tests are
the proof.
"""

from __future__ import annotations

import pytest

from baseline.hashing import (
    _canon_float,
    build_hash_payload,
    compute_stats_hash,
    stats_hash_to_bytes,
)
from baseline.types import HASH_FLOAT_PRECISION


def _base_kwargs(**overrides):
    """A complete, valid set of compute_stats_hash kwargs; override as needed."""
    kwargs = dict(
        baseline_algo_version=3,
        feature_schema_fingerprint="a" * 64,
        feature_means=[0.1, 0.2, 0.3],
        feature_stds=[0.01, 0.02, 0.03],
        txtype_distribution=[0.2, 0.2, 0.2, 0.2, 0.2],
        action_entropy=0.95,
        success_rate_30d=0.88,
        daily_success_rate_series=[0.95, 0.93, 0.97, 0.90, 0.95],
    )
    kwargs.update(overrides)
    return kwargs


# =============================================================================
# Float canonicalisation
# =============================================================================

class TestCanonFloat:

    def test_fixed_width_format(self):
        assert _canon_float(1.0) == f"{1.0:.{HASH_FLOAT_PRECISION}f}"
        assert _canon_float(1.0) == "1.000000000"

    def test_rounding_collapses_noise(self):
        # 0.30000000000000004 and 0.3 must canonicalise identically.
        a = _canon_float(0.1 + 0.2)
        b = _canon_float(0.3)
        assert a == b

    def test_negative_zero_normalised(self):
        assert _canon_float(-0.0) == _canon_float(0.0)
        assert _canon_float(-0.0) == "0.000000000"

    def test_tiny_difference_below_precision_collapses(self):
        # Two values differing only in the 12th decimal -> same canonical string.
        assert _canon_float(0.123456789001) == _canon_float(0.123456789002)

    def test_difference_above_precision_preserved(self):
        # Two values differing in the 8th decimal -> different canonical strings.
        assert _canon_float(0.12345678) != _canon_float(0.12345679)


# =============================================================================
# Determinism — the core commitment property
# =============================================================================

class TestDeterminism:

    def test_identical_input_identical_hash(self):
        h1 = compute_stats_hash(**_base_kwargs())
        h2 = compute_stats_hash(**_base_kwargs())
        assert h1 == h2

    def test_hash_is_64_hex_chars(self):
        h = compute_stats_hash(**_base_kwargs())
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_float_noise_does_not_change_hash(self):
        # Means with sub-precision noise must produce the SAME hash.
        clean = _base_kwargs(feature_means=[0.1, 0.2, 0.3])
        noisy = _base_kwargs(feature_means=[0.1 + 1e-15, 0.2 - 1e-15, 0.3 + 1e-14])
        assert compute_stats_hash(**clean) == compute_stats_hash(**noisy)

    def test_repeated_calls_stable(self):
        first = compute_stats_hash(**_base_kwargs())
        for _ in range(100):
            assert compute_stats_hash(**_base_kwargs()) == first


# =============================================================================
# Sensitivity — the hash MUST change when statistical content changes
# =============================================================================

class TestSensitivity:

    def test_different_means_different_hash(self):
        h1 = compute_stats_hash(**_base_kwargs(feature_means=[0.1, 0.2, 0.3]))
        h2 = compute_stats_hash(**_base_kwargs(feature_means=[0.1, 0.2, 0.4]))
        assert h1 != h2

    def test_different_stds_different_hash(self):
        h1 = compute_stats_hash(**_base_kwargs(feature_stds=[0.01, 0.02, 0.03]))
        h2 = compute_stats_hash(**_base_kwargs(feature_stds=[0.01, 0.02, 0.04]))
        assert h1 != h2

    def test_different_algo_version_different_hash(self):
        h1 = compute_stats_hash(**_base_kwargs(baseline_algo_version=2))
        h2 = compute_stats_hash(**_base_kwargs(baseline_algo_version=3))
        assert h1 != h2

    def test_different_schema_fingerprint_different_hash(self):
        h1 = compute_stats_hash(**_base_kwargs(feature_schema_fingerprint="a" * 64))
        h2 = compute_stats_hash(**_base_kwargs(feature_schema_fingerprint="b" * 64))
        assert h1 != h2

    def test_different_action_entropy_different_hash(self):
        h1 = compute_stats_hash(**_base_kwargs(action_entropy=0.95))
        h2 = compute_stats_hash(**_base_kwargs(action_entropy=0.96))
        assert h1 != h2

    def test_different_success_rate_different_hash(self):
        h1 = compute_stats_hash(**_base_kwargs(success_rate_30d=0.88))
        h2 = compute_stats_hash(**_base_kwargs(success_rate_30d=0.89))
        assert h1 != h2

    def test_means_order_matters(self):
        # The feature vector is positional — reordering means IS a different baseline.
        h1 = compute_stats_hash(**_base_kwargs(feature_means=[0.1, 0.2, 0.3]))
        h2 = compute_stats_hash(**_base_kwargs(feature_means=[0.3, 0.2, 0.1]))
        assert h1 != h2


# =============================================================================
# Payload structure
# =============================================================================

class TestPayload:

    def test_payload_keys_are_stable(self):
        payload = build_hash_payload(**_base_kwargs())
        assert set(payload.keys()) == {
            "v", "schema_fp", "means", "stds",
            "txtype_dist", "action_entropy", "success_rate_30d",
            "daily_success_rate_series",
        }

    def test_payload_floats_are_strings(self):
        # No raw float ever reaches json.dumps — all pre-canonicalised to strings.
        payload = build_hash_payload(**_base_kwargs())
        assert all(isinstance(m, str) for m in payload["means"])
        assert all(isinstance(s, str) for s in payload["stds"])
        assert isinstance(payload["action_entropy"], str)
        assert isinstance(payload["success_rate_30d"], str)
        assert all(isinstance(r, str) for r in payload["daily_success_rate_series"])

    def test_payload_excludes_context_fields(self):
        # agent_wallet, timestamps, counts are NOT in the hashed payload.
        payload = build_hash_payload(**_base_kwargs())
        for forbidden in ("agent_wallet", "computed_at", "window_start",
                          "window_end", "transaction_count", "is_provisional"):
            assert forbidden not in payload


# =============================================================================
# Hex -> bytes conversion
# =============================================================================

class TestStatsHashToBytes:

    def test_valid_hash_converts_to_32_bytes(self):
        h = compute_stats_hash(**_base_kwargs())
        raw = stats_hash_to_bytes(h)
        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_round_trip(self):
        h = compute_stats_hash(**_base_kwargs())
        assert stats_hash_to_bytes(h).hex() == h

    def test_wrong_length_rejected(self):
        with pytest.raises(ValueError, match="64 hex chars"):
            stats_hash_to_bytes("abc123")

    def test_non_hex_rejected(self):
        with pytest.raises(ValueError, match="not valid hex"):
            stats_hash_to_bytes("z" * 64)
