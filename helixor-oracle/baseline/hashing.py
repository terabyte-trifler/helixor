"""
baseline/hashing.py — the canonical baseline commitment hash.

The `stats_hash` is the value committed ON-CHAIN in Day 3. It must be a true
commitment: given the same agent behaviour, ANY honest oracle node — on any
machine, any Python version — computes the same 32 bytes. Three Phase-4
cluster nodes depend on this.

Achieving that requires eliminating every source of non-determinism from the
hash input:

  1. FLOAT REPRESENTATION. `0.1 + 0.2` is `0.30000000000000004` and its repr
     can differ across platforms in the last digits. FIX: every float is
     rounded to HASH_FLOAT_PRECISION decimals, then formatted with a fixed
     format string, BEFORE it enters the JSON payload.

  2. KEY ORDER. JSON object key order is insertion-order in Python but must
     not be relied on. FIX: json.dumps(..., sort_keys=True).

  3. WHITESPACE. FIX: json.dumps(..., separators=(",", ":")) — no spaces.

  4. WHAT IS HASHED. Only the fields that DEFINE the baseline:
       - baseline_algo_version
       - feature_schema_fingerprint   (covers schema version + feature names)
       - feature_means, feature_stds  (rounded)
       - txtype_distribution          (rounded)
       - action_entropy               (rounded)
       - success_rate_30d             (rounded)
     EXCLUDED: agent_wallet, window timestamps, computed_at, transaction_count,
     days_with_activity, is_provisional. Those describe the *context* of the
     baseline, not the baseline's statistical content. Two agents with
     byte-identical behaviour SHOULD produce the same stats_hash — that's a
     feature (it makes the hash a pure function of behaviour), and it's why
     agent_wallet is excluded.

This module is deliberately tiny and has ONE public function so it can be
fuzzed + property-tested in isolation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from baseline.types import HASH_FLOAT_PRECISION


def _canon_float(x: float) -> str:
    """
    Canonical string form of a float for hashing.

    Rounded to HASH_FLOAT_PRECISION decimals, then formatted with a fixed-width
    format so that 1.0, 1.00, and 0.9999999996 all collapse to the same string.
    Negative zero is normalised to "0.000000000".
    """
    rounded = round(float(x), HASH_FLOAT_PRECISION)
    # round() can still yield -0.0; normalise it.
    if rounded == 0.0:
        rounded = 0.0
    return f"{rounded:.{HASH_FLOAT_PRECISION}f}"


def _canon_float_list(xs: Sequence[float]) -> list[str]:
    return [_canon_float(x) for x in xs]


def build_hash_payload(
    *,
    baseline_algo_version:      int,
    feature_schema_fingerprint: str,
    feature_means:              Sequence[float],
    feature_stds:               Sequence[float],
    txtype_distribution:        Sequence[float],
    action_entropy:             float,
    success_rate_30d:           float,
    daily_success_rate_series:  Sequence[float],
) -> dict:
    """
    Build the canonical dict that gets hashed. Pure. Exposed (not just the
    final hash) so tests can inspect exactly what is being committed.

    All floats are pre-canonicalised to strings here, so json.dumps never
    sees a raw float.

    NOTE (Day 6 / v3): `daily_success_rate_series` is included in the
    commitment. Adding it bumps `BASELINE_ALGO_VERSION` to 3. v2 baselines
    are not silently compatible — they must be recomputed.
    """
    return {
        "v":            int(baseline_algo_version),
        "schema_fp":    str(feature_schema_fingerprint),
        "means":        _canon_float_list(feature_means),
        "stds":         _canon_float_list(feature_stds),
        "txtype_dist":  _canon_float_list(txtype_distribution),
        "action_entropy":   _canon_float(action_entropy),
        "success_rate_30d": _canon_float(success_rate_30d),
        "daily_success_rate_series": _canon_float_list(daily_success_rate_series),
    }


def compute_stats_hash(
    *,
    baseline_algo_version:      int,
    feature_schema_fingerprint: str,
    feature_means:              Sequence[float],
    feature_stds:               Sequence[float],
    txtype_distribution:        Sequence[float],
    action_entropy:             float,
    success_rate_30d:           float,
    daily_success_rate_series:  Sequence[float],
) -> str:
    """
    Compute the canonical SHA-256 commitment hash for a baseline.

    Returns 64-char lowercase hex. Deterministic: identical statistical
    content -> identical hash, on every machine.
    """
    payload = build_hash_payload(
        baseline_algo_version=baseline_algo_version,
        feature_schema_fingerprint=feature_schema_fingerprint,
        feature_means=feature_means,
        feature_stds=feature_stds,
        txtype_distribution=txtype_distribution,
        action_entropy=action_entropy,
        success_rate_30d=success_rate_30d,
        daily_success_rate_series=daily_success_rate_series,
    )
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def stats_hash_to_bytes(stats_hash_hex: str) -> bytes:
    """
    Convert the 64-char hex hash to the 32 raw bytes that go on-chain.
    Validates length + hex-ness.
    """
    if len(stats_hash_hex) != 64:
        raise ValueError(f"stats_hash must be 64 hex chars, got {len(stats_hash_hex)}")
    try:
        raw = bytes.fromhex(stats_hash_hex)
    except ValueError as e:
        raise ValueError(f"stats_hash is not valid hex: {e}") from e
    assert len(raw) == 32
    return raw
