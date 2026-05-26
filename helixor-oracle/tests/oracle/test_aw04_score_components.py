"""
tests/oracle/test_aw04_score_components.py — AW-04 canonical serializer.

THE CONTRACT UNDER TEST
-----------------------
`oracle/score_components.py` produces the canonical-JSON payload bytes
that get published in the on-chain `ScoreComponentsAccount`. The bytes
must be:

  1. Byte-deterministic across runs (sorted keys, no whitespace).
  2. Decoded to a dict that carries every documented schema-v1 field.
  3. Hashable to a 32-byte SHA-256 (`score_components_hash`).
  4. Replay-consistent: sum(dims[i].contrib) -> clamp(0,1000) ->
     delta_guard(previous_score) == cert.score.
  5. Refused at the writer level if the bytes exceed
     MAX_SCORE_COMPONENTS_PAYLOAD_LEN (a serializer regression).

Properties this file pins:
  - `_canon_float` rounds to 9 decimals, normalises -0.0.
  - `build_score_components_payload` carries every required key.
  - `serialize_score_components` is byte-identical on repeat calls.
  - `serialize_score_components` keys are alphabetically sorted in the
    raw JSON text (the on-chain hash binding depends on this).
  - `serialize_score_components` rejects oversized payloads.
  - `score_components_hash` returns 32 bytes.
  - `build_components_and_hash` produces matching bytes + sha256.
  - `previous_score` round-trips through
    `build_score_components_with_previous`.
  - The replay arithmetic baked into the payload matches the composite
    scorer's actual output.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from baseline import compute_baseline
from detection.types import DIMENSION_MAX_SCORES, DimensionId, DimensionResult, FlagBit
from features import ExtractionWindow, Transaction
from scoring import compute_composite_score
from scoring._gaming import MAX_SCORE_DELTA, apply_delta_guard_rail

from oracle.score_components import (
    MAX_SCORE_COMPONENTS_PAYLOAD_LEN,
    SCORE_COMPONENTS_SCHEMA_VERSION,
    _canon_float,
    build_components_and_hash,
    build_score_components_payload,
    build_score_components_with_previous,
    score_components_hash,
    serialize_score_components,
)


REF_TIME = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Real ScoreResult builder — mirrors tests/scoring/conftest.py::baseline
# =============================================================================

def _real_baseline():
    txs = []
    for day in range(30):
        for k in range(5):
            idx = day * 5 + k
            txs.append(Transaction(
                signature=f"S{idx:08d}".ljust(64, "x"),
                slot=100_000_000 + idx,
                block_time=REF_TIME - timedelta(hours=day * 24 + k * 2 + 1.0),
                success=(idx % 20) != 0,
                program_ids=("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",),
                sol_change=1_000_000 if k % 2 == 0 else -400_000,
                fee=5000,
                priority_fee=0,
                compute_units=200_000,
                counterparty=f"cp{idx % 7}",
            ))
    return compute_baseline(
        "11111111111111111111111111111112", txs,
        ExtractionWindow.ending_at(REF_TIME, days=30),
        computed_at=REF_TIME,
    )


def _dim_results(
    *, drift=200, anomaly=200, performance=200, consistency=200, security=150,
    immediate_red=False,
) -> dict[DimensionId, DimensionResult]:
    flags_red = int(FlagBit.IMMEDIATE_RED) if immediate_red else 0
    return {
        DimensionId.DRIFT: DimensionResult(
            dimension=DimensionId.DRIFT, score=drift,
            max_score=DIMENSION_MAX_SCORES[DimensionId.DRIFT],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.ANOMALY: DimensionResult(
            dimension=DimensionId.ANOMALY, score=anomaly,
            max_score=DIMENSION_MAX_SCORES[DimensionId.ANOMALY],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.PERFORMANCE: DimensionResult(
            dimension=DimensionId.PERFORMANCE, score=performance,
            max_score=DIMENSION_MAX_SCORES[DimensionId.PERFORMANCE],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.CONSISTENCY: DimensionResult(
            dimension=DimensionId.CONSISTENCY, score=consistency,
            max_score=DIMENSION_MAX_SCORES[DimensionId.CONSISTENCY],
            flags=0, sub_scores={}, algo_version=1,
        ),
        DimensionId.SECURITY: DimensionResult(
            dimension=DimensionId.SECURITY, score=security,
            max_score=DIMENSION_MAX_SCORES[DimensionId.SECURITY],
            flags=flags_red, sub_scores={}, algo_version=1,
        ),
    }


def _score_result(**kwargs):
    return compute_composite_score(
        _dim_results(**kwargs),
        _real_baseline(),
        computed_at=REF_TIME,
    )


# =============================================================================
# _canon_float — fixed precision, -0.0 normalisation
# =============================================================================

class TestCanonFloat:

    def test_returns_string_with_9_decimals(self):
        # The canonical float form is f"{rounded:.9f}".
        out = _canon_float(0.123456789012345)
        assert isinstance(out, str)
        # exactly one dot, exactly 9 digits to the right.
        i, _, f = out.partition(".")
        assert len(f) == 9, out

    def test_collapses_negative_zero(self):
        # -0.0 must not survive — IEEE 754 distinguishes -0.0 from 0.0,
        # which would otherwise leak into the canonical bytes.
        assert _canon_float(-0.0) == _canon_float(0.0)
        assert _canon_float(-0.0) == "0.000000000"

    def test_round_to_9_decimals(self):
        # The 10th digit is dropped via banker's rounding.
        # 0.1234567894 -> 0.123456789 (10th digit < 5)
        assert _canon_float(0.1234567894) == "0.123456789"

    def test_same_value_same_string(self):
        a = _canon_float(0.42)
        b = _canon_float(0.42)
        assert a == b


# =============================================================================
# build_score_components_payload — required keys, replay-consistent
# =============================================================================

class TestPayloadShape:

    REQUIRED_KEYS = {
        "v", "algo_v", "weights_v", "score", "raw_score", "delta_clamped",
        "previous_score", "alert", "immediate_red", "agg_flags", "confidence",
        "gaming", "gaming_drop", "dims",
    }
    DIM_REQUIRED_KEYS = {"id", "norm", "flags", "algo_v", "contrib"}

    def test_payload_carries_every_required_key(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        assert set(payload.keys()) == self.REQUIRED_KEYS

    def test_schema_version_pinned_to_v1(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        assert payload["v"] == SCORE_COMPONENTS_SCHEMA_VERSION == 1

    def test_dims_list_has_five_entries_in_canonical_order(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        dims = payload["dims"]
        assert len(dims) == 5
        # Output ORDER mirrors DimensionId.ordered() — drift, anomaly,
        # performance, consistency, security. JSON sort_keys does NOT
        # reorder list elements, so consumers can index positionally.
        assert [d["id"] for d in dims] == [
            DimensionId.DRIFT.value,
            DimensionId.ANOMALY.value,
            DimensionId.PERFORMANCE.value,
            DimensionId.CONSISTENCY.value,
            DimensionId.SECURITY.value,
        ]

    def test_each_dim_carries_every_required_key(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        for d in payload["dims"]:
            assert set(d.keys()) == self.DIM_REQUIRED_KEYS

    def test_raw_score_equals_sum_of_dim_contribs(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        contrib_sum = sum(int(d["contrib"]) for d in payload["dims"])
        assert payload["raw_score"] == contrib_sum

    def test_replay_arithmetic_matches_score(self):
        # The replay contract: sum -> clamp -> delta_guard(None on first
        # scoring) == cert.score. This is exactly what the SDK verifier
        # re-executes.
        result = _score_result()
        payload = build_score_components_payload(result)

        contrib_sum = sum(int(d["contrib"]) for d in payload["dims"])
        clamped = max(0, min(1000, contrib_sum))
        rail = apply_delta_guard_rail(
            new_score=clamped,
            previous_score=payload["previous_score"],
        )
        assert rail["score"] == payload["score"]


# =============================================================================
# build_score_components_with_previous
# =============================================================================

class TestPreviousScoreThreading:

    def test_previous_score_round_trips(self):
        result = _score_result()
        payload = build_score_components_with_previous(
            result, previous_score=650,
        )
        assert payload["previous_score"] == 650

    def test_previous_score_none_stays_none(self):
        result = _score_result()
        payload = build_score_components_with_previous(
            result, previous_score=None,
        )
        assert payload["previous_score"] is None

    def test_previous_score_out_of_range_rejected(self):
        result = _score_result()
        with pytest.raises(ValueError):
            build_score_components_with_previous(result, previous_score=-1)
        with pytest.raises(ValueError):
            build_score_components_with_previous(result, previous_score=1001)


# =============================================================================
# serialize_score_components — byte-canonical form
# =============================================================================

class TestSerialiseCanonical:

    def test_serialise_returns_bytes(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        raw = serialize_score_components(payload)
        assert isinstance(raw, bytes)

    def test_serialise_is_deterministic(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        a = serialize_score_components(payload)
        b = serialize_score_components(payload)
        # Byte-identical on repeat calls — the threshold signature
        # cluster depends on this.
        assert a == b

    def test_serialise_has_no_whitespace(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        raw = serialize_score_components(payload)
        text = raw.decode("utf-8")
        # No spaces or newlines outside string literals: the canonical
        # form uses separators=(",", ":") which removes ALL whitespace.
        # Spot-check on the top-level structure.
        assert ", " not in text
        assert ": " not in text
        assert "\n" not in text

    def test_serialise_keys_are_alphabetical_at_top_level(self):
        # Sorted keys are the AW-04 hash binding's foundation — they
        # MUST be alphabetised by `json.dumps(sort_keys=True)`. A
        # serializer change that breaks this would silently break the
        # on-chain hash binding.
        result = _score_result()
        payload = build_score_components_payload(result)
        raw = serialize_score_components(payload).decode("utf-8")
        # Walk the top-level keys from the raw text by stripping
        # everything except the outermost dict.
        # Reparse with the standard parser, then re-encode with
        # sort_keys=True and compare bytes.
        obj = json.loads(raw)
        sorted_form = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        assert raw == sorted_form

    def test_serialise_rejects_oversized_payload(self):
        # The 4 KB ceiling guards against a serializer regression that
        # would otherwise pass an over-budget payload to the on-chain
        # write (where it would silently exceed the account size).
        result = _score_result()
        payload = build_score_components_payload(result)
        # Inflate the payload past the limit by stuffing a long string.
        payload["__overflow__"] = "x" * (MAX_SCORE_COMPONENTS_PAYLOAD_LEN + 100)
        with pytest.raises(ValueError, match="exceeds"):
            serialize_score_components(payload)


# =============================================================================
# score_components_hash + build_components_and_hash
# =============================================================================

class TestComponentsHash:

    def test_hash_is_32_bytes(self):
        result = _score_result()
        payload = build_score_components_payload(result)
        raw = serialize_score_components(payload)
        h = score_components_hash(raw)
        assert isinstance(h, bytes)
        assert len(h) == 32

    def test_hash_matches_sha256_of_payload(self):
        # Pin the exact wire contract: the on-chain handler MUST be able
        # to re-derive the hash by running sha256 over the account's
        # payload bytes. This pins the off-chain side of that contract.
        result = _score_result()
        payload = build_score_components_payload(result)
        raw = serialize_score_components(payload)
        assert score_components_hash(raw) == hashlib.sha256(raw).digest()

    def test_build_components_and_hash_returns_consistent_pair(self):
        result = _score_result()
        raw, h = build_components_and_hash(result, previous_score=None)
        assert isinstance(raw, bytes) and isinstance(h, bytes)
        assert len(h) == 32
        assert hashlib.sha256(raw).digest() == h

    def test_different_inputs_different_hashes(self):
        # Tampering with the dim contribs MUST change the hash —
        # this is the AW-04 catch in action.
        result_a = _score_result(drift=200, anomaly=200,
                                  performance=200, consistency=200,
                                  security=150)  # all max
        result_b = _score_result(drift=100, anomaly=200,
                                  performance=200, consistency=200,
                                  security=150)  # different drift
        _, h_a = build_components_and_hash(result_a, previous_score=None)
        _, h_b = build_components_and_hash(result_b, previous_score=None)
        assert h_a != h_b
