"""
oracle/score_components.py — AW-04 canonical score-components payload.

THE AUDIT FINDING
-----------------
AW-04 (Scoring Engine is a Black Box). Pre-AW-04 the cert carried only
the FINAL score (0-1000) + flags (u32). A consumer that wanted to know
WHY the score was 750 had to trust the cluster's claim — there was no
on-chain breakdown of which detector contributed what, and a malicious
cluster could publish any score it wanted without an auditable trail.

THE FIX
-------
Each cert is paired with a `ScoreComponentsAccount` PDA at
`["score_components", agent_wallet, epoch_le]` whose payload is the
canonical-JSON serialisation produced here. The on-chain handler
enforces `sha256(payload) == score_components_hash` at write time, and
the cluster-signed `cert_payload_digest` folds `score_components_hash`
in alongside the cert fields. A third party can:

  1. Fetch `cert.scoreComponentsHash` from the cert payload digest
     ingredients (the SDK exposes it as a cert field on layout v7).
  2. Derive the components PDA and fetch the payload bytes.
  3. Verify `sha256(payload) == score_components_hash`.
  4. Parse the canonical JSON.
  5. Verify `sum(dims[i].contrib) == raw_score`, then apply the
     documented delta-guard-rail + clamp to get `final_score`, then
     compare to `cert.score`. Mismatch = the cluster published a
     wrong score and was caught by an on-chain hash.

THE CANONICAL FORM
------------------
`json.dumps(payload, sort_keys=True, separators=(",", ":"))` produces
byte-identical output on every Python interpreter for the same `dict`.
Floats are pre-canonicalised to fixed-precision strings (mirrors
`baseline/hashing.py:_canon_float`) — IEEE-754 reprs differ between
platforms in the trailing digits.

THE PAYLOAD SHAPE (schema v1)
-----------------------------
{
  "v":              1,
  "algo_v":         <SCORING_ALGO_VERSION at compute time>,
  "weights_v":      <SCORING_WEIGHTS_VERSION at compute time>,
  "score":          <int 0..1000 — final, post-clamp post-delta-guard>,
  "raw_score":      <int — sum(dims[i].contrib), pre-clamp pre-guard>,
  "delta_clamped":  <bool — was the 200-pt rail enforced>,
  "previous_score": <int|null — input to the delta guard rail>,
  "alert":          "GREEN" | "YELLOW" | "RED",
  "immediate_red":  <bool>,
  "agg_flags":      <int — u32 aggregated_flags>,
  "confidence":     <int 0..1000>,
  "gaming":         <bool — gaming_detected>,
  "gaming_drop":    <str   — _canon_float(gaming_drop_fraction)>,
  "dims": [
    {"id": "drift",       "norm": "<str>", "flags": <int>, "algo_v": <int>, "contrib": <int>},
    {"id": "anomaly",     "norm": "<str>", "flags": <int>, "algo_v": <int>, "contrib": <int>},
    {"id": "performance", "norm": "<str>", "flags": <int>, "algo_v": <int>, "contrib": <int>},
    {"id": "consistency", "norm": "<str>", "flags": <int>, "algo_v": <int>, "contrib": <int>},
    {"id": "security",    "norm": "<str>", "flags": <int>, "algo_v": <int>, "contrib": <int>}
  ]
}

Members are ordered by `DimensionId.ordered()` — the canonical scoring
order. The list is OUTPUT-ORDERED (`json.dumps(sort_keys=True)` does
not reorder list elements, only dict keys), so the consumer can index
positionally if they prefer.

CALLERS
-------
- `oracle.cluster.pipeline` — builds the payload at cert-signing time
  from the `ScoreResult` and serializes it for inclusion in the
  `ScoreComponentsAccount` write.
- `oracle.cluster.cert_signing.cert_payload_digest` — receives the
  resulting 32-byte SHA-256 as `score_components_hash`.
- Tests + audit gate — use the same builder so the canonical form is
  exercised in CI.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scoring.composite import ScoreResult


# =============================================================================
# Constants
# =============================================================================

# Schema version. v1 = AW-04 initial. Bump on any canonical-form change.
SCORE_COMPONENTS_SCHEMA_VERSION = 1

# Float canonicalisation precision. Matches baseline/hashing.py so the two
# off-chain serializers use the same float→str discipline. Nine decimals
# is finer than the 0-1000 integer score resolution — plenty of headroom.
_FLOAT_PRECISION = 9

# Max payload length the on-chain `ScoreComponentsAccount` accepts. Real
# payloads run < 1 KB (five fixed-shape dim entries + a handful of scalars);
# 4 KB is the safety ceiling. Anything larger means a serializer regression
# or an attempt to stuff extra fields — the writer should be refused so
# the issue surfaces.
MAX_SCORE_COMPONENTS_PAYLOAD_LEN = 4096


# =============================================================================
# Float canonicalisation
# =============================================================================

def _canon_float(x: float) -> str:
    """
    Canonical string form of a float for hashing. Mirrors
    `baseline/hashing.py:_canon_float` — rounded to fixed precision,
    formatted with a fixed-width format, negative zero normalised.
    """
    rounded = round(float(x), _FLOAT_PRECISION)
    if rounded == 0.0:
        rounded = 0.0  # collapse -0.0
    return f"{rounded:.{_FLOAT_PRECISION}f}"


# =============================================================================
# Build the canonical payload dict
# =============================================================================

def build_score_components_payload(result: "ScoreResult") -> dict[str, Any]:
    """
    Build the canonical-form `dict` that gets serialised. Pure: same
    `ScoreResult` -> byte-identical dict structure.

    The consumer's strict score-replay check is:
      raw_score = sum(d["contrib"] for d in dims)
      final = apply_delta_guard_rail(clamp(0, 1000, raw_score), previous_score)
      assert final == cert.score
    """
    # Local import — composite.py imports this module via pipeline.py and we
    # would create a load-time cycle otherwise.
    from detection.types import DimensionId
    from scoring.composite import AlertTier

    # `raw_score` is the PRE-clamp PRE-delta-guard sum of per-dim contribs.
    # `weighted_contributions` already excludes any clamp/guard effects
    # because the composite stores them PRE-clamp.
    contribs = result.weighted_contributions
    raw_score = sum(contribs[dim] for dim in DimensionId.ordered())

    dims_list = []
    for dim in DimensionId.ordered():
        dim_result = result.dimension_results[dim]
        dims_list.append({
            "id":       dim.value,
            "norm":     _canon_float(dim_result.score_normalised),
            "flags":    int(dim_result.flags),
            "algo_v":   int(result.detector_algo_versions[dim]),
            "contrib":  int(contribs[dim]),
        })

    payload: dict[str, Any] = {
        "v":              SCORE_COMPONENTS_SCHEMA_VERSION,
        "algo_v":         int(result.scoring_algo_version),
        "weights_v":      int(result.scoring_weights_version),
        "score":          int(result.score),
        "raw_score":      int(raw_score),
        "delta_clamped":  bool(result.delta_clamped),
        # `previous_score` is not on ScoreResult (the composite consumes it
        # but does not retain it for the result). Callers thread it
        # through via build_score_components_with_previous() below. The
        # default-`None` form is for tests / tooling that don't have it.
        "previous_score": None,
        "alert":          (result.alert.value
                            if isinstance(result.alert, AlertTier)
                            else str(result.alert)),
        "immediate_red":  bool(result.immediate_red),
        "agg_flags":      int(result.aggregated_flags),
        "confidence":     int(result.confidence),
        "gaming":         bool(result.gaming_detected),
        "gaming_drop":    _canon_float(result.gaming_drop_fraction),
        "dims":           dims_list,
    }
    return payload


def build_score_components_with_previous(
    result:         "ScoreResult",
    *,
    previous_score: int | None,
) -> dict[str, Any]:
    """
    Same as `build_score_components_payload` but threads the
    `previous_score` value that was supplied to `compute_composite_score`
    so the consumer can re-apply the 200-pt delta guard rail. Production
    callers use this form.
    """
    payload = build_score_components_payload(result)
    if previous_score is not None:
        if not (0 <= int(previous_score) <= 1000):
            raise ValueError(
                f"previous_score must be in [0, 1000] or None, "
                f"got {previous_score!r}"
            )
        payload["previous_score"] = int(previous_score)
    return payload


# =============================================================================
# Canonical serialise + hash
# =============================================================================

def serialize_score_components(payload: dict[str, Any]) -> bytes:
    """
    Canonical-JSON serialisation. Sorted keys, no whitespace, UTF-8 bytes.
    Byte-identical output on every Python interpreter for the same dict.

    Raises `ValueError` if the resulting bytes exceed
    `MAX_SCORE_COMPONENTS_PAYLOAD_LEN` — the writer should refuse to issue
    a cert in that case (a payload that big means a serializer regression).
    """
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    raw = text.encode("utf-8")
    if len(raw) > MAX_SCORE_COMPONENTS_PAYLOAD_LEN:
        raise ValueError(
            f"score-components payload is {len(raw)} bytes, exceeds "
            f"MAX_SCORE_COMPONENTS_PAYLOAD_LEN={MAX_SCORE_COMPONENTS_PAYLOAD_LEN}"
        )
    return raw


def score_components_hash(payload_bytes: bytes) -> bytes:
    """Return the 32-byte SHA-256 of canonical-serialised payload bytes."""
    return hashlib.sha256(payload_bytes).digest()


# =============================================================================
# One-shot helper — the call site every cluster writer uses
# =============================================================================

def build_components_and_hash(
    result:         "ScoreResult",
    *,
    previous_score: int | None,
) -> tuple[bytes, bytes]:
    """
    Build the canonical payload bytes AND its SHA-256 in one call.

    Returns `(payload_bytes, components_hash)`. The cluster writer
    publishes `payload_bytes` in the `ScoreComponentsAccount` and folds
    `components_hash` into the cert-payload digest. The on-chain handler
    enforces `sha256(payload_bytes) == components_hash` at write time.
    """
    payload = build_score_components_with_previous(
        result, previous_score=previous_score,
    )
    raw = serialize_score_components(payload)
    return raw, score_components_hash(raw)
