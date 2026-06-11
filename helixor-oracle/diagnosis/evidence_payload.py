"""
diagnosis/evidence_payload.py — Day-39 canonical evidence payload.

WHAT THIS IS
------------
The canonical-JSON diagnosis payload whose SHA-256 == the on-chain
`diagnosis_payload_hash` (Day 38) the cluster threshold-signs into a
HealthCertificate v2. Cert v2 attests to this hash; the payload itself
lives in the off-chain DA layer (the indexer's `diagnosis_payloads`
table, served via `GET /agents/{wallet}/diagnosis/{epoch}/evidence`).

SPEC
----
    {
      "taxonomy_version": "1",
      "kernel_manifest":  "<sha256 hex of the kernel's frozen surface>",
      "dimensions": [
          {"dimension": "drift", "score": 920, "max_score": 1000,
           "flags": 0, "sub_scores": {...}, "algo_version": 3},
          ...
      ],
      "findings": [
          {
            "bit":            35,
            "label":          "TOOL_LOOP",
            "confidence":     0.95,
            "evidence_spans": [
                {"slot": 12345, "tx_sig": "...", "ix_index": 0, "note": ""},
                ...
            ],
          },
          ...
      ],
    }

Per D4 the per-dimension components ride inside this payload — threshold-
attested without a new PDA. The hash binds the cluster's threshold
signatures to the EXACT bytes the cert v2 was signed against; any future
verifier recomputes the bytes from the served payload, hashes, and
compares against the on-chain field.

DETERMINISTIC TRUNCATION
------------------------
Two caps, applied in order:

  1. MAX_SPANS_PER_FINDING (`16`) — every finding's `evidence_spans`
     is capped to the first N in canonical (slot, tx_sig, ix_index)
     order. Spans beyond the cap are dropped on every node identically.

  2. MAX_PAYLOAD_BYTES (`65536` = 64 KiB) — after the per-finding cap,
     if the serialised payload still exceeds the cap, the per-finding
     span budget is decremented UNIFORMLY and the payload is
     re-serialised. The loop terminates at k=0 (every finding retains
     only `bit`/`label`/`confidence`), which is always under the cap.

Why uniform decrement, not "drop largest finding first"?

  * Determinism is trivial — every node runs the same loop with the
    same data, so they all converge on the same k. No tiebreaker
    sensitive to floating-point or memory-layout ordering.
  * Fairness — a single finding with many spans cannot starve the
    others of their evidence headroom.
  * Span preservation — under any normal traffic load, the cap is not
    hit, and full spans go through unchanged.

CANONICAL JSON
--------------
`json.dumps(..., sort_keys=True, separators=(",", ":"),
ensure_ascii=True)`. Same dumper the Day-23 baseline-hashing and
Day-36 kernel use — readers/writers across the project agree on the
byte representation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from diagnosis.detectors.kernel import KernelResult, kernel_manifest_hash
from diagnosis.detectors.types import EvidenceSpan
from diagnosis.taxonomy import FailureMode, LABEL_METADATA


# =============================================================================
# Frozen constants — bumping these is a wire-format break
# =============================================================================

# Taxonomy schema version. Must match `_TAXONOMY_SCHEMA_VERSION` in
# diagnosis/detectors/kernel.py — they are read off the same source of
# truth. Folded into the on-chain `taxonomy_version: u8` Day 38 field
# (after a parseint), so the cluster's threshold signatures attest to
# the exact schema the bitmask was decoded against.
TAXONOMY_VERSION: str = "1"

# Truncation caps. Tuned to keep evidence rich on the median case
# (most detectors emit <= 4 spans) while bounding the worst case at a
# generous 64 KiB. Bumping either is a wire-format break.
MAX_SPANS_PER_FINDING: int = 16
MAX_PAYLOAD_BYTES:     int = 65_536  # 64 KiB


# =============================================================================
# Builder — KernelResult + per-dimension breakdown -> canonical payload
# =============================================================================

@dataclass(frozen=True, slots=True)
class DimensionEntry:
    """Per-dimension slice that rides inside the evidence payload (D4).

    Mirrors `oracle.diagnosis.DimensionBreakdown` field-for-field but
    is intentionally a plain dataclass (not a frozen Mapping) so this
    module imports nothing from `diagnosis.record` — that file pulls in
    the Phase-1 off-chain stack we want to keep independent of the
    threshold-attested DA path.

    `sub_scores` is a dict[str, float]. Determinism over its key order
    is handled by the `sort_keys=True` dumper; per-key float values are
    rounded to 6 dp (matching the kernel) so a node that recomputes the
    same score does not produce a different byte tail through a
    different precision.
    """
    dimension:    str
    score:        int
    max_score:    int
    flags:        int
    sub_scores:   Mapping[str, float]
    algo_version: int


def build_evidence_payload(
    *,
    kernel_result:     KernelResult,
    dimensions:        Iterable[DimensionEntry],
    taxonomy_version:  str = TAXONOMY_VERSION,
    max_spans_per_finding: int = MAX_SPANS_PER_FINDING,
    max_payload_bytes:     int = MAX_PAYLOAD_BYTES,
) -> dict:
    """Build the Day-39 canonical payload dict.

    Pure. Same inputs → byte-identical canonical JSON. The output dict
    is itself an ordinary Python dict — call `canonical_json_bytes()`
    to get the byte representation that hashes to
    `diagnosis_payload_hash`.

    The truncation policy is applied here (not at hashing time) so a
    consumer that round-trips the served payload through json.loads
    and re-hashes gets the same bytes the cluster signed against.
    """
    if max_spans_per_finding < 0:
        raise ValueError("max_spans_per_finding must be >= 0")
    if max_payload_bytes < 1:
        raise ValueError("max_payload_bytes must be >= 1")

    # Stable per-dimension ordering — sort by dimension name. Sub-scores
    # are sorted by the canonical dumper at emit time, so we pass the
    # dict through unchanged here.
    dim_list = sorted(
        (
            {
                "dimension":    d.dimension,
                "score":        int(d.score),
                "max_score":    int(d.max_score),
                "flags":        int(d.flags),
                "sub_scores":   {k: round(float(v), 6) for k, v in d.sub_scores.items()},
                "algo_version": int(d.algo_version),
            }
            for d in dimensions
        ),
        key=lambda x: x["dimension"],
    )

    findings_full = _findings_with_full_spans(kernel_result)

    # Apply the per-finding span cap first, then the byte cap. The loop
    # decrements k uniformly across all findings — see module docstring.
    k = max_spans_per_finding
    while True:
        findings_capped = _cap_spans(findings_full, k)
        payload = {
            "taxonomy_version": taxonomy_version,
            "kernel_manifest":  kernel_result.manifest_hash,
            "dimensions":       dim_list,
            "findings":         findings_capped,
        }
        if len(canonical_json_bytes(payload)) <= max_payload_bytes:
            return payload
        if k == 0:
            # Cannot truncate further. Return as-is; the cap may legitimately
            # be smaller than the irreducible payload (lots of findings, lots
            # of dimensions). A caller that needs a hard ceiling enforces it
            # by widening MAX_PAYLOAD_BYTES, not by truncating dimensions.
            return payload
        k -= 1


def canonical_json_bytes(payload: dict) -> bytes:
    """Serialise the payload to canonical-JSON bytes.

    Same dumper as Day-23 baseline-hashing and Day-36 kernel JSON.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def diagnosis_payload_hash(payload: dict) -> bytes:
    """SHA-256 of the canonical-JSON bytes — 32 raw bytes.

    This is the value the cluster threshold-signs into the cert v2
    `diagnosis_payload_hash` field. A verifier recomputes it from the
    served payload and compares against the on-chain field.
    """
    return hashlib.sha256(canonical_json_bytes(payload)).digest()


# =============================================================================
# Internal helpers
# =============================================================================

def _findings_with_full_spans(kernel_result: KernelResult) -> list[dict]:
    """Translate KernelResult findings into the Day-39 wire shape with
    every span present. Truncation is applied by `_cap_spans` later.

    Findings are sorted by (bit asc, label asc) for byte stability —
    matching the kernel's `to_canonical_json` order, so a node that
    reads the kernel result and a node that re-derives from the wire
    payload converge on the same finding sequence.
    """
    out: list[dict] = []
    for f in kernel_result.findings:
        label = _label_name(f.label_bit)
        out.append({
            "bit":        int(f.label_bit),
            "label":      label,
            "confidence": round(float(f.confidence), 6),
            "evidence_spans": [_span_to_dict(s) for s in f.evidence_spans],
        })
    out.sort(key=lambda x: (x["bit"], x["label"]))
    return out


def _cap_spans(findings: list[dict], k: int) -> list[dict]:
    """Return a copy of `findings` with each `evidence_spans` capped to k.

    The kernel already canonicalises span order, so taking the head k
    is deterministic — every node arrives at the same retained set.
    """
    capped: list[dict] = []
    for f in findings:
        capped.append({
            "bit":        f["bit"],
            "label":      f["label"],
            "confidence": f["confidence"],
            "evidence_spans": f["evidence_spans"][:k],
        })
    return capped


def _span_to_dict(s: EvidenceSpan) -> dict:
    """Translate an EvidenceSpan into the Day-39 wire dict.

    Adds the `note` field (default ""). The frozen EvidenceSpan type
    does not yet carry a note — when a future detector wants to attach
    one, EvidenceSpan grows an optional `note: str = ""` field and this
    helper picks it up via `getattr`. The "" default keeps the wire
    shape stable today, and the canonical JSON serialiser sorts keys so
    the byte layout does not depend on attribute order.
    """
    return {
        "slot":     int(s.slot),
        "tx_sig":   str(s.tx_sig),
        "ix_index": int(s.ix_index),
        "note":     getattr(s, "note", ""),
    }


def _label_name(bit: int) -> str:
    """Resolve the canonical FailureMode label name for a bit position.

    Falls back to "UNKNOWN_BIT_<n>" when the bit is set but the
    taxonomy does not name it — happens only for a stale detector
    against a newer taxonomy or vice versa. The cluster will refuse
    the cert at the digest-match step anyway; this fallback keeps the
    payload deterministic instead of crashing.
    """
    try:
        mode = FailureMode(1 << bit)
    except ValueError:
        return f"UNKNOWN_BIT_{bit}"
    md = LABEL_METADATA.get(mode)
    if md is None:
        return f"UNKNOWN_BIT_{bit}"
    return md.name


# =============================================================================
# Convenience — verifier-side recipe
# =============================================================================

def verify_payload_hash(payload: dict, expected_hash: bytes) -> bool:
    """Recompute the canonical hash of `payload` and compare against
    `expected_hash` (32 raw bytes — the on-chain cert v2 field).

    Pure, constant-time-ish equality via `hmac.compare_digest`.
    """
    import hmac
    if not isinstance(expected_hash, (bytes, bytearray)):
        raise TypeError("expected_hash must be bytes")
    if len(expected_hash) != 32:
        raise ValueError("expected_hash must be 32 bytes (SHA-256 output)")
    return hmac.compare_digest(diagnosis_payload_hash(payload), bytes(expected_hash))
