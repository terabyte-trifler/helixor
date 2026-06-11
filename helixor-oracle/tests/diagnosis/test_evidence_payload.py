"""
tests/diagnosis/test_evidence_payload.py — Day-39 canonical-payload pins.

The Day-39 evidence payload is the off-chain DA layer behind the
threshold-attested on-chain `diagnosis_payload_hash` (Day 38). This
file pins:

  1. SHA-256 of canonical JSON == `diagnosis_payload_hash` (the
     cluster-signs-this-hash contract).
  2. Byte-stable across 100 runs over the same inputs and across
     shuffled input ordering — every honest node emits identical bytes.
  3. The per-finding span cap is enforced.
  4. The total-bytes cap is enforced by uniformly decrementing the
     per-finding span budget until the serialized payload fits.
  5. Truncation is deterministic — every node converges on the same
     retained set, regardless of which node trimmed.
  6. The verifier-side recipe: `verify_payload_hash(payload, on_chain_hash)`
     returns True iff the recomputed hash matches.
  7. Wire-frozen constants — `TAXONOMY_VERSION`, `MAX_SPANS_PER_FINDING`,
     `MAX_PAYLOAD_BYTES` — bumping any is a wire-format break.
"""

from __future__ import annotations

import hashlib
import json
import random

from diagnosis.detectors.kernel import KernelResult, kernel_manifest_hash
from diagnosis.detectors.types import DiagnosisFinding, EvidenceSpan
from diagnosis.evidence_payload import (
    MAX_PAYLOAD_BYTES,
    MAX_SPANS_PER_FINDING,
    TAXONOMY_VERSION,
    DimensionEntry,
    build_evidence_payload,
    canonical_json_bytes,
    diagnosis_payload_hash,
    verify_payload_hash,
)


# =============================================================================
# Fixtures — small reusable inputs
# =============================================================================

def _spans(n: int, base_slot: int = 1000) -> tuple[EvidenceSpan, ...]:
    """n synthetic spans with strictly increasing (slot, ix) keys."""
    return tuple(
        EvidenceSpan(slot=base_slot + i, tx_sig=f"sig{i:04d}", ix_index=i % 4)
        for i in range(n)
    )


def _finding(
    bit: int = 35,
    conf: float = 0.9,
    span_count: int = 3,
    rem: int = 4,
    det: str = "tool_loop@1",
) -> DiagnosisFinding:
    return DiagnosisFinding(
        label_bit=bit,
        confidence=conf,
        evidence_spans=_spans(span_count),
        remediation_codes=rem,
        detector_id=det,
    )


def _kernel(findings: tuple[DiagnosisFinding, ...]) -> KernelResult:
    bitmask = 0
    for f in findings:
        bitmask |= 1 << f.label_bit
    return KernelResult(
        kernel_version="v1.0",
        manifest_hash=kernel_manifest_hash(),
        failure_mode_bitmask=bitmask,
        findings=findings,
    )


def _dims() -> list[DimensionEntry]:
    return [
        DimensionEntry("drift", 920, 1000, 0, {"a": 0.25, "x": 0.5}, 3),
        DimensionEntry("anomaly", 880, 1000, 0, {"b": 0.7}, 2),
    ]


# =============================================================================
# Wire-frozen constants
# =============================================================================

def test_wire_constants_pinned():
    """Bumping any of these is a wire-format break — the cluster's
    threshold-signed cert v2 attests to bytes built under these caps."""
    assert TAXONOMY_VERSION == "1"
    assert MAX_SPANS_PER_FINDING == 16
    assert MAX_PAYLOAD_BYTES == 65_536


# =============================================================================
# Cluster-signs-this-hash contract — the core Day-39 invariant
# =============================================================================

def test_payload_hash_is_sha256_of_canonical_bytes():
    """The on-chain `diagnosis_payload_hash` is sha256(canonical JSON)."""
    payload = build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=_dims())
    expected = hashlib.sha256(canonical_json_bytes(payload)).digest()
    assert diagnosis_payload_hash(payload) == expected
    assert len(diagnosis_payload_hash(payload)) == 32


def test_payload_carries_required_top_level_keys():
    """The Day-39 wire shape is `{taxonomy_version, kernel_manifest,
    dimensions, findings}`. Renames are wire breaks."""
    payload = build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=_dims())
    assert set(payload.keys()) == {
        "taxonomy_version", "kernel_manifest", "dimensions", "findings",
    }
    assert payload["taxonomy_version"] == TAXONOMY_VERSION
    assert payload["kernel_manifest"] == kernel_manifest_hash()


def test_finding_entry_carries_required_keys():
    """Each finding emits `{bit, label, confidence, evidence_spans}`."""
    payload = build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=_dims())
    f = payload["findings"][0]
    assert set(f.keys()) == {"bit", "label", "confidence", "evidence_spans"}
    assert f["bit"] == 35
    assert f["label"] == "TOOL_LOOP"


def test_span_entry_carries_required_keys():
    """Each span emits `{slot, tx_sig, ix_index, note}`. `note` defaults
    to "" — the EvidenceSpan type does not yet carry one, but the field
    is in the wire shape today so a future detector that attaches a note
    is a non-breaking change."""
    payload = build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=_dims())
    span = payload["findings"][0]["evidence_spans"][0]
    assert set(span.keys()) == {"slot", "tx_sig", "ix_index", "note"}
    assert span["note"] == ""


# =============================================================================
# Determinism — 100 runs and shuffled input
# =============================================================================

def test_payload_is_byte_identical_across_100_runs():
    """Same inputs → byte-identical bytes across 100 runs.

    The "100 runs" guarantee Day-36 established for the kernel JSON;
    Day 39 inherits it because every honest node must produce the same
    bytes for the threshold signatures to converge on a single hash."""
    findings = (_finding(bit=35, span_count=4), _finding(bit=57, det="cost_blowup@1", span_count=2))
    dims = _dims()
    pinned = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel(findings), dimensions=dims))
    for _ in range(100):
        again = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel(findings), dimensions=dims))
        assert again == pinned


def test_shuffled_dimension_input_yields_identical_bytes():
    """Two nodes that supply dimensions in different orders produce the
    same bytes — the dumper sorts dimension entries by name."""
    dims = _dims()
    a = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=dims))
    b = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=list(reversed(dims))))
    assert a == b


def test_shuffled_finding_input_yields_identical_bytes():
    """Same as above for findings. The KernelResult constructor sorts
    findings, but a paranoid caller that hand-builds one in shuffled
    order must still get the same bytes."""
    findings_a = (
        _finding(bit=35, det="tool_loop@1"),
        _finding(bit=57, det="cost_blowup@1"),
    )
    findings_b = tuple(reversed(findings_a))
    a = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel(findings_a), dimensions=_dims()))
    b = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel(findings_b), dimensions=_dims()))
    assert a == b


def test_shuffled_sub_scores_yield_identical_bytes():
    """The sort_keys=True dumper means a per-dimension `sub_scores` dict
    inserted in different key orders hashes the same."""
    dims_a = [DimensionEntry("drift", 920, 1000, 0, {"a": 0.25, "x": 0.5}, 3)]
    dims_b = [DimensionEntry("drift", 920, 1000, 0, {"x": 0.5, "a": 0.25}, 3)]
    a = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=dims_a))
    b = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=dims_b))
    assert a == b


# =============================================================================
# Truncation — per-finding span cap
# =============================================================================

def test_per_finding_span_cap_is_enforced():
    """A finding with > MAX_SPANS_PER_FINDING spans is trimmed to the
    first N in canonical (slot, tx_sig, ix_index) order."""
    over = _finding(bit=35, span_count=MAX_SPANS_PER_FINDING + 10)
    payload = build_evidence_payload(kernel_result=_kernel((over,)), dimensions=_dims())
    spans = payload["findings"][0]["evidence_spans"]
    assert len(spans) == MAX_SPANS_PER_FINDING
    # The kept set is the head of the canonical order — slots 1000..1015.
    assert [s["slot"] for s in spans] == list(range(1000, 1000 + MAX_SPANS_PER_FINDING))


def test_under_cap_passes_all_spans_through():
    """Under the cap, every span is preserved — the median case."""
    f = _finding(bit=35, span_count=4)
    payload = build_evidence_payload(kernel_result=_kernel((f,)), dimensions=_dims())
    assert len(payload["findings"][0]["evidence_spans"]) == 4


# =============================================================================
# Truncation — total-bytes cap (uniform decrement)
# =============================================================================

def test_total_bytes_cap_truncates_uniformly():
    """When the per-finding cap is not enough to fit under the byte cap,
    the loop decrements k uniformly across every finding until the
    payload fits. We force this with an artificially tight cap."""
    findings = (
        _finding(bit=35, span_count=8, det="tool_loop@1"),
        _finding(bit=57, span_count=8, det="cost_blowup@1"),
    )
    # 800 bytes is below the natural full-fat size with 8 spans each;
    # the loop must decrement k uniformly.
    payload = build_evidence_payload(
        kernel_result=_kernel(findings),
        dimensions=_dims(),
        max_spans_per_finding=8,
        max_payload_bytes=800,
    )
    assert len(canonical_json_bytes(payload)) <= 800
    spans_per_finding = [len(f["evidence_spans"]) for f in payload["findings"]]
    # The cap is uniform — every finding has the same span count.
    assert len(set(spans_per_finding)) == 1


def test_total_bytes_cap_terminates_at_k_zero():
    """Worst case: cap so tight that even k=0 cannot fit. The loop
    terminates rather than hanging — the caller eats the over-cap
    payload (the alternative — silently dropping a finding — would
    break the diagnosis_payload_hash binding)."""
    findings = tuple(
        _finding(bit=35 + i, span_count=2, det=f"det{i}@1")
        for i in range(8)
    )
    payload = build_evidence_payload(
        kernel_result=_kernel(findings),
        dimensions=_dims(),
        max_spans_per_finding=8,
        max_payload_bytes=10,   # impossibly small
    )
    # Every span dropped — only bit/label/confidence survive.
    for f in payload["findings"]:
        assert f["evidence_spans"] == []


def test_truncation_is_deterministic_across_runs():
    """Two nodes running truncation over identical inputs converge on
    the same retained set — same bytes out."""
    findings = (
        _finding(bit=35, span_count=12, det="tool_loop@1"),
        _finding(bit=57, span_count=12, det="cost_blowup@1"),
    )
    a = canonical_json_bytes(build_evidence_payload(
        kernel_result=_kernel(findings),
        dimensions=_dims(),
        max_spans_per_finding=12,
        max_payload_bytes=700,
    ))
    b = canonical_json_bytes(build_evidence_payload(
        kernel_result=_kernel(findings),
        dimensions=_dims(),
        max_spans_per_finding=12,
        max_payload_bytes=700,
    ))
    assert a == b


# =============================================================================
# Verifier recipe
# =============================================================================

def test_verify_payload_hash_round_trips():
    """The serve-side recipe: a consumer fetches the payload + on-chain
    hash, recomputes, compares. True iff bytes match."""
    payload = build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=_dims())
    on_chain = diagnosis_payload_hash(payload)
    assert verify_payload_hash(payload, on_chain)


def test_verify_payload_hash_rejects_tampered_payload():
    """A consumer that received a tampered payload must see a hash
    mismatch — the threshold signatures attest only to the ORIGINAL
    bytes, so the consumer rejects the served version."""
    payload = build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=_dims())
    on_chain = diagnosis_payload_hash(payload)
    tampered = json.loads(json.dumps(payload))
    tampered["findings"][0]["confidence"] = 0.1  # silent change
    assert not verify_payload_hash(tampered, on_chain)


def test_verify_payload_hash_rejects_wrong_length():
    """The on-chain field is fixed-width 32 bytes — a non-32-byte
    candidate is a programmer error, not a consumer-recoverable case."""
    payload = build_evidence_payload(kernel_result=_kernel((_finding(),)), dimensions=_dims())
    try:
        verify_payload_hash(payload, b"\x00" * 16)
    except ValueError:
        return
    raise AssertionError("verify_payload_hash must reject non-32-byte input")


# =============================================================================
# Round-trip — kernel result -> payload -> json.loads -> recompute -> match
# =============================================================================

def test_full_round_trip_through_json_loads():
    """The full DA round trip: cluster builds payload, serialises, the
    indexer stores the bytes, the API serves them back. A consumer
    json.loads the served bytes and recomputes the hash — must match.

    This is the Day-39 'Done when' check for the in-process path; the
    network round trip is exercised by the API test."""
    payload = build_evidence_payload(
        kernel_result=_kernel((_finding(bit=35, span_count=3), _finding(bit=57, det="cost_blowup@1", span_count=2))),
        dimensions=_dims(),
    )
    served = canonical_json_bytes(payload)
    recovered = json.loads(served)
    assert diagnosis_payload_hash(recovered) == diagnosis_payload_hash(payload)


# =============================================================================
# Determinism under stress — many findings, many spans, shuffled input
# =============================================================================

def test_stress_determinism_with_many_findings_and_shuffled_input():
    """A larger payload with multiple findings, each with several
    spans, shuffled across two independent rng seeds. Both nodes
    converge on the same bytes."""
    rng_a = random.Random(0xa)
    rng_b = random.Random(0xb)

    def make_finding(bit: int, n_spans: int, det: str) -> DiagnosisFinding:
        return DiagnosisFinding(
            label_bit=bit,
            confidence=0.5,
            evidence_spans=tuple(
                EvidenceSpan(slot=10_000 + i, tx_sig=f"x{i:05d}", ix_index=i % 3)
                for i in range(n_spans)
            ),
            remediation_codes=1,
            detector_id=det,
        )

    findings_a = [
        make_finding(35, 5, "tool_loop@1"),
        make_finding(57, 3, "cost_blowup@1"),
        make_finding(36, 4, "excessive_agency@1"),
    ]
    findings_b = list(findings_a)
    rng_a.shuffle(findings_a)
    rng_b.shuffle(findings_b)

    a = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel(tuple(findings_a)), dimensions=_dims()))
    b = canonical_json_bytes(build_evidence_payload(kernel_result=_kernel(tuple(findings_b)), dimensions=_dims()))
    assert a == b
