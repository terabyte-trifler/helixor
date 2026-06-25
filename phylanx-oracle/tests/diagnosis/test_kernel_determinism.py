"""
tests/diagnosis/test_kernel_determinism.py — kernel determinism + manifest pins.

The Day-36 kernel becomes the `scoring_code_hash` input on Day 38. Two
nodes that ran the same kernel must produce the SAME bytes. This file
pins:

    1. `KERNEL_VERSION` literal — bumped only on a wire change.
    2. `kernel_manifest_hash()` — stable across calls; ANY change is a
        deliberate manifest bump.
    3. The exhaustive 8-detector descriptor list (id + thresholds) the
       manifest hashes over. A new detector OR a threshold tweak shows up
       as a single failing assert.
    4. `KernelResult.to_canonical_json()` is byte-identical across 100
       runs over the same inputs (the "100 runs" guarantee from the spec).
    5. Mixed-input determinism: the kernel emits findings in canonical
       (label_bit, detector_id) order regardless of input shuffling.
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone

from diagnosis.detectors import (
    KERNEL_VERSION,
    kernel_manifest_hash,
    run_kernel,
)
from features.types import ExtractionWindow, Transaction


# ─────────────────────────────────────────────────────────────────────────────
# Manifest pin: version + hash + detector descriptor table
# ─────────────────────────────────────────────────────────────────────────────

def test_kernel_version_literal_pin():
    """The wire version string is on-chain-load-bearing once Day 38 ships."""
    assert KERNEL_VERSION == "v1.0"


def test_manifest_hash_stable_within_process():
    """Calling the manifest twice returns the same hex digest."""
    a = kernel_manifest_hash()
    b = kernel_manifest_hash()
    assert a == b
    assert len(a) == 64  # sha256 hex
    int(a, 16)  # parses


def test_manifest_hash_pinned():
    """Pin the manifest hash. Bumping a detector threshold or adding a
    detector must come with a deliberate update of THIS literal.
    Any drift here is what Day 38 attestation will treat as a code-identity
    bump."""
    expected = "b02d6bea0c51d3eccb8d072a12ab1af34fd233c46318e705d6fb5bbf6edbae75"
    assert kernel_manifest_hash() == expected


def test_manifest_payload_shape():
    """The payload the hash is computed over keeps a documented shape."""
    from diagnosis.detectors.kernel import _manifest_payload
    payload = _manifest_payload()
    assert payload["taxonomy_schema_version"] == "1"
    assert payload["kernel_version"] == KERNEL_VERSION
    ids = {d["id"] for d in payload["detectors"]}
    assert ids == {
        "arg_validation@1",
        "cost_blowup@1",
        "counterparty_concentration@1",
        "excessive_agency@1",
        "rapid_drain@1",
        "timing_anomaly@1",
        "tool_loop@1",
        "unauthorized_program@1",
    }
    # Detectors are sorted by id — required for the hash to be stable.
    sorted_ids = [d["id"] for d in payload["detectors"]]
    assert sorted_ids == sorted(sorted_ids)


# ─────────────────────────────────────────────────────────────────────────────
# Kernel determinism: 100 runs, byte-identical
# ─────────────────────────────────────────────────────────────────────────────

NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
WINDOW = ExtractionWindow(start=NOW - timedelta(hours=2), end=NOW)
JUP = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def _build_loop_txs(n: int) -> list[Transaction]:
    return [
        Transaction(
            signature=f"sig{i:061d}",
            slot=2000 + i,
            block_time=NOW - timedelta(seconds=60 - i*5),
            success=True,
            program_ids=(JUP,),
            sol_change=-1000,
            fee=5000,
            counterparty="peerA",
        )
        for i in range(n)
    ]


def test_kernel_byte_identical_100_runs():
    """Same inputs -> same JSON bytes, 100 runs. The 'byte-identical
    determinism' invariant from the Day-36 spec."""
    txs = _build_loop_txs(8)
    expected = run_kernel(txs, WINDOW).to_canonical_json()
    digests = set()
    for _ in range(100):
        r = run_kernel(txs, WINDOW)
        digests.add(hashlib.sha256(r.to_canonical_json().encode("ascii")).hexdigest())
        assert r.to_canonical_json() == expected
    assert len(digests) == 1


def test_kernel_input_order_invariance():
    """Shuffled input order yields the same output. The kernel internally
    canonicalises by (block_time, slot, signature) — the byte-identical
    guarantee depends on that canonicalisation."""
    txs = _build_loop_txs(8)
    base = run_kernel(txs, WINDOW).to_canonical_json()
    rng = random.Random(0)
    for seed in range(10):
        shuffled = list(txs)
        rng.shuffle(shuffled)
        assert run_kernel(shuffled, WINDOW).to_canonical_json() == base


def test_kernel_findings_sorted_by_bit():
    """Findings are emitted in ascending (label_bit, detector_id) order."""
    # Mix of bursts that should fire MULTIPLE detectors:
    # 1. Tool-loop on JUP (label_bit 35)
    # 2. Cost blowup via huge fee (label_bit 57)
    txs = [
        Transaction(
            signature=f"sig{i:061d}",
            slot=3000 + i,
            block_time=NOW - timedelta(seconds=60 - i*5),
            success=True,
            program_ids=(JUP,),
            sol_change=-1000,
            fee=20_000_000,  # 8 * 20M = 160M > 50M threshold
            counterparty="peerA",
        )
        for i in range(8)
    ]
    r = run_kernel(txs, WINDOW)
    bits = [f.label_bit for f in r.findings]
    assert bits == sorted(bits)


def test_canonical_json_parses_and_round_trips():
    txs = _build_loop_txs(8)
    r = run_kernel(txs, WINDOW)
    j = r.to_canonical_json()
    payload = json.loads(j)
    assert payload["kernel_version"] == KERNEL_VERSION
    assert payload["manifest_hash"] == kernel_manifest_hash()
    assert payload["failure_mode_bitmask"] == r.failure_mode_bitmask
    assert len(payload["findings"]) == len(r.findings)


def test_empty_window_produces_zero_bitmask():
    r = run_kernel([], WINDOW)
    assert r.failure_mode_bitmask == 0
    assert r.findings == ()
    assert r.kernel_version == KERNEL_VERSION
    assert r.manifest_hash == kernel_manifest_hash()
