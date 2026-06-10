"""
diagnosis/detectors/kernel.py — runs the 8 detectors, ORs bits, collects evidence.

KERNEL_VERSION is the on-the-wire schema id for downstream consumers. The
`kernel_manifest_hash()` is a sha256 over (taxonomy schema_version + sorted
detector descriptors + thresholds). It is the value that becomes the
`scoring_code_hash` input on Day 38 — two nodes producing the same hash means
they ran the same byte-frozen kernel.

A `KernelResult` carries the aggregated bitmask, the per-detector findings,
the manifest hash, and a `to_canonical_json()` byte-stable export. The
output ordering is determined entirely by FailureMode-bit ascending — same
inputs → byte-identical bytes across runs.

The kernel is invoked once per agent per epoch. It does NOT need a baseline
— Day-36 detectors are deliberately mechanical, runnable on the first epoch.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass

from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from . import (
    arg_validation,
    cost_blowup,
    counterparty_concentration,
    excessive_agency,
    rapid_drain,
    timing_anomaly,
    tool_loop,
    unauthorized_program,
)
from .types import DiagnosisFinding


# Frozen wire version — bumped on any breaking output shape change.
KERNEL_VERSION: str = "v1.0"

# Taxonomy schema version (must match diagnosis/taxonomy.json + taxonomy.py).
# Bumped together with FailureMode bit layout.
_TAXONOMY_SCHEMA_VERSION: str = "1"


# Detector dispatch table — order is locked. The manifest hash sorts by
# detector_id so manifest stability does not depend on this list's order,
# but readers should still avoid reordering for review-diff hygiene.
@dataclass(frozen=True, slots=True)
class _Detector:
    id:         str
    thresholds: tuple[tuple[str, int | float], ...]


_DETECTORS: tuple = (
    arg_validation,
    cost_blowup,
    counterparty_concentration,
    excessive_agency,
    rapid_drain,
    timing_anomaly,
    tool_loop,
    unauthorized_program,
)


def _manifest_payload() -> dict:
    """Build the canonical structure the manifest hash digests over."""
    detector_descs: list[dict] = []
    for d in _DETECTORS:
        detector_descs.append({
            "id":         d.DETECTOR_ID,
            "thresholds": dict(sorted(d.THRESHOLDS.items())),
        })
    detector_descs.sort(key=lambda x: x["id"])
    return {
        "taxonomy_schema_version": _TAXONOMY_SCHEMA_VERSION,
        "kernel_version":          KERNEL_VERSION,
        "detectors":               detector_descs,
    }


def kernel_manifest_hash() -> str:
    """sha256 hex digest over the kernel's frozen surface.

    Pure. Depends ONLY on the bytecode of this module and the imported
    detector modules — no env, no clock, no I/O. The hash changes only
    when a detector id, threshold, or the taxonomy schema version bumps.
    """
    payload = _manifest_payload()
    canonical = json.dumps(
        payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class KernelResult:
    """The per-agent kernel output.

    `failure_mode_bitmask` is the OR of every finding's `label_value`
    cast to a `FailureMode` value. `findings` is sorted into canonical
    (label_bit ASC, detector_id ASC) order so the JSON export is
    byte-stable across nodes.
    """
    kernel_version:       str
    manifest_hash:        str
    failure_mode_bitmask: int
    findings:             tuple[DiagnosisFinding, ...]

    def to_canonical_json(self) -> str:
        """Byte-stable JSON representation. The determinism suite asserts
        this round-trips identically across 100 runs."""
        payload = {
            "kernel_version":       self.kernel_version,
            "manifest_hash":        self.manifest_hash,
            "failure_mode_bitmask": self.failure_mode_bitmask,
            "findings": [
                {
                    "detector_id":       f.detector_id,
                    "label_bit":         f.label_bit,
                    "confidence":        round(f.confidence, 6),
                    "remediation_codes": f.remediation_codes,
                    "evidence_spans": [
                        {"slot": s.slot, "tx_sig": s.tx_sig, "ix_index": s.ix_index}
                        for s in f.evidence_spans
                    ],
                }
                for f in self.findings
            ],
        }
        return json.dumps(
            payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True
        )


def run_kernel(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
    *,
    declared_domain:  str = "",
    allowed_programs: frozenset[str] = frozenset(),
) -> KernelResult:
    """
    Run every Day-36 detector against `(transactions, window)` and assemble
    the kernel's output.

    `declared_domain` feeds the excessive-agency detector; an empty string
    causes that detector to abstain. `allowed_programs` feeds the
    unauthorized-program detector; an empty frozenset causes that detector
    to abstain.

    Pure. Same inputs → byte-identical `KernelResult` and JSON. The kernel
    NEVER raises on detector errors — a future detector that crashes is
    contained and silently omitted (Day 38 attestation will surface the
    omission via a separate health flag).
    """
    raw: list[DiagnosisFinding] = []

    for detector_module in _DETECTORS:
        try:
            if detector_module is excessive_agency:
                finding = detector_module.detect(
                    transactions, window, declared_domain=declared_domain,
                )
            elif detector_module is unauthorized_program:
                finding = detector_module.detect(
                    transactions, window, allowed_programs=allowed_programs,
                )
            else:
                finding = detector_module.detect(transactions, window)
        except Exception:  # noqa: BLE001 — kernel must not crash on detector bugs
            finding = None

        if finding is not None:
            raw.append(finding)

    raw.sort(key=lambda f: (f.label_bit, f.detector_id))

    bitmask = 0
    for f in raw:
        bitmask |= f.label_value
    # Bitmask must fit in u64 — every label_bit is already in [0, 63].
    bitmask &= (1 << 64) - 1

    return KernelResult(
        kernel_version=KERNEL_VERSION,
        manifest_hash=kernel_manifest_hash(),
        failure_mode_bitmask=bitmask,
        findings=tuple(raw),
    )


# Sanity at import time: every label_bit returned by the wired detectors
# must correspond to a real FailureMode bit. This catches a detector that
# raises a stale bit after a taxonomy rename.
def _verify_detector_label_bits() -> None:
    known = {int(m).bit_length() - 1 for m in FailureMode}
    # The label_bit a detector raises is hardcoded at construction time, so
    # we can't introspect without running it. Instead, assert the detector
    # registry exposes the documented bits.
    documented = {
        "arg_validation@1":             FailureMode.TOOL_MISUSE,
        "cost_blowup@1":                FailureMode.COST_BLOWUP,
        "counterparty_concentration@1": FailureMode.IDENTITY_PRIVILEGE_ABUSE,
        "excessive_agency@1":           FailureMode.EXCESSIVE_AGENCY,
        "rapid_drain@1":                FailureMode.DATA_LEAKAGE,
        "timing_anomaly@1":             FailureMode.LATENCY_DEGRADATION,
        "tool_loop@1":                  FailureMode.TOOL_LOOP,
        "unauthorized_program@1":       FailureMode.TOOL_MISUSE,
    }
    for mod in _DETECTORS:
        if mod.DETECTOR_ID not in documented:
            raise AssertionError(
                f"detector {mod.DETECTOR_ID} has no documented FailureMode binding"
            )
        fm = documented[mod.DETECTOR_ID]
        bit = int(fm).bit_length() - 1
        if bit not in known:
            raise AssertionError(
                f"detector {mod.DETECTOR_ID} maps to FailureMode bit {bit} which "
                f"is not in the taxonomy"
            )


_verify_detector_label_bits()
