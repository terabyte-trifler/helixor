"""
diagnosis/detectors/ — the Day-36 mechanical diagnosis kernel.

Phase-3(a) of the score-to-diagnosis pivot. Eight deterministic detectors,
pure stdlib, pure functions over the existing (Transactions, ExtractionWindow)
inputs. Each emits a `DiagnosisFinding` carrying:

    * label_bit      — the FailureMode bit it raises
    * confidence     — 0.0 .. 1.0
    * evidence_spans — (slot, tx_sig, ix_index) tuples for forensics
    * remediation_codes — RemediationCode bitmask for the cluster to surface

The kernel runs all detectors, ORs their bits, and collects evidence into a
single `KernelResult`. `KERNEL_VERSION` + `kernel_manifest_hash` form the
scoring_code_hash input the Day-38 attestation flow will threshold-sign.

DETERMINISM CONTRACT
--------------------
The kernel is intentionally cross-node identical:
    * inputs are canonically sorted before scanning
    * thresholds are integer / float literals declared once at module load
    * findings are emitted in `FailureMode`-bit-ascending order
    * `KernelResult.to_canonical_json()` round-trips byte-identically across
      Python interpreters that share the same module bytecode

A Day-30 detection-engine `DimensionResult` is the SCORE surface; a
`DiagnosisFinding` is the DIAGNOSIS surface. The two are independent — the
kernel is opt-in via a feature flag on the epoch runner (default OFF) so
the Phase-1 1,164-test baseline of the existing detection / oracle suite
stays untouched.
"""

from .types import DiagnosisFinding, EvidenceSpan
from .kernel import (
    KERNEL_VERSION,
    KernelResult,
    kernel_manifest_hash,
    run_kernel,
)

__all__ = (
    "DiagnosisFinding",
    "EvidenceSpan",
    "KERNEL_VERSION",
    "KernelResult",
    "kernel_manifest_hash",
    "run_kernel",
)
