"""
diagnosis/detectors/arg_validation.py — structural-malformation signal.

A transaction whose result is `success=False` together with a non-trivial
fee burn is the chain's "tool was called with bad arguments" signal — the
runtime spent compute units, validated the inputs, and reverted. A sustained
rate of those failures over the window is a tool-misuse pattern.

DETECTION
---------
Failure-rate = failed / (failed + successful). If failure-rate exceeds
`FAILURE_RATE_THRESHOLD` AND the failed-count >= `MIN_FAILED`, raise
`FailureMode.TOOL_MISUSE` (bit 34). Confidence ramps from 0.5 at the
threshold to 1.0 at 1.0.

Evidence: every failed transaction in the window.
"""

from __future__ import annotations

from collections.abc import Sequence

from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from ._canon import canonical_window_txs
from .types import DiagnosisFinding, EvidenceSpan

DETECTOR_ID:             str   = "arg_validation@1"
MIN_FAILED:              int   = 3
FAILURE_RATE_THRESHOLD:  float = 0.30   # >= 30% failed = malformed args pattern


def detect(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> DiagnosisFinding | None:
    txs = canonical_window_txs(transactions, window)
    if not txs:
        return None

    failed = [t for t in txs if not t.success]
    if len(failed) < MIN_FAILED:
        return None

    rate = len(failed) / len(txs)
    if rate < FAILURE_RATE_THRESHOLD:
        return None

    confidence = min(
        1.0,
        0.5 + 0.5 * (rate - FAILURE_RATE_THRESHOLD) / max(1e-9, 1.0 - FAILURE_RATE_THRESHOLD),
    )
    spans = tuple(
        EvidenceSpan(slot=t.slot, tx_sig=t.signature, ix_index=0)
        for t in failed
    )
    return DiagnosisFinding(
        label_bit=FailureMode.TOOL_MISUSE.bit_length() - 1,
        confidence=confidence,
        evidence_spans=spans,
        remediation_codes=int(
            RemediationCode.REVIEW_TOOL_PERMISSIONS
            | RemediationCode.AUDIT_RECENT_OUTPUTS
            | RemediationCode.PATCH_PROMPT_GUARD
        ),
        detector_id=DETECTOR_ID,
    )


THRESHOLDS: dict[str, int | float] = {
    "min_failed":             MIN_FAILED,
    "failure_rate_threshold": FAILURE_RATE_THRESHOLD,
}
