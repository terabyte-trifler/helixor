"""
diagnosis/detectors/unauthorized_program.py — agent invoked a program
outside its declared allowlist.

We raise `FailureMode.TOOL_MISUSE` (bit 34, OWASP ASI02:2026): the tool
was called outside its declared contract — here "contract" = the
operator's program allowlist.

DETECTION
---------
For every transaction in the window, walk `program_ids`. Any program
that is NOT in `allowed_programs` becomes evidence. If the count of
offending instructions exceeds `MIN_VIOLATIONS`, raise the finding.
Confidence ramps from 0.6 with a single offending tx up to 1.0 as the
ratio of offending invocations rises.

An empty `allowed_programs` set => the operator declared no allowlist and
the detector abstains (returns None) — no false positives for agents that
intentionally have no allowlist policy yet.
"""

from __future__ import annotations

from collections.abc import Sequence

from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from ._canon import canonical_window_txs
from .types import DiagnosisFinding, EvidenceSpan

DETECTOR_ID:    str = "unauthorized_program@1"
MIN_VIOLATIONS: int = 1   # one offending instruction is enough — small N is fine


def detect(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
    *,
    allowed_programs: frozenset[str],
) -> DiagnosisFinding | None:
    if not allowed_programs:
        return None
    txs = canonical_window_txs(transactions, window)
    if not txs:
        return None

    spans: list[EvidenceSpan] = []
    total_ix = 0
    for t in txs:
        for idx, pid in enumerate(t.program_ids):
            total_ix += 1
            if pid not in allowed_programs:
                spans.append(EvidenceSpan(slot=t.slot, tx_sig=t.signature, ix_index=idx))

    if len(spans) < MIN_VIOLATIONS or total_ix == 0:
        return None

    ratio = len(spans) / total_ix
    confidence = min(1.0, 0.6 + 0.4 * ratio)
    return DiagnosisFinding(
        label_bit=FailureMode.TOOL_MISUSE.bit_length() - 1,
        confidence=confidence,
        evidence_spans=tuple(spans),
        remediation_codes=int(
            RemediationCode.REVIEW_TOOL_PERMISSIONS | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
        detector_id=DETECTOR_ID,
    )


THRESHOLDS: dict[str, int | float] = {
    "min_violations": MIN_VIOLATIONS,
}
