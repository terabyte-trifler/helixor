"""
diagnosis/detectors/cost_blowup.py — fee + priority-fee spend over budget.

Sums lamport-fees across the window. If the spend exceeds
`COST_BLOWUP_LAMPORTS`, raises `FailureMode.COST_BLOWUP` (bit 57).
Confidence ramps from 0.5 at threshold to 1.0 at 2x. The top spenders
become evidence spans.

The detector is intentionally absolute (no per-agent baseline) so it can
fire on the first epoch of a new agent — the diagnosis kernel's job is to
catch obvious runaway spend, the score's drift dimension still owns the
relative comparison.
"""

from __future__ import annotations

from collections.abc import Sequence

from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from ._canon import canonical_window_txs
from .types import DiagnosisFinding, EvidenceSpan

DETECTOR_ID:          str = "cost_blowup@1"
COST_BLOWUP_LAMPORTS: int = 50_000_000   # 0.05 SOL across the window
TOP_EVIDENCE_COUNT:   int = 5


def detect(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> DiagnosisFinding | None:
    txs = canonical_window_txs(transactions, window)
    if not txs:
        return None

    total = sum(t.fee + t.priority_fee for t in txs)
    if total < COST_BLOWUP_LAMPORTS:
        return None

    confidence = min(1.0, 0.5 + 0.5 * (total - COST_BLOWUP_LAMPORTS) / COST_BLOWUP_LAMPORTS)

    # Top spenders, then re-sort canonically inside the finding.
    top = sorted(
        txs,
        key=lambda t: (-(t.fee + t.priority_fee), t.block_time, t.slot, t.signature),
    )[:TOP_EVIDENCE_COUNT]
    spans = tuple(
        EvidenceSpan(slot=t.slot, tx_sig=t.signature, ix_index=0)
        for t in top
    )
    return DiagnosisFinding(
        label_bit=FailureMode.COST_BLOWUP.bit_length() - 1,
        confidence=confidence,
        evidence_spans=spans,
        remediation_codes=int(
            RemediationCode.DECREASE_RATE_LIMITS | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
        detector_id=DETECTOR_ID,
    )


THRESHOLDS: dict[str, int | float] = {
    "cost_blowup_lamports": COST_BLOWUP_LAMPORTS,
    "top_evidence_count":   TOP_EVIDENCE_COUNT,
}
