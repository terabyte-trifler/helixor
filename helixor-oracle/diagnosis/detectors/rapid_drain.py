"""
diagnosis/detectors/rapid_drain.py — fast outflow burst.

We map a sustained outflow burst to `FailureMode.DATA_LEAKAGE` (bit 59) —
treating "drain" as a value-data exfiltration signal. Honest framing: the
on-chain literal is "rapid drain of value"; the same pattern is what data
exfiltration looks like in lamports.

DETECTION
---------
Slide a `WINDOW_SECONDS` window across the canonical tx list. Sum the
absolute value of negative `sol_change` per window (outflow only). If any
window exceeds `DRAIN_THRESHOLD_LAMPORTS`, raise the finding. Confidence
ramps from 0.5 at the threshold to 1.0 at 4x. Evidence: every outflow tx
inside the worst window.

The detector is wallet-agnostic: it does not need to know which side of
each transfer was the agent — `sol_change` is already the agent-relative
delta computed by the indexer (per `features/types.py`).
"""

from __future__ import annotations

from collections.abc import Sequence

from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from ._canon import canonical_window_txs
from .types import DiagnosisFinding, EvidenceSpan

DETECTOR_ID:              str = "rapid_drain@1"
WINDOW_SECONDS:           int = 300                  # 5-minute slide
DRAIN_THRESHOLD_LAMPORTS: int = 1_000_000_000        # 1 SOL


def detect(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> DiagnosisFinding | None:
    txs = canonical_window_txs(transactions, window)
    if not txs:
        return None

    outflows = [t for t in txs if t.sol_change < 0]
    if not outflows:
        return None

    best_window: list[Transaction] = []
    best_sum: int = 0
    j_start = 0
    running: list[Transaction] = []
    running_sum = 0
    for i, t in enumerate(outflows):
        running.append(t)
        running_sum += -t.sol_change
        # Slide left edge forward while span > WINDOW_SECONDS.
        while running and (t.block_time - running[0].block_time).total_seconds() > WINDOW_SECONDS:
            dropped = running.pop(0)
            running_sum -= -dropped.sol_change
            j_start += 1
        if running_sum > best_sum:
            best_sum = running_sum
            best_window = list(running)

    if best_sum < DRAIN_THRESHOLD_LAMPORTS:
        return None

    confidence = min(
        1.0,
        0.5 + 0.5 * (best_sum - DRAIN_THRESHOLD_LAMPORTS) / (3 * DRAIN_THRESHOLD_LAMPORTS),
    )
    spans = tuple(
        EvidenceSpan(slot=t.slot, tx_sig=t.signature, ix_index=0)
        for t in best_window
    )
    return DiagnosisFinding(
        label_bit=FailureMode.DATA_LEAKAGE.bit_length() - 1,
        confidence=confidence,
        evidence_spans=spans,
        remediation_codes=int(
            RemediationCode.PAUSE_AGENT
            | RemediationCode.ALERT_OPERATORS
            | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
        detector_id=DETECTOR_ID,
    )


THRESHOLDS: dict[str, int | float] = {
    "window_seconds":           WINDOW_SECONDS,
    "drain_threshold_lamports": DRAIN_THRESHOLD_LAMPORTS,
}
