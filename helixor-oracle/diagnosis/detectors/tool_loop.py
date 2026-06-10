"""
diagnosis/detectors/tool_loop.py — same program invoked far past the loop budget.

A tool-loop is the practitioner failure mode where an agent calls the same
tool in a tight burst that exceeds a sane budget — cost + latency runaway,
sometimes a stuck planning step. We map it to `FailureMode.TOOL_LOOP`
(bit 35, OWASP ASI02:2026 sub-mode) and surface the bursting program +
remediation hints.

DETECTION
---------
For each adjacent run of transactions whose `program_ids[0]` (the OUTER
program — the agent's chosen tool) is identical, count the run length. If
the longest run is >= `LOOP_THRESHOLD` calls inside a window of
<= `LOOP_BURST_SECONDS`, raise the finding. The largest run drives the
confidence score (linear ramp from 0.5 at the threshold to 1.0 at 2x).

Evidence: every tx in the offending run, ix_index = 0 (the outer program).

Pure stdlib. No baseline. No counterparty heuristics.
"""

from __future__ import annotations

from collections.abc import Sequence

from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from ._canon import canonical_window_txs
from .types import DiagnosisFinding, EvidenceSpan

DETECTOR_ID:        str = "tool_loop@1"
LOOP_THRESHOLD:     int = 6        # >= this many tight repeats = loop
LOOP_BURST_SECONDS: int = 60       # all calls must fall inside this span


def _outer_program(tx: Transaction) -> str | None:
    return tx.program_ids[0] if tx.program_ids else None


def detect(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> DiagnosisFinding | None:
    txs = canonical_window_txs(transactions, window)
    if not txs:
        return None

    best_run: list[Transaction] = []
    current:  list[Transaction] = []
    for tx in txs:
        prog = _outer_program(tx)
        if prog is None:
            if len(current) > len(best_run):
                best_run = current
            current = []
            continue
        if not current:
            current = [tx]
            continue
        head_prog = _outer_program(current[0])
        span_s = (tx.block_time - current[0].block_time).total_seconds()
        if prog == head_prog and span_s <= LOOP_BURST_SECONDS:
            current.append(tx)
        else:
            if len(current) > len(best_run):
                best_run = current
            current = [tx]
    if len(current) > len(best_run):
        best_run = current

    if len(best_run) < LOOP_THRESHOLD:
        return None

    confidence = min(1.0, 0.5 + 0.5 * (len(best_run) - LOOP_THRESHOLD) / LOOP_THRESHOLD)
    spans = tuple(
        EvidenceSpan(slot=t.slot, tx_sig=t.signature, ix_index=0)
        for t in best_run
    )
    return DiagnosisFinding(
        label_bit=FailureMode.TOOL_LOOP.bit_length() - 1,
        confidence=confidence,
        evidence_spans=spans,
        remediation_codes=int(
            RemediationCode.PAUSE_AGENT | RemediationCode.REVIEW_TOOL_PERMISSIONS
        ),
        detector_id=DETECTOR_ID,
    )


# Surface thresholds for the kernel manifest hash.
THRESHOLDS: dict[str, int | float] = {
    "loop_threshold":     LOOP_THRESHOLD,
    "loop_burst_seconds": LOOP_BURST_SECONDS,
}
