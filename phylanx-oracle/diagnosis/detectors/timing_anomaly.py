"""
diagnosis/detectors/timing_anomaly.py — sustained latency / inter-call gap
collapse.

A timing anomaly here means: the inter-arrival time between the agent's
transactions has collapsed below a sane floor. If the median inter-arrival
falls under `MIN_INTERARRIVAL_SECONDS` over `MIN_SAMPLE` adjacent pairs,
that is a bot-rate burst — we raise `FailureMode.LATENCY_DEGRADATION`
(bit 56) since the latency dimension is where the failure lives in v1.

We use the MEDIAN, not the minimum, so a single accidentally-fast pair
does not trip the detector. Confidence ramps from 0.5 at the threshold to
1.0 as the median drops toward zero.

Evidence: every transaction inside the fastest contiguous run of length
`MIN_SAMPLE` (inclusive) — both endpoints carry the signal.
"""

from __future__ import annotations

from collections.abc import Sequence

from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from ._canon import canonical_window_txs
from .types import DiagnosisFinding, EvidenceSpan

DETECTOR_ID:              str   = "timing_anomaly@1"
MIN_SAMPLE:               int   = 8     # adjacent gaps required to trip
MIN_INTERARRIVAL_SECONDS: float = 0.5   # below this median = bot burst


def _median(xs: list[float]) -> float:
    xs_sorted = sorted(xs)
    n = len(xs_sorted)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return xs_sorted[mid]
    return 0.5 * (xs_sorted[mid - 1] + xs_sorted[mid])


def detect(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> DiagnosisFinding | None:
    txs = canonical_window_txs(transactions, window)
    if len(txs) < MIN_SAMPLE + 1:
        return None

    gaps = [
        (txs[i + 1].block_time - txs[i].block_time).total_seconds()
        for i in range(len(txs) - 1)
    ]

    # Slide a window of MIN_SAMPLE consecutive gaps; find the run with
    # the lowest median. Equal medians: keep the earliest run (canonical).
    best_start = -1
    best_median = float("inf")
    for i in range(len(gaps) - MIN_SAMPLE + 1):
        med = _median(gaps[i : i + MIN_SAMPLE])
        if med < best_median:
            best_median = med
            best_start = i

    if best_start < 0 or best_median >= MIN_INTERARRIVAL_SECONDS:
        return None

    confidence = min(
        1.0,
        0.5 + 0.5 * (MIN_INTERARRIVAL_SECONDS - best_median) / MIN_INTERARRIVAL_SECONDS,
    )
    # Evidence spans = MIN_SAMPLE + 1 txs that bracket the fastest run.
    sample = txs[best_start : best_start + MIN_SAMPLE + 1]
    spans = tuple(
        EvidenceSpan(slot=t.slot, tx_sig=t.signature, ix_index=0)
        for t in sample
    )
    return DiagnosisFinding(
        label_bit=FailureMode.LATENCY_DEGRADATION.bit_length() - 1,
        confidence=confidence,
        evidence_spans=spans,
        remediation_codes=int(
            RemediationCode.DECREASE_RATE_LIMITS | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
        detector_id=DETECTOR_ID,
    )


THRESHOLDS: dict[str, int | float] = {
    "min_sample":               MIN_SAMPLE,
    "min_interarrival_seconds": MIN_INTERARRIVAL_SECONDS,
}
