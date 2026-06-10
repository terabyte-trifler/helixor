"""
diagnosis/detectors/counterparty_concentration.py — a single counterparty
absorbs an outsized share of the agent's window.

Concentration is a structural-risk signal — a single peer becoming the
agent's gravity well looks like `FailureMode.IDENTITY_PRIVILEGE_ABUSE`
(bit 37, OWASP ASI03:2026) when the dominance is severe.

DETECTION
---------
Count, per counterparty, the number of transactions in the window. Skip
transactions with `counterparty is None` (multi-party / unclear). If the
top counterparty accounts for >= `MAX_SHARE` of the typed counterparty
flow AND total typed transactions >= `MIN_TYPED_TXS`, raise the finding.
Confidence ramps from 0.5 at MAX_SHARE to 1.0 at 1.0.

Evidence: every tx that hit the dominant counterparty.
"""

from __future__ import annotations

from collections.abc import Sequence

from diagnosis.remediation import RemediationCode
from diagnosis.taxonomy import FailureMode
from features.types import ExtractionWindow, Transaction

from ._canon import canonical_window_txs
from .types import DiagnosisFinding, EvidenceSpan

DETECTOR_ID:   str   = "counterparty_concentration@1"
MIN_TYPED_TXS: int   = 8     # below this, dominance is noise
MAX_SHARE:     float = 0.80  # one peer absorbing >= 80% of typed flow


def detect(
    transactions: Sequence[Transaction],
    window:       ExtractionWindow,
) -> DiagnosisFinding | None:
    txs = canonical_window_txs(transactions, window)
    typed = [t for t in txs if t.counterparty]
    if len(typed) < MIN_TYPED_TXS:
        return None

    counts: dict[str, int] = {}
    for t in typed:
        counts[t.counterparty] = counts.get(t.counterparty, 0) + 1

    # Deterministic tiebreak: highest count, then lexicographic counterparty.
    top_cp = min(counts, key=lambda cp: (-counts[cp], cp))
    share = counts[top_cp] / len(typed)
    if share < MAX_SHARE:
        return None

    confidence = min(1.0, 0.5 + 0.5 * (share - MAX_SHARE) / max(1e-9, 1.0 - MAX_SHARE))
    spans = tuple(
        EvidenceSpan(slot=t.slot, tx_sig=t.signature, ix_index=0)
        for t in typed
        if t.counterparty == top_cp
    )
    return DiagnosisFinding(
        label_bit=FailureMode.IDENTITY_PRIVILEGE_ABUSE.bit_length() - 1,
        confidence=confidence,
        evidence_spans=spans,
        remediation_codes=int(
            RemediationCode.BLOCK_AGENT_PEER
            | RemediationCode.VERIFY_AGENT_IDENTITY
            | RemediationCode.ALERT_OPERATORS
        ),
        detector_id=DETECTOR_ID,
    )


THRESHOLDS: dict[str, int | float] = {
    "min_typed_txs": MIN_TYPED_TXS,
    "max_share":     MAX_SHARE,
}
