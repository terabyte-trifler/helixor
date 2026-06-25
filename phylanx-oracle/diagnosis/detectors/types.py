"""
diagnosis/detectors/types.py — frozen finding + evidence-span shapes.

These are the wire types the eight Day-36 detectors emit. They are
deliberately small, hashable, and totally ordered so the kernel can
canonicalise findings into byte-identical JSON across nodes.

EvidenceSpan
------------
References a single instruction inside a single transaction:

    slot      — Solana slot number (int)
    tx_sig    — full base-58 signature string
    ix_index  — index into Transaction.program_ids (the invocation order)

A detector may attach multiple spans to one finding; the kernel sorts them
into canonical (slot, tx_sig, ix_index) order at emit time.

DiagnosisFinding
----------------
A detector's positive emission:

    label_bit         — the FailureMode bit raised (single bit)
    confidence        — 0.0 .. 1.0 (validated finite, clamped)
    evidence_spans    — canonical-ordered tuple of EvidenceSpan
    remediation_codes — RemediationCode bitmask (u32)
    detector_id       — the detector's stable id (e.g. "tool_loop@1")

Findings ARE NOT raised for "nothing wrong" cases — a clean detector
returns `None`. The kernel only stores positive emissions.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class EvidenceSpan:
    """One (slot, tx_sig, ix_index) pointer into the scanned window.

    `order=True` lets the kernel sort spans canonically without a helper.
    """
    slot:     int
    tx_sig:   str
    ix_index: int

    def __post_init__(self) -> None:
        if not isinstance(self.slot, int) or isinstance(self.slot, bool):
            raise TypeError("slot must be int")
        if self.slot < 0:
            raise ValueError(f"slot must be >= 0, got {self.slot}")
        if not isinstance(self.tx_sig, str) or not self.tx_sig:
            raise ValueError("tx_sig must be a non-empty str")
        if not isinstance(self.ix_index, int) or isinstance(self.ix_index, bool):
            raise TypeError("ix_index must be int")
        if self.ix_index < 0:
            raise ValueError(f"ix_index must be >= 0, got {self.ix_index}")


@dataclass(frozen=True, slots=True)
class DiagnosisFinding:
    """One detector's positive emission.

    The frozen dataclass enforces every wire invariant the kernel relies on:
        * `label_bit` is a single bit in [0, 63] (the u64 FailureMode space)
        * `confidence` is finite, in [0, 1]
        * `evidence_spans` is a canonical-ordered tuple of EvidenceSpan
        * `remediation_codes` fits in u32
        * `detector_id` is non-empty
    """
    label_bit:         int
    confidence:        float
    evidence_spans:    tuple[EvidenceSpan, ...]
    remediation_codes: int
    detector_id:       str

    def __post_init__(self) -> None:
        if not isinstance(self.label_bit, int) or isinstance(self.label_bit, bool):
            raise TypeError("label_bit must be int")
        if not (0 <= self.label_bit <= 63):
            raise ValueError(f"label_bit must be in [0, 63], got {self.label_bit}")

        if not isinstance(self.confidence, float):
            raise TypeError("confidence must be float")
        if not math.isfinite(self.confidence):
            raise ValueError(f"confidence must be finite, got {self.confidence!r}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence {self.confidence} outside [0, 1]")

        if not isinstance(self.evidence_spans, tuple):
            raise TypeError("evidence_spans must be a tuple")
        for s in self.evidence_spans:
            if not isinstance(s, EvidenceSpan):
                raise TypeError(
                    f"evidence_spans must contain EvidenceSpan, got {type(s).__name__}"
                )
        # Canonicalise span order at emit time so two nodes that build the
        # same spans in different orders still produce byte-identical JSON.
        canonical = tuple(sorted(self.evidence_spans))
        if canonical != self.evidence_spans:
            object.__setattr__(self, "evidence_spans", canonical)

        if not isinstance(self.remediation_codes, int) or isinstance(self.remediation_codes, bool):
            raise TypeError("remediation_codes must be int")
        if not (0 <= self.remediation_codes <= 0xFFFF_FFFF):
            raise ValueError(
                f"remediation_codes {self.remediation_codes} does not fit in u32"
            )

        if not isinstance(self.detector_id, str) or not self.detector_id:
            raise ValueError("detector_id must be a non-empty str")

    @property
    def label_value(self) -> int:
        """The single-bit `1 << label_bit` value for ORing into a bitmask."""
        return 1 << self.label_bit
