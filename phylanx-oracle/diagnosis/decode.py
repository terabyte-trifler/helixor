"""
diagnosis/decode.py — bitmask -> structured diagnosis output.

The on-chain certificate carries a `failure_mode_bitmask: u64` and a
`remediation_codes: u32`. Consumers (API responses, web UI, indexer)
call `decode(mask)` to turn the bitmask into a tuple of `DecodedLabel`
records that include the human-readable name, description, severity,
OWASP references, and default remediation hint per set bit.

DESIGN
------
- Stateless. All metadata is read from `taxonomy.LABEL_METADATA`.
- Deterministic. Output order is bit-position ascending.
- Tolerant of EMPTY masks — `decode(0)` returns `()`, not an error.
- Strict on UNKNOWN bits — a set bit with no LABEL_METADATA entry
  raises. The taxonomy invariants in `taxonomy.py` guarantee this
  cannot happen for any FailureMode member at import time, so an
  unknown bit can only come from a bitmask with stray bits set —
  almost always a serialisation bug worth surfacing.
"""

from __future__ import annotations

from dataclasses import dataclass

from .remediation import RemediationCode
from .taxonomy import (
    FAILURE_MODE_MAX,
    FailureMode,
    LABEL_METADATA,
    Severity,
)


@dataclass(frozen=True, slots=True)
class DecodedLabel:
    """One label decoded from the bitmask. Mirrors LabelMetadata for
    consumer convenience but is the public, JSON-stable surface."""
    name:                str
    bit:                 int
    description:         str
    severity:            Severity
    owasp_refs:          tuple[str, ...]
    default_remediation: RemediationCode


def _check_u64(mask: int) -> None:
    if not isinstance(mask, int) or isinstance(mask, bool):
        raise TypeError(f"mask must be int, got {type(mask).__name__}")
    if not (0 <= mask <= FAILURE_MODE_MAX):
        raise ValueError(
            f"mask {mask:#x} does not fit in u64 (0..{FAILURE_MODE_MAX:#x})"
        )


def decode(mask: int) -> tuple[DecodedLabel, ...]:
    """
    Decode a u64 FailureMode bitmask into an ordered tuple of
    DecodedLabel records, low-bit first.

    `decode(0) == ()` is the canonical "no failure modes" output.

    Raises ValueError if a set bit has no taxonomy entry — a guarded
    detection of bitmask corruption.
    """
    _check_u64(mask)
    if mask == 0:
        return ()

    out: list[DecodedLabel] = []
    bit = 0
    remaining = mask
    while remaining:
        if remaining & 1:
            v = 1 << bit
            mode = FailureMode(v) if v in FailureMode._value2member_map_ else None
            if mode is None:
                raise ValueError(
                    f"bit {bit} ({v:#x}) is set but is not a known "
                    f"FailureMode member"
                )
            meta = LABEL_METADATA[mode]
            out.append(DecodedLabel(
                name                = meta.name,
                bit                 = meta.bit,
                description         = meta.description,
                severity            = meta.severity,
                owasp_refs          = meta.owasp_refs,
                default_remediation = meta.default_remediation,
            ))
        remaining >>= 1
        bit += 1
    return tuple(out)


def default_remediation(mask: int) -> RemediationCode:
    """
    Aggregate the default `RemediationCode` u32 bitmask over every set
    `FailureMode` bit. `default_remediation(0)` returns an empty
    RemediationCode (i.e. `RemediationCode(0)`).
    """
    out = RemediationCode(0)
    for label in decode(mask):
        out |= label.default_remediation
    return out


def severity_of(mask: int) -> Severity:
    """
    The maximum `Severity` across every set `FailureMode` bit.
    Empty mask -> `Severity.INFO` (the floor).
    """
    decoded = decode(mask)
    if not decoded:
        return Severity.INFO
    return max(label.severity for label in decoded)
