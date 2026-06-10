"""
diagnosis/ — Helixor on-chain diagnosis taxonomy v1.

The pivot from "score-only" to "diagnosis": every Helixor certificate
will eventually carry a `failure_mode_bitmask: u64` and a
`remediation_codes: u32`. This package owns the frozen bit layout
for both, plus the decode helpers consumers (API, web, downstream
indexers) call to render the human-meaningful labels.

PUBLIC SURFACE
--------------
- taxonomy.FailureMode       — u64 IntFlag, low 32 bits mirror legacy
                               detection.types.FlagBit; high 32 bits
                               carry the OWASP-aligned diagnosis labels.
- remediation.RemediationCode — u32 IntFlag of actionable remediations.
- decode.decode               — bitmask -> ordered tuple of DecodedLabel.
- decode.default_remediation  — bitmask -> aggregated RemediationCode mask.
- decode.severity_of          — bitmask -> max severity across set bits.

The bit layout is FROZEN by pin tests in
`tests/diagnosis/test_taxonomy_v1.py`. Bumping a bit position is a
breaking on-chain change.
"""

from .taxonomy import (
    FailureMode,
    Severity,
    LABEL_METADATA,
    LabelMetadata,
)
from .remediation import RemediationCode
from .decode import (
    DecodedLabel,
    decode,
    default_remediation,
    severity_of,
)

__all__ = (
    "FailureMode",
    "Severity",
    "LABEL_METADATA",
    "LabelMetadata",
    "RemediationCode",
    "DecodedLabel",
    "decode",
    "default_remediation",
    "severity_of",
)
