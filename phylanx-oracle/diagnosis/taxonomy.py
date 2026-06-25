"""
diagnosis/taxonomy.py — the frozen v1 failure-mode bit layout.

`FailureMode` is a u64 IntFlag. The bit positions are the on-chain
contract: a Phylanx diagnosis certificate's `failure_mode_bitmask`
field is interpreted exactly through this enum, and downstream
consumers (web app, indexer, insurer dashboards) re-import this
file as the single source of truth.

LAYOUT
------
LOW 32 BITS  — LEGACY (mirror of detection.types.FlagBit)
    The pre-diagnosis "flags" field was a u32 FlagBit bitmask. To stay
    layout-compatible with deployed certs (and to let consumers process
    a `failure_mode_bitmask & 0xFFFF_FFFF` as a legacy flags field
    verbatim), every populated FlagBit position is mirrored 1:1 into
    the low 32 bits of FailureMode.

    A module-import-time assertion verifies the mirror property — if
    FlagBit ever drifts, importing this file fails loudly.

HIGH 32 BITS — DIAGNOSIS (NEW, OWASP-aligned)
    The new diagnostic labels — practitioner failure modes (TOOL_LOOP,
    HALLUCINATION_CASCADE, …) and OWASP LLM Top 10 2025 / Agentic
    Applications Top 10 2026 categories.

    Bits 32 through 62 are the labelled slots. Bit 63 is reserved
    (intentionally left unset) — packing it later would force a
    breaking on-chain bump.

SEVERITY
--------
Every FailureMode bit MUST have an associated `Severity` recorded in
`LABEL_METADATA`. A bit with no severity is a taxonomy bug — the
"trace-tier-unset invariant" test enforces this. There is no
"unset" tier at runtime; if you can't decide what tier a label
belongs to, do not ship the label.

OWASP REFS
----------
Each label declares the OWASP entries it traces to in
`LABEL_METADATA[bit].owasp_refs`. Empty tuple means "not OWASP-mapped"
(practitioner-only failure mode); the field must still exist.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from detection.types import FlagBit

from .remediation import RemediationCode


# =============================================================================
# Severity — per-label tier independent of the cert-wide alert_tier
# =============================================================================

class Severity(enum.IntEnum):
    """
    Per-label severity ranking. Independent of the cert-wide alert_tier
    (GREEN/YELLOW/RED) so a single cert can carry mixed-severity labels
    without losing fidelity. Numerical values are ordered so the
    aggregate severity over a bitmask is `max()` of the per-bit values.
    """
    INFO     = 0    # observability only; no action required
    LOW      = 1    # informational with weak recommendation
    MED      = 2    # actionable; investigation recommended
    HIGH     = 3    # actionable; containment recommended
    CRITICAL = 4    # actionable; immediate containment + escalation


# =============================================================================
# FailureMode — the u64 frozen layout
# =============================================================================

class FailureMode(enum.IntFlag):
    """
    u64 bitmask of agent failure modes. Bit positions are frozen and
    on-chain-load-bearing.

    LOW 32 — legacy passthrough of detection.types.FlagBit
    HIGH 32 — diagnosis labels (OWASP-aligned + practitioner)
    """

    # ── LOW 32 — legacy passthrough (mirrors detection.types.FlagBit) ─────
    PROVISIONAL              = 1 << 0
    INSUFFICIENT_DATA        = 1 << 1
    INCOMPATIBLE_INPUT       = 1 << 2
    IMMEDIATE_RED            = 1 << 3
    DEGRADED_BASELINE        = 1 << 4
    ENSEMBLE_INCOMPLETE      = 1 << 5
    DIMENSION_CLAMPED        = 1 << 6
    INPUT_DIVERGENCE         = 1 << 7
    SOURCE_DISAGREEMENT      = 1 << 29

    # ── HIGH 32 — OWASP LLM Top 10 (2025) + Agentic Top 10 (2026) ─────────
    PROMPT_INJECTION             = 1 << 32   # LLM01:2025
    AGENT_GOAL_HIJACK            = 1 << 33   # ASI01:2026
    TOOL_MISUSE                  = 1 << 34   # ASI02:2026
    TOOL_LOOP                    = 1 << 35   # ASI02:2026 (sub-mode)
    EXCESSIVE_AGENCY             = 1 << 36   # LLM06:2025
    IDENTITY_PRIVILEGE_ABUSE     = 1 << 37   # ASI03:2026
    SUPPLY_CHAIN_COMPROMISE      = 1 << 38   # LLM03:2025 + ASI04:2026
    UNEXPECTED_CODE_EXECUTION    = 1 << 39   # ASI05:2026
    MEMORY_POISONING             = 1 << 40   # ASI06:2026
    CONTEXT_POISONING            = 1 << 41   # ASI06:2026
    INSECURE_INTER_AGENT_COMM    = 1 << 42   # ASI07:2026
    CASCADING_AGENT_FAILURE      = 1 << 43   # ASI08:2026
    HUMAN_TRUST_EXPLOITATION     = 1 << 44   # ASI09:2026
    ROGUE_AGENT                  = 1 << 45   # ASI10:2026
    SENSITIVE_INFO_DISCLOSURE    = 1 << 46   # LLM02:2025
    DATA_MODEL_POISONING         = 1 << 47   # LLM04:2025
    IMPROPER_OUTPUT_HANDLING     = 1 << 48   # LLM05:2025
    SYSTEM_PROMPT_LEAK           = 1 << 49   # LLM07:2025
    VECTOR_EMBEDDING_WEAKNESS    = 1 << 50   # LLM08:2025
    MISINFORMATION               = 1 << 51   # LLM09:2025
    UNBOUNDED_CONSUMPTION        = 1 << 52   # LLM10:2025

    # ── HIGH 32 — practitioner failure modes (no OWASP id) ────────────────
    HALLUCINATION_CASCADE        = 1 << 53
    OUTPUT_DISTRIBUTION_DRIFT    = 1 << 54
    CONTEXT_WINDOW_EXHAUSTION    = 1 << 55
    LATENCY_DEGRADATION          = 1 << 56
    COST_BLOWUP                  = 1 << 57
    ALIGNMENT_REGRESSION         = 1 << 58
    DATA_LEAKAGE                 = 1 << 59
    JAILBREAK                    = 1 << 60
    SUB_AGENT_DEADLOCK           = 1 << 61
    ROLE_CONFUSION               = 1 << 62
    # Bit 63 is INTENTIONALLY RESERVED. Do not pack.


# u64 ceiling — the on-chain field width.
FAILURE_MODE_BITS:  int = 64
FAILURE_MODE_MAX:   int = (1 << FAILURE_MODE_BITS) - 1
LEGACY_MASK:        int = 0xFFFF_FFFF
LEGACY_MASK_BITS:   int = 32


# =============================================================================
# Label metadata — single source of truth for decode, JSON export, docs
# =============================================================================

@dataclass(frozen=True, slots=True)
class LabelMetadata:
    """
    Per-label metadata. One entry per FailureMode bit.

    Every field is mandatory. The frozen dataclass + import-time
    completeness check enforces the "trace-tier-unset invariant" —
    no label may ship without a tier, description, OWASP-ref slot,
    and a default remediation.
    """
    name:                str
    bit:                 int                  # position in [0, 63]
    description:         str
    severity:            Severity
    owasp_refs:          tuple[str, ...]      # may be empty (practitioner-only)
    default_remediation: RemediationCode      # may be 0 if no default exists


def _md(
    mode:        FailureMode,
    *,
    description: str,
    severity:    Severity,
    owasp_refs:  tuple[str, ...],
    remediation: RemediationCode,
) -> tuple[FailureMode, LabelMetadata]:
    """Compact builder — the bit position is derived from the mode itself."""
    bit_pos = int(mode).bit_length() - 1
    return mode, LabelMetadata(
        name                = mode.name,
        bit                 = bit_pos,
        description         = description,
        severity            = severity,
        owasp_refs          = owasp_refs,
        default_remediation = remediation,
    )


# Build the metadata table in one place. Order = bit-position ascending
# so reviewers can eyeball gaps.
_RAW_METADATA: tuple[tuple[FailureMode, LabelMetadata], ...] = (
    # ── LOW 32 (legacy) ────────────────────────────────────────────────────
    _md(
        FailureMode.PROVISIONAL,
        description = "detector ran with thin data — outputs are low confidence",
        severity    = Severity.INFO,
        owasp_refs  = (),
        remediation = RemediationCode.COLLECT_EVIDENCE,
    ),
    _md(
        FailureMode.INSUFFICIENT_DATA,
        description = "detector refused to run; the score is a default placeholder",
        severity    = Severity.LOW,
        owasp_refs  = (),
        remediation = RemediationCode.COLLECT_EVIDENCE,
    ),
    _md(
        FailureMode.INCOMPATIBLE_INPUT,
        description = "baseline or feature vector was rejected by the detector",
        severity    = Severity.LOW,
        owasp_refs  = (),
        remediation = (
            RemediationCode.RUN_FRESH_BASELINE
            | RemediationCode.COLLECT_EVIDENCE
        ),
    ),
    _md(
        FailureMode.IMMEDIATE_RED,
        description = "fast-path RED — composite scorer demands immediate flag",
        severity    = Severity.CRITICAL,
        owasp_refs  = (),
        remediation = (
            RemediationCode.PAUSE_AGENT
            | RemediationCode.ALERT_OPERATORS
            | RemediationCode.ENGAGE_HUMAN_REVIEW
        ),
    ),
    _md(
        FailureMode.DEGRADED_BASELINE,
        description = "active baseline is provisional — drift readings are weak",
        severity    = Severity.LOW,
        owasp_refs  = (),
        remediation = RemediationCode.RUN_FRESH_BASELINE,
    ),
    _md(
        FailureMode.ENSEMBLE_INCOMPLETE,
        description = "VULN-24 — fewer than 3 of 5 detectors fired (evasion suspect)",
        severity    = Severity.MED,
        owasp_refs  = (),
        remediation = (
            RemediationCode.COLLECT_EVIDENCE
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.DIMENSION_CLAMPED,
        description = "per-dimension velocity guard fired (single-detector pump suspect)",
        severity    = Severity.LOW,
        owasp_refs  = (),
        remediation = RemediationCode.AUDIT_RECENT_OUTPUTS,
    ),
    _md(
        FailureMode.INPUT_DIVERGENCE,
        description = "AW-01 — at least one node's input commitment differed from majority",
        severity    = Severity.MED,
        owasp_refs  = (),
        remediation = (
            RemediationCode.COLLECT_EVIDENCE
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.SOURCE_DISAGREEMENT,
        description = "AW-01-EXT — a node saw upstream RPC fleet disagreement",
        severity    = Severity.MED,
        owasp_refs  = (),
        remediation = (
            RemediationCode.COLLECT_EVIDENCE
            | RemediationCode.ALERT_OPERATORS
        ),
    ),

    # ── HIGH 32 (OWASP + practitioner) ─────────────────────────────────────
    _md(
        FailureMode.PROMPT_INJECTION,
        description = "user-supplied prompt steered the agent off its declared task",
        severity    = Severity.HIGH,
        owasp_refs  = ("LLM01:2025",),
        remediation = (
            RemediationCode.PATCH_PROMPT_GUARD
            | RemediationCode.ENABLE_OUTPUT_FILTER
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.AGENT_GOAL_HIJACK,
        description = "agent's declared goal was redefined mid-execution by external input",
        severity    = Severity.CRITICAL,
        owasp_refs  = ("ASI01:2026",),
        remediation = (
            RemediationCode.PAUSE_AGENT
            | RemediationCode.ENGAGE_HUMAN_REVIEW
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.TOOL_MISUSE,
        description = "tool was invoked with malformed args or outside its declared contract",
        severity    = Severity.HIGH,
        owasp_refs  = ("ASI02:2026",),
        remediation = (
            RemediationCode.REVIEW_TOOL_PERMISSIONS
            | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
    ),
    _md(
        FailureMode.TOOL_LOOP,
        description = "tool call repeated past the loop budget (cost + latency runaway)",
        severity    = Severity.MED,
        owasp_refs  = ("ASI02:2026",),
        remediation = (
            RemediationCode.PAUSE_AGENT
            | RemediationCode.REVIEW_TOOL_PERMISSIONS
        ),
    ),
    _md(
        FailureMode.EXCESSIVE_AGENCY,
        description = "agent exercised authority beyond the operator's declared scope",
        severity    = Severity.HIGH,
        owasp_refs  = ("LLM06:2025",),
        remediation = (
            RemediationCode.REDUCE_AUTONOMY
            | RemediationCode.REVIEW_TOOL_PERMISSIONS
        ),
    ),
    _md(
        FailureMode.IDENTITY_PRIVILEGE_ABUSE,
        description = "agent assumed or escalated to an identity / role it should not hold",
        severity    = Severity.CRITICAL,
        owasp_refs  = ("ASI03:2026",),
        remediation = (
            RemediationCode.REVOKE_AGENT_IDENTITY
            | RemediationCode.ROTATE_API_KEYS
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.SUPPLY_CHAIN_COMPROMISE,
        description = "a dependency, model, or pinned artefact failed integrity verification",
        severity    = Severity.CRITICAL,
        owasp_refs  = ("LLM03:2025", "ASI04:2026"),
        remediation = (
            RemediationCode.VERIFY_SUPPLY_CHAIN
            | RemediationCode.ISOLATE_AGENT
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.UNEXPECTED_CODE_EXECUTION,
        description = "agent executed code outside its sandbox or declared interpreter",
        severity    = Severity.CRITICAL,
        owasp_refs  = ("ASI05:2026",),
        remediation = (
            RemediationCode.ISOLATE_AGENT
            | RemediationCode.PAUSE_AGENT
            | RemediationCode.ALERT_OPERATORS
            | RemediationCode.COLLECT_EVIDENCE
        ),
    ),
    _md(
        FailureMode.MEMORY_POISONING,
        description = "stored memory entries contradict baseline distribution — write injection",
        severity    = Severity.HIGH,
        owasp_refs  = ("ASI06:2026",),
        remediation = (
            RemediationCode.CLEAR_AGENT_MEMORY
            | RemediationCode.SCAN_MEMORY_STORE
        ),
    ),
    _md(
        FailureMode.CONTEXT_POISONING,
        description = "in-session context window was steered by injected retrieved content",
        severity    = Severity.HIGH,
        owasp_refs  = ("ASI06:2026",),
        remediation = (
            RemediationCode.CLEAR_AGENT_MEMORY
            | RemediationCode.RESTART_AGENT_SESSION
        ),
    ),
    _md(
        FailureMode.INSECURE_INTER_AGENT_COMM,
        description = "peer-to-peer message lacked authentication or used an untrusted channel",
        severity    = Severity.HIGH,
        owasp_refs  = ("ASI07:2026",),
        remediation = (
            RemediationCode.BLOCK_AGENT_PEER
            | RemediationCode.VERIFY_AGENT_IDENTITY
        ),
    ),
    _md(
        FailureMode.CASCADING_AGENT_FAILURE,
        description = "a peer agent's bad output corrupted this agent's downstream chain",
        severity    = Severity.HIGH,
        owasp_refs  = ("ASI08:2026",),
        remediation = (
            RemediationCode.PAUSE_AGENT
            | RemediationCode.ISOLATE_AGENT
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.HUMAN_TRUST_EXPLOITATION,
        description = "agent output exploited user trust patterns (urgency, authority cues)",
        severity    = Severity.MED,
        owasp_refs  = ("ASI09:2026",),
        remediation = (
            RemediationCode.ENABLE_OUTPUT_FILTER
            | RemediationCode.ENGAGE_HUMAN_REVIEW
        ),
    ),
    _md(
        FailureMode.ROGUE_AGENT,
        description = "agent acted against its declared principal — full identity divergence",
        severity    = Severity.CRITICAL,
        owasp_refs  = ("ASI10:2026",),
        remediation = (
            RemediationCode.ISOLATE_AGENT
            | RemediationCode.REVOKE_AGENT_IDENTITY
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.SENSITIVE_INFO_DISCLOSURE,
        description = "agent surfaced data outside its declared confidentiality scope",
        severity    = Severity.HIGH,
        owasp_refs  = ("LLM02:2025",),
        remediation = (
            RemediationCode.ENABLE_OUTPUT_FILTER
            | RemediationCode.AUDIT_RECENT_OUTPUTS
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.DATA_MODEL_POISONING,
        description = "training / fine-tuning artefacts diverged from approved provenance",
        severity    = Severity.HIGH,
        owasp_refs  = ("LLM04:2025",),
        remediation = (
            RemediationCode.RUN_FRESH_BASELINE
            | RemediationCode.ROLLBACK_MODEL_VERSION
        ),
    ),
    _md(
        FailureMode.IMPROPER_OUTPUT_HANDLING,
        description = "downstream consumer received insufficiently sanitised agent output",
        severity    = Severity.MED,
        owasp_refs  = ("LLM05:2025",),
        remediation = (
            RemediationCode.ENABLE_OUTPUT_FILTER
            | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
    ),
    _md(
        FailureMode.SYSTEM_PROMPT_LEAK,
        description = "internal system prompt or hidden instructions surfaced in output",
        severity    = Severity.MED,
        owasp_refs  = ("LLM07:2025",),
        remediation = (
            RemediationCode.PATCH_PROMPT_GUARD
            | RemediationCode.ENABLE_OUTPUT_FILTER
        ),
    ),
    _md(
        FailureMode.VECTOR_EMBEDDING_WEAKNESS,
        description = "retrieval / embedding step admitted adversarial or malformed vectors",
        severity    = Severity.MED,
        owasp_refs  = ("LLM08:2025",),
        remediation = (
            RemediationCode.TIGHTEN_RETRIEVAL_FILTER
            | RemediationCode.SCAN_MEMORY_STORE
        ),
    ),
    _md(
        FailureMode.MISINFORMATION,
        description = "output contained factually wrong claims at material rate",
        severity    = Severity.MED,
        owasp_refs  = ("LLM09:2025",),
        remediation = (
            RemediationCode.ENABLE_OUTPUT_FILTER
            | RemediationCode.TIGHTEN_RETRIEVAL_FILTER
        ),
    ),
    _md(
        FailureMode.UNBOUNDED_CONSUMPTION,
        description = "per-call resource use exceeded declared envelope (tokens, cost, time)",
        severity    = Severity.MED,
        owasp_refs  = ("LLM10:2025",),
        remediation = (
            RemediationCode.DECREASE_RATE_LIMITS
            | RemediationCode.PAUSE_AGENT
        ),
    ),
    _md(
        FailureMode.HALLUCINATION_CASCADE,
        description = "a hallucinated step in a chain corrupted every dependent downstream step",
        severity    = Severity.HIGH,
        owasp_refs  = (),
        remediation = (
            RemediationCode.CLEAR_AGENT_MEMORY
            | RemediationCode.RESTART_AGENT_SESSION
            | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
    ),
    _md(
        FailureMode.OUTPUT_DISTRIBUTION_DRIFT,
        description = "output distribution diverged materially from the established baseline",
        severity    = Severity.MED,
        owasp_refs  = (),
        remediation = (
            RemediationCode.RUN_FRESH_BASELINE
            | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
    ),
    _md(
        FailureMode.CONTEXT_WINDOW_EXHAUSTION,
        description = "context window filled — agent began truncating load-bearing history",
        severity    = Severity.LOW,
        owasp_refs  = (),
        remediation = (
            RemediationCode.RESTART_AGENT_SESSION
            | RemediationCode.CLEAR_AGENT_MEMORY
        ),
    ),
    _md(
        FailureMode.LATENCY_DEGRADATION,
        description = "per-call latency exceeded SLO baseline by sustained margin",
        severity    = Severity.LOW,
        owasp_refs  = (),
        remediation = (
            RemediationCode.AUDIT_RECENT_OUTPUTS
            | RemediationCode.INCREASE_RATE_LIMITS
        ),
    ),
    _md(
        FailureMode.COST_BLOWUP,
        description = "spend per task exceeded declared budget envelope",
        severity    = Severity.MED,
        owasp_refs  = (),
        remediation = (
            RemediationCode.DECREASE_RATE_LIMITS
            | RemediationCode.AUDIT_RECENT_OUTPUTS
        ),
    ),
    _md(
        FailureMode.ALIGNMENT_REGRESSION,
        description = "behavioural alignment metrics regressed after a model / config swap",
        severity    = Severity.HIGH,
        owasp_refs  = (),
        remediation = (
            RemediationCode.ROLLBACK_MODEL_VERSION
            | RemediationCode.ENGAGE_HUMAN_REVIEW
        ),
    ),
    _md(
        FailureMode.DATA_LEAKAGE,
        description = "training / customer data leaked into outputs against confidentiality policy",
        severity    = Severity.HIGH,
        owasp_refs  = (),
        remediation = (
            RemediationCode.ENABLE_OUTPUT_FILTER
            | RemediationCode.AUDIT_RECENT_OUTPUTS
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.JAILBREAK,
        description = "safety filter bypassed via known or novel jailbreak technique",
        severity    = Severity.HIGH,
        owasp_refs  = (),
        remediation = (
            RemediationCode.PATCH_PROMPT_GUARD
            | RemediationCode.ENABLE_OUTPUT_FILTER
            | RemediationCode.ALERT_OPERATORS
        ),
    ),
    _md(
        FailureMode.SUB_AGENT_DEADLOCK,
        description = "sub-agents stalled in mutual wait — no forward progress",
        severity    = Severity.MED,
        owasp_refs  = (),
        remediation = (
            RemediationCode.RESTART_AGENT_SESSION
            | RemediationCode.ISOLATE_AGENT
        ),
    ),
    _md(
        FailureMode.ROLE_CONFUSION,
        description = "agent confused its declared role with that of a peer or user",
        severity    = Severity.MED,
        owasp_refs  = (),
        remediation = (
            RemediationCode.CLEAR_AGENT_MEMORY
            | RemediationCode.RESTART_AGENT_SESSION
        ),
    ),
)


LABEL_METADATA: Mapping[FailureMode, LabelMetadata] = MappingProxyType(
    dict(_RAW_METADATA)
)


# =============================================================================
# Module-import-time invariants
# =============================================================================
#
# Every assertion below is a HARD invariant — if it fails at import time
# the module refuses to load, surfacing the taxonomy bug to whoever
# imported it. The same invariants are also pinned by explicit tests in
# `tests/diagnosis/test_taxonomy_v1.py`; the runtime check is the
# defence-in-depth backup.

def _verify_taxonomy_invariants() -> None:
    # 1. Every FailureMode member maps to exactly one bit.
    for m in FailureMode:
        v = int(m)
        if v <= 0 or (v & (v - 1)) != 0:
            raise AssertionError(
                f"FailureMode.{m.name} = {v:#x} is not a single bit value"
            )

    # 2. Every FailureMode bit fits in u64.
    for m in FailureMode:
        if int(m) > FAILURE_MODE_MAX:
            raise AssertionError(
                f"FailureMode.{m.name} = {int(m):#x} exceeds the u64 ceiling"
            )

    # 3. Bit positions are unique.
    seen: set[int] = set()
    for m in FailureMode:
        bit_pos = int(m).bit_length() - 1
        if bit_pos in seen:
            raise AssertionError(
                f"FailureMode.{m.name} bit {bit_pos} is duplicated"
            )
        seen.add(bit_pos)

    # 4. Legacy passthrough — every FlagBit member must equal exactly
    #    one FailureMode low-32 member by VALUE.
    legacy_values: dict[int, FailureMode] = {
        int(m): m for m in FailureMode if int(m) <= LEGACY_MASK
    }
    for fb in FlagBit:
        v = int(fb)
        if v not in legacy_values:
            raise AssertionError(
                f"detection.types.FlagBit.{fb.name} = {v:#x} has no matching "
                f"FailureMode low-32 member — legacy passthrough broken"
            )
        # The names should also match — a rename without taxonomy
        # update is a taxonomy bug.
        matched = legacy_values[v]
        if matched.name != fb.name:
            raise AssertionError(
                f"FlagBit.{fb.name} maps to FailureMode.{matched.name} by "
                f"value but the names differ — keep names in sync to avoid "
                f"silent semantic drift"
            )

    # 5. Every FailureMode member has metadata recorded.
    for m in FailureMode:
        if m not in LABEL_METADATA:
            raise AssertionError(
                f"FailureMode.{m.name} has no LABEL_METADATA entry — "
                f"the 'trace-tier-unset invariant' refuses to ship a "
                f"label without a Severity / description / remediation"
            )

    # 6. LABEL_METADATA does not declare metadata for unknown bits.
    metadata_modes = set(LABEL_METADATA.keys())
    actual_modes = set(FailureMode)
    extras = metadata_modes - actual_modes
    if extras:
        raise AssertionError(
            f"LABEL_METADATA references unknown FailureMode value(s): "
            f"{sorted(int(e) for e in extras)}"
        )

    # 7. Bit 63 is reserved — no member claims it.
    for m in FailureMode:
        if int(m) == (1 << 63):
            raise AssertionError(
                f"FailureMode.{m.name} claims the reserved bit 63"
            )


_verify_taxonomy_invariants()
