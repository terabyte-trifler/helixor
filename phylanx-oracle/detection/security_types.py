"""
detection/security_types.py — typed contracts for the security layer.

Day 9 builds the attack-pattern library and the `scan()` function. The
scanner consumes transactions + agent metadata and emits `SecuritySignal`s.
Day 10 turns those signals into the 0-150 security DimensionResult.

Every type here is a frozen, self-validating dataclass — the same
discipline as `DimensionResult` (Day 4) and `BaselineStats` (Day 2).

A NOTE ON THE PATTERN LIBRARY'S PROVENANCE
------------------------------------------
The Doc-2 brief refers to "the 31 MCP attack vectors from the security
paper". The concrete patterns in `security_patterns.py` are drawn from
well-established, publicly-documented agent/MCP threat CLASSES — prompt
injection, tool poisoning, data exfiltration, instruction override,
confused-deputy, permission escalation, and so on (cf. the OWASP LLM Top
10 and the MCP security literature). The library is structured so the
exact vectors from any specific internal paper can be dropped in by
editing one data file — the ENGINE is format-stable, the pattern SET is
data.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


# =============================================================================
# Severity
# =============================================================================

class Severity(enum.IntEnum):
    """
    Attack-pattern severity. IntEnum so signals sort naturally and the
    Day-10 scorer can weight by numeric severity.
    """
    INFO     = 1     # noteworthy, not itself harmful
    LOW      = 2     # minor — suspicious but plausibly benign
    MEDIUM   = 3     # likely malicious; warrants a score penalty
    HIGH     = 4     # strong attack signal
    CRITICAL = 5     # unambiguous attack — Day-10 will fast-path to RED

    @property
    def label(self) -> str:
        return self.name.lower()


# =============================================================================
# Detection method
# =============================================================================

class DetectionMethod(enum.Enum):
    """How a pattern decides whether it matched."""
    REGEX        = "regex"          # regex over textual fields (memo/log/metadata)
    SEMANTIC     = "semantic"       # token-Jaccard similarity to known-bad templates
    STRUCTURAL   = "structural"     # predicate over program IDs / account roles / shapes
    COMPOSITE    = "composite"      # combination — pattern defines its own logic


# =============================================================================
# Attack categories — the real threat CLASSES the library covers
# =============================================================================

class AttackCategory(enum.Enum):
    """
    Top-level threat classes. Each concrete pattern belongs to exactly one.
    These are real, publicly-documented agent/MCP threat categories.
    """
    PROMPT_INJECTION      = "prompt_injection"       # adversarial instructions in inputs
    TOOL_POISONING        = "tool_poisoning"         # malicious/altered tool definitions
    DATA_EXFILTRATION     = "data_exfiltration"      # covert outbound data movement
    INSTRUCTION_OVERRIDE  = "instruction_override"   # attempts to override system prompt
    CONFUSED_DEPUTY       = "confused_deputy"        # agent tricked into misusing authority
    PERMISSION_ESCALATION = "permission_escalation"  # acquiring authority beyond scope
    EXCESSIVE_AGENCY      = "excessive_agency"       # acting far outside declared domain
    SUPPLY_CHAIN          = "supply_chain"           # malicious dependency / program
    DENIAL_OF_WALLET      = "denial_of_wallet"       # fee/resource-draining behaviour
    SOCIAL_ENGINEERING    = "social_engineering"     # manipulation via crafted content


# =============================================================================
# ScanMetadata — agent context the scanner needs beyond per-tx records
# =============================================================================

@dataclass(frozen=True, slots=True)
class ScanMetadata:
    """
    Agent-level context for a scan. Carries what the per-transaction record
    cannot: the agent's declared capabilities and identity.

    All fields optional — a scan with empty metadata still runs (textual +
    structural patterns that don't need declared context still fire); the
    metadata-dependent patterns simply don't trigger.
    """
    agent_wallet:        str = ""
    # The set of program IDs the agent DECLARED it would invoke (its MCP
    # tool manifest, resolved to on-chain programs). Used by confused-deputy
    # / excessive-agency patterns: invoking a program outside this set is a
    # signal. Empty set = "not declared" → those patterns skip.
    declared_programs:   frozenset[str] = field(default_factory=frozenset)
    # The agent's declared domain ("defi-trading", "nft-marketplace", ...).
    declared_domain:     str = ""
    # Free-form text fields associated with the agent (description, tool
    # manifest text). Scanned by regex / semantic patterns.
    declared_text:       str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.declared_programs, frozenset):
            object.__setattr__(
                self, "declared_programs", frozenset(self.declared_programs),
            )


# =============================================================================
# SecuritySignal — one detection
# =============================================================================

@dataclass(frozen=True, slots=True)
class SecuritySignal:
    """
    A single attack-pattern detection. Immutable, validated at construction.

    `evidence` is a short, human-readable string naming WHAT matched (a
    redacted phrase, a program ID, a structural fact) — never raw secrets.
    `confidence` is the scanner's calibrated belief in [0, 1] that this is a
    true positive, after the pattern's false-positive logic.
    """
    pattern_id:   str
    category:     AttackCategory
    severity:     Severity
    method:       DetectionMethod
    confidence:   float                 # [0, 1]
    evidence:     str                    # human-readable, no raw secrets
    tx_signature: str = ""               # the transaction that triggered it, if any

    def __post_init__(self) -> None:
        if not self.pattern_id or not isinstance(self.pattern_id, str):
            raise ValueError(f"pattern_id must be a non-empty str, got {self.pattern_id!r}")
        if not isinstance(self.category, AttackCategory):
            raise TypeError(f"category must be AttackCategory, got {type(self.category).__name__}")
        if not isinstance(self.severity, Severity):
            raise TypeError(f"severity must be Severity, got {type(self.severity).__name__}")
        if not isinstance(self.method, DetectionMethod):
            raise TypeError(f"method must be DetectionMethod, got {type(self.method).__name__}")
        if not isinstance(self.confidence, float):
            raise TypeError(f"confidence must be float, got {type(self.confidence).__name__}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence {self.confidence} outside [0, 1]")
        if not isinstance(self.evidence, str):
            raise TypeError(f"evidence must be str, got {type(self.evidence).__name__}")

    @property
    def weighted_severity(self) -> float:
        """severity (1-5) scaled by confidence — the Day-10 scorer's input."""
        return int(self.severity) * self.confidence
