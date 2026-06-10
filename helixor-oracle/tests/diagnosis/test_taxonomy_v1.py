"""
tests/diagnosis/test_taxonomy_v1.py — Day-33 pin vectors for the
frozen diagnosis taxonomy.

Why the pin density?
-------------------
Every bit in `FailureMode` and `RemediationCode` is on-chain-load-
bearing the moment Phase-2 lands a `failure_mode_bitmask` field on the
certificate. Once cert v2 ships, a silent bit-position shift becomes
an interpretation drift that nobody catches at code review — every
existing cert decodes against the new layout and silently mis-labels.

These ~50 tests freeze the layout: every name -> exact bit, no overlap,
no growth, every label has a tier, the legacy 32-bit FlagBit value
matches the low 32 bits of FailureMode bit-for-bit. The
"trace-tier-unset invariant" specifically refers to test
`test_no_failure_mode_label_is_missing_a_severity_tier`.
"""

from __future__ import annotations

import json

import pytest

from detection.types import FlagBit
from diagnosis import (
    DecodedLabel,
    FailureMode,
    LABEL_METADATA,
    RemediationCode,
    Severity,
    decode,
    default_remediation,
    severity_of,
)
from diagnosis.taxonomy import (
    FAILURE_MODE_BITS,
    FAILURE_MODE_MAX,
    LEGACY_MASK,
    LEGACY_MASK_BITS,
)
from diagnosis.__main__ import build_payload


# =============================================================================
# Section A — FailureMode bit-position pin vectors
# =============================================================================
#
# A single test per name. Mutation cost: one line of source, one line of
# test — keeps reviewer attention high on any change. Every line below
# is "this name = this exact bit, FOREVER."


@pytest.mark.parametrize(
    "mode, expected_bit",
    [
        # ── Legacy (low 32) — must mirror detection.types.FlagBit ──────
        (FailureMode.PROVISIONAL,                0),
        (FailureMode.INSUFFICIENT_DATA,          1),
        (FailureMode.INCOMPATIBLE_INPUT,         2),
        (FailureMode.IMMEDIATE_RED,              3),
        (FailureMode.DEGRADED_BASELINE,          4),
        (FailureMode.ENSEMBLE_INCOMPLETE,        5),
        (FailureMode.DIMENSION_CLAMPED,          6),
        (FailureMode.INPUT_DIVERGENCE,           7),
        (FailureMode.SOURCE_DISAGREEMENT,        29),
        # ── OWASP-aligned (high 32) ──────────────────────────────────────
        (FailureMode.PROMPT_INJECTION,           32),
        (FailureMode.AGENT_GOAL_HIJACK,          33),
        (FailureMode.TOOL_MISUSE,                34),
        (FailureMode.TOOL_LOOP,                  35),
        (FailureMode.EXCESSIVE_AGENCY,           36),
        (FailureMode.IDENTITY_PRIVILEGE_ABUSE,   37),
        (FailureMode.SUPPLY_CHAIN_COMPROMISE,    38),
        (FailureMode.UNEXPECTED_CODE_EXECUTION,  39),
        (FailureMode.MEMORY_POISONING,           40),
        (FailureMode.CONTEXT_POISONING,          41),
        (FailureMode.INSECURE_INTER_AGENT_COMM,  42),
        (FailureMode.CASCADING_AGENT_FAILURE,    43),
        (FailureMode.HUMAN_TRUST_EXPLOITATION,   44),
        (FailureMode.ROGUE_AGENT,                45),
        (FailureMode.SENSITIVE_INFO_DISCLOSURE,  46),
        (FailureMode.DATA_MODEL_POISONING,       47),
        (FailureMode.IMPROPER_OUTPUT_HANDLING,   48),
        (FailureMode.SYSTEM_PROMPT_LEAK,         49),
        (FailureMode.VECTOR_EMBEDDING_WEAKNESS,  50),
        (FailureMode.MISINFORMATION,             51),
        (FailureMode.UNBOUNDED_CONSUMPTION,      52),
        (FailureMode.HALLUCINATION_CASCADE,      53),
        (FailureMode.OUTPUT_DISTRIBUTION_DRIFT,  54),
        (FailureMode.CONTEXT_WINDOW_EXHAUSTION,  55),
        (FailureMode.LATENCY_DEGRADATION,        56),
        (FailureMode.COST_BLOWUP,                57),
        (FailureMode.ALIGNMENT_REGRESSION,       58),
        (FailureMode.DATA_LEAKAGE,               59),
        (FailureMode.JAILBREAK,                  60),
        (FailureMode.SUB_AGENT_DEADLOCK,         61),
        (FailureMode.ROLE_CONFUSION,             62),
    ],
)
def test_failure_mode_bit_position_pin(mode: FailureMode, expected_bit: int) -> None:
    """Every label maps to exactly the bit declared in the v1 layout."""
    assert int(mode) == 1 << expected_bit, (
        f"FailureMode.{mode.name} drifted off bit {expected_bit}: "
        f"got {int(mode):#x}, expected {1 << expected_bit:#x}"
    )


def test_bit_63_is_reserved_unused() -> None:
    """Bit 63 must remain unclaimed. Future labels grow from 53+ first."""
    claimed = {int(m) for m in FailureMode}
    assert (1 << 63) not in claimed, (
        "bit 63 is the u64 reserved slot — packing it is a breaking change"
    )


def test_failure_mode_count_pin() -> None:
    """The v1 surface area is 40 labels (9 legacy + 31 new)."""
    assert len(list(FailureMode)) == 40


def test_failure_mode_fits_u64() -> None:
    """No member overflows the on-chain u64 field."""
    for m in FailureMode:
        assert 0 < int(m) <= FAILURE_MODE_MAX


def test_failure_mode_bits_constants_pin() -> None:
    assert FAILURE_MODE_BITS == 64
    assert FAILURE_MODE_MAX == (1 << 64) - 1
    assert LEGACY_MASK == 0xFFFF_FFFF
    assert LEGACY_MASK_BITS == 32


# =============================================================================
# Section B — Structural invariants
# =============================================================================


def test_no_two_failure_modes_share_a_bit() -> None:
    """No-overlap invariant — every label owns a unique bit position."""
    positions = [int(m).bit_length() - 1 for m in FailureMode]
    assert len(positions) == len(set(positions)), (
        "duplicate bit position in FailureMode — taxonomy is broken"
    )


def test_every_failure_mode_is_a_single_bit_value() -> None:
    """Single-bit invariant — composite values are not member-permitted."""
    for m in FailureMode:
        v = int(m)
        assert v > 0 and (v & (v - 1)) == 0, (
            f"FailureMode.{m.name} = {v:#x} is not a single bit"
        )


def test_legacy_bits_fit_in_low_32() -> None:
    """Every legacy mirror is in the low 32 bits."""
    legacy_names = {fb.name for fb in FlagBit}
    for m in FailureMode:
        if m.name in legacy_names:
            assert int(m) <= LEGACY_MASK, (
                f"FailureMode.{m.name} is a legacy mirror but does not fit "
                f"in the low 32 bits"
            )


def test_new_diagnosis_bits_are_in_high_32() -> None:
    """Every non-legacy label lives strictly above bit 31."""
    legacy_names = {fb.name for fb in FlagBit}
    for m in FailureMode:
        if m.name not in legacy_names:
            assert int(m) > LEGACY_MASK, (
                f"FailureMode.{m.name} is a NEW label but sits in the legacy "
                f"low-32 region — that region is reserved for FlagBit mirrors"
            )


# =============================================================================
# Section C — Legacy passthrough (the load-bearing back-compat property)
# =============================================================================


@pytest.mark.parametrize("flag", list(FlagBit))
def test_every_flag_bit_round_trips_through_failure_mode(flag: FlagBit) -> None:
    """
    Legacy passthrough: every FlagBit member must equal a FailureMode
    member of the same name, with the same integer value, in the
    low 32 bits.
    """
    assert flag.name in FailureMode.__members__, (
        f"FlagBit.{flag.name} has no FailureMode mirror"
    )
    mirror = FailureMode[flag.name]
    assert int(mirror) == int(flag)
    assert int(mirror) <= LEGACY_MASK


def test_legacy_mask_extracts_exactly_the_flagbit_value() -> None:
    """
    Consumers can read `failure_mode_bitmask & 0xFFFF_FFFF` and get a
    bit-identical legacy FlagBit u32 for downstream code that hasn't
    been upgraded yet.
    """
    composite = 0
    for fb in FlagBit:
        composite |= int(fb)
    mirror_composite = 0
    for fb in FlagBit:
        mirror_composite |= int(FailureMode[fb.name])
    assert (mirror_composite & LEGACY_MASK) == composite


# =============================================================================
# Section D — Metadata completeness ("trace-tier-unset invariant")
# =============================================================================


def test_no_failure_mode_label_is_missing_a_severity_tier() -> None:
    """
    THE TRACE-TIER-UNSET INVARIANT.

    Every FailureMode bit MUST have a LABEL_METADATA entry with a
    declared `Severity`. A label without a tier is unshippable — it
    means the diagnosis surface doesn't know whether to escalate.
    """
    for m in FailureMode:
        assert m in LABEL_METADATA, f"FailureMode.{m.name} has no metadata"
        meta = LABEL_METADATA[m]
        assert isinstance(meta.severity, Severity), (
            f"FailureMode.{m.name} severity is not a Severity, got "
            f"{type(meta.severity).__name__}"
        )


def test_every_label_has_a_non_empty_description() -> None:
    for m, meta in LABEL_METADATA.items():
        assert isinstance(meta.description, str) and meta.description.strip(), (
            f"FailureMode.{m.name} description is empty"
        )


def test_every_label_carries_owasp_refs_field_even_if_empty() -> None:
    """`owasp_refs` is a tuple of strings — empty allowed, missing is not."""
    for m, meta in LABEL_METADATA.items():
        assert isinstance(meta.owasp_refs, tuple)
        for ref in meta.owasp_refs:
            assert isinstance(ref, str) and ref
            # Pinned format: "CODE:YEAR"
            assert ":" in ref, f"FailureMode.{m.name} OWASP ref {ref!r} missing year"


def test_every_label_has_a_default_remediation_field() -> None:
    """May be 0 only for informational labels — pin the field exists."""
    for m, meta in LABEL_METADATA.items():
        assert isinstance(meta.default_remediation, RemediationCode)


def test_critical_labels_must_carry_a_nonzero_remediation_default() -> None:
    """
    A CRITICAL label without a remediation is a documentation hole that
    will show up in production at the worst moment. Fail loudly.
    """
    for m, meta in LABEL_METADATA.items():
        if meta.severity == Severity.CRITICAL:
            assert int(meta.default_remediation) != 0, (
                f"CRITICAL FailureMode.{m.name} has no default remediation"
            )


def test_metadata_has_no_orphan_entries() -> None:
    """LABEL_METADATA must not reference unknown FailureMode values."""
    assert set(LABEL_METADATA.keys()) == set(FailureMode)


# =============================================================================
# Section E — Specific OWASP mapping pins
# =============================================================================


@pytest.mark.parametrize(
    "mode, expected_refs",
    [
        (FailureMode.PROMPT_INJECTION,           ("LLM01:2025",)),
        (FailureMode.SENSITIVE_INFO_DISCLOSURE,  ("LLM02:2025",)),
        (FailureMode.SUPPLY_CHAIN_COMPROMISE,    ("LLM03:2025", "ASI04:2026")),
        (FailureMode.DATA_MODEL_POISONING,       ("LLM04:2025",)),
        (FailureMode.IMPROPER_OUTPUT_HANDLING,   ("LLM05:2025",)),
        (FailureMode.EXCESSIVE_AGENCY,           ("LLM06:2025",)),
        (FailureMode.SYSTEM_PROMPT_LEAK,         ("LLM07:2025",)),
        (FailureMode.VECTOR_EMBEDDING_WEAKNESS,  ("LLM08:2025",)),
        (FailureMode.MISINFORMATION,             ("LLM09:2025",)),
        (FailureMode.UNBOUNDED_CONSUMPTION,      ("LLM10:2025",)),
        (FailureMode.AGENT_GOAL_HIJACK,          ("ASI01:2026",)),
        (FailureMode.TOOL_MISUSE,                ("ASI02:2026",)),
        (FailureMode.IDENTITY_PRIVILEGE_ABUSE,   ("ASI03:2026",)),
        (FailureMode.UNEXPECTED_CODE_EXECUTION,  ("ASI05:2026",)),
        (FailureMode.INSECURE_INTER_AGENT_COMM,  ("ASI07:2026",)),
        (FailureMode.CASCADING_AGENT_FAILURE,    ("ASI08:2026",)),
        (FailureMode.HUMAN_TRUST_EXPLOITATION,   ("ASI09:2026",)),
        (FailureMode.ROGUE_AGENT,                ("ASI10:2026",)),
    ],
)
def test_owasp_ref_pin(mode: FailureMode, expected_refs: tuple[str, ...]) -> None:
    assert LABEL_METADATA[mode].owasp_refs == expected_refs


# =============================================================================
# Section F — RemediationCode bit pins + structural invariants
# =============================================================================


@pytest.mark.parametrize(
    "code, expected_bit",
    [
        (RemediationCode.PAUSE_AGENT,              0),
        (RemediationCode.ISOLATE_AGENT,            1),
        (RemediationCode.BLOCK_AGENT_PEER,         2),
        (RemediationCode.QUARANTINE_TOOL_RESULT,   3),
        (RemediationCode.RESTART_AGENT_SESSION,    4),
        (RemediationCode.CLEAR_AGENT_MEMORY,       5),
        (RemediationCode.REVOKE_AGENT_IDENTITY,    6),
        (RemediationCode.ROTATE_API_KEYS,          7),
        (RemediationCode.REVIEW_TOOL_PERMISSIONS,  8),
        (RemediationCode.REDUCE_AUTONOMY,          9),
        (RemediationCode.DECREASE_RATE_LIMITS,     10),
        (RemediationCode.INCREASE_RATE_LIMITS,     11),
        (RemediationCode.PATCH_PROMPT_GUARD,       12),
        (RemediationCode.ENABLE_OUTPUT_FILTER,     13),
        (RemediationCode.TIGHTEN_RETRIEVAL_FILTER, 14),
        (RemediationCode.VERIFY_SUPPLY_CHAIN,      15),
        (RemediationCode.ROLLBACK_MODEL_VERSION,   16),
        (RemediationCode.RUN_FRESH_BASELINE,       17),
        (RemediationCode.SCAN_MEMORY_STORE,        18),
        (RemediationCode.VERIFY_AGENT_IDENTITY,    19),
        (RemediationCode.ALERT_OPERATORS,          24),
        (RemediationCode.ENGAGE_HUMAN_REVIEW,      25),
        (RemediationCode.AUDIT_RECENT_OUTPUTS,     26),
        (RemediationCode.COLLECT_EVIDENCE,         27),
    ],
)
def test_remediation_code_bit_position_pin(
    code: RemediationCode, expected_bit: int
) -> None:
    assert int(code) == 1 << expected_bit


def test_remediation_codes_all_fit_in_u32() -> None:
    for rc in RemediationCode:
        assert 0 < int(rc) <= 0xFFFF_FFFF


def test_remediation_codes_no_overlap() -> None:
    positions = [int(rc).bit_length() - 1 for rc in RemediationCode]
    assert len(positions) == len(set(positions))


# =============================================================================
# Section G — decode() round-trips
# =============================================================================


def test_decode_empty_mask_returns_empty_tuple() -> None:
    assert decode(0) == ()


def test_decode_single_bit_returns_one_label() -> None:
    out = decode(int(FailureMode.TOOL_LOOP))
    assert len(out) == 1
    assert out[0].name == "TOOL_LOOP"
    assert out[0].bit == 35


def test_decode_returns_labels_in_bit_order() -> None:
    """Low-bit first — deterministic for downstream consumers."""
    mask = (
        int(FailureMode.JAILBREAK)              # bit 60
        | int(FailureMode.PROVISIONAL)          # bit  0
        | int(FailureMode.TOOL_LOOP)            # bit 35
    )
    out = decode(mask)
    assert [lbl.name for lbl in out] == ["PROVISIONAL", "TOOL_LOOP", "JAILBREAK"]


def test_decode_round_trips_every_single_label() -> None:
    """For every FailureMode, decode({that bit}) returns exactly that label."""
    for m in FailureMode:
        out = decode(int(m))
        assert len(out) == 1
        assert out[0].name == m.name
        meta = LABEL_METADATA[m]
        assert out[0] == DecodedLabel(
            name                = meta.name,
            bit                 = meta.bit,
            description         = meta.description,
            severity            = meta.severity,
            owasp_refs          = meta.owasp_refs,
            default_remediation = meta.default_remediation,
        )


def test_decode_all_bits_returns_every_label() -> None:
    mask = 0
    for m in FailureMode:
        mask |= int(m)
    out = decode(mask)
    assert len(out) == len(list(FailureMode))
    assert {lbl.name for lbl in out} == {m.name for m in FailureMode}


def test_decode_rejects_unknown_bit() -> None:
    """Bit 63 is reserved — using it in a mask must be a hard error."""
    with pytest.raises(ValueError, match="not a known FailureMode"):
        decode(1 << 63)


def test_decode_rejects_non_int_mask() -> None:
    with pytest.raises(TypeError):
        decode("0x1")  # type: ignore[arg-type]


def test_decode_rejects_negative_mask() -> None:
    with pytest.raises(ValueError):
        decode(-1)


def test_decode_rejects_over_u64_mask() -> None:
    with pytest.raises(ValueError):
        decode(1 << 64)


# =============================================================================
# Section H — default_remediation() + severity_of()
# =============================================================================


def test_default_remediation_empty_mask_returns_zero() -> None:
    assert int(default_remediation(0)) == 0


def test_default_remediation_single_label() -> None:
    rem = default_remediation(int(FailureMode.TOOL_LOOP))
    assert (rem & RemediationCode.PAUSE_AGENT) == RemediationCode.PAUSE_AGENT
    assert (rem & RemediationCode.REVIEW_TOOL_PERMISSIONS) == \
        RemediationCode.REVIEW_TOOL_PERMISSIONS


def test_default_remediation_unions_across_labels() -> None:
    """OR across the per-label defaults."""
    mask = (
        int(FailureMode.PROMPT_INJECTION)       # PATCH | OUTPUT_FILTER | ALERT
        | int(FailureMode.TOOL_LOOP)            # PAUSE | REVIEW_TOOL_PERMS
    )
    rem = default_remediation(mask)
    for must_have in (
        RemediationCode.PATCH_PROMPT_GUARD,
        RemediationCode.ENABLE_OUTPUT_FILTER,
        RemediationCode.ALERT_OPERATORS,
        RemediationCode.PAUSE_AGENT,
        RemediationCode.REVIEW_TOOL_PERMISSIONS,
    ):
        assert (rem & must_have) == must_have


def test_severity_of_empty_mask_is_info_floor() -> None:
    assert severity_of(0) == Severity.INFO


def test_severity_of_takes_max_across_labels() -> None:
    mask = (
        int(FailureMode.PROVISIONAL)            # INFO
        | int(FailureMode.IMMEDIATE_RED)        # CRITICAL
        | int(FailureMode.TOOL_LOOP)            # MED
    )
    assert severity_of(mask) == Severity.CRITICAL


def test_severity_of_single_label_matches_metadata() -> None:
    for m in FailureMode:
        assert severity_of(int(m)) == LABEL_METADATA[m].severity


# =============================================================================
# Section I — taxonomy.json export round-trip
# =============================================================================


def test_taxonomy_json_payload_round_trips_every_label() -> None:
    payload = build_payload()
    # Re-import and re-derive equivalence with LABEL_METADATA.
    json_str = json.dumps(payload)
    reparsed = json.loads(json_str)
    assert reparsed["schema_version"] == 1
    by_name = {entry["name"]: entry for entry in reparsed["failure_modes"]}
    for m, meta in LABEL_METADATA.items():
        e = by_name[m.name]
        assert e["bit"] == meta.bit
        assert e["value"] == int(m)
        assert e["severity"] == meta.severity.name
        assert tuple(e["owasp_refs"]) == meta.owasp_refs
        assert e["default_remediation"]["value"] == int(meta.default_remediation)


def test_taxonomy_json_includes_every_remediation_code() -> None:
    payload = build_payload()
    by_name = {entry["name"]: entry for entry in payload["remediation_codes"]}
    assert set(by_name.keys()) == {rc.name for rc in RemediationCode}
    for rc in RemediationCode:
        assert by_name[rc.name]["value"] == int(rc)


def test_taxonomy_json_labels_ordered_by_bit_ascending() -> None:
    payload = build_payload()
    bits = [entry["bit"] for entry in payload["failure_modes"]]
    assert bits == sorted(bits)
