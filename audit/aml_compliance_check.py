#!/usr/bin/env python3
"""
audit/aml_compliance_check.py — AML-1 KYC/AML posture gate.

The substrate is `helixor-oracle/oracle/aml_compliance.py`, which
declares the closed-enum `AmlProgramAttestation`, the
`_KYC_FORBIDDEN_FIELDS` guard, and `verify_aml_posture`. The
`OperatorAttestation` dataclass in `oracle/operator_manifest.py`
carries `aml_program_attestation` and folds it into
`attestation_canonical_bytes` so the existing OFAC-1 Ed25519 sig
binding extends to cover it.

This gate is the mechanical regression alarm: if a refactor quietly
removes the substrate, widens the allowlist past governance-approved
boundaries, drops the field from `attestation_canonical_bytes`,
de-binds the sig from the new field, or strips the KYC guard, this
lights red BEFORE mainnet.

WHAT IT VERIFIES
----------------
1. The `aml_compliance` module exists at the expected path.
2. The module exports the audit-pinned public surface
   (`AmlProgramAttestation`, `ALLOWED_AML_ATTESTATIONS`,
   `AML_KYC_DISCLAIMER`, `verify_aml_posture`,
   `assert_no_kyc_fields`, etc.).
3. `ALLOWED_AML_ATTESTATIONS` contains exactly the values declared
   in `AmlProgramAttestation` (no drift between enum and allowlist).
4. The AML allowlist still contains exactly the governance-pinned
   today-set ({`NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY`,
   `EXTERNAL_AML_PROGRAM_DECLARED`}). Widening this set requires
   updating PINNED_ALLOWED_AML_ATTESTATIONS in this file in
   lockstep with `launch/legal/aml_kyc_notice.md`.
5. `OperatorAttestation` declares the AML-1 field
   (`aml_program_attestation`).
6. `attestation_canonical_bytes` folds the new field in — a sig
   over the OLD format (no AML-1 field) must NOT match the new
   canonical bytes (downgrade defense).
7. The DataCategory enum (from `oracle.data_protection_policy`) is
   free of KYC-shaped substrings — `assert_no_kyc_fields` returns
   clean on every existing category value.
8. The SDK's `safe_reader.ts` carries an `AML_KYC_DISCLAIMER`
   constant whose string content matches the Python substrate
   byte-for-byte. Drift here means SDK consumers receive
   different disclosure text than the public AML notice claims.
9. Every published integration reader under
   `launch/integrations/*/reader.ts` imports and references
   `AML_KYC_DISCLAIMER` — a reader that returns a score without
   surfacing the disclaimer violates the public AML posture.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any
HARD finding. Wired into `audit/run_all.sh` after the SEC-1 gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Audit-pinned values
# =============================================================================

#: The governance-approved AML-attestation allowlist. Widening
#: this set requires updating the public notice
#: (`launch/legal/aml_kyc_notice.md`) and this file in lockstep —
#: the gate refuses any module-level allowlist that does not match.
PINNED_ALLOWED_AML_ATTESTATIONS: frozenset[str] = frozenset(
    {
        "NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY",
        "EXTERNAL_AML_PROGRAM_DECLARED",
    }
)


# =============================================================================
# Finding / Report
# =============================================================================

@dataclass
class Finding:
    severity: str
    rule:     str
    detail:   str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    checked:  list[str] = field(default_factory=list)

    def hard(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HARD"]

    def to_json(self) -> str:
        return json.dumps(
            {
                "checked":  self.checked,
                "findings": [asdict(f) for f in self.findings],
                "summary": {
                    "checks":         len(self.checked),
                    "hard_findings":  len(self.hard()),
                    "soft_findings":  len(self.findings) - len(self.hard()),
                },
            },
            indent=2,
            sort_keys=True,
        )


# =============================================================================
# Checks
# =============================================================================

def _check_substrate_present(report: Report) -> None:
    path = REPO_ROOT / "helixor-oracle" / "oracle" / "aml_compliance.py"
    report.checked.append(str(path.relative_to(REPO_ROOT)))
    if not path.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.substrate-exists",
            detail=(
                f"missing {path.relative_to(REPO_ROOT)} — AML-1 "
                f"KYC/AML posture compliance cannot fire without "
                f"the substrate"
            ),
        ))


def _check_oracle_public_surface(report: Report) -> None:
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "helixor-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        module = importlib.import_module("oracle.aml_compliance")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.module-importable",
            detail=f"aml_compliance not importable: {exc!r}",
        ))
        return

    report.checked.append("oracle.aml_compliance:exports")
    required = {
        "ALLOWED_AML_ATTESTATIONS",
        "AML_KYC_DISCLAIMER",
        "AmlComplianceError",
        "AmlComplianceReport",
        "AmlProgramAttestation",
        "KycFieldRefusedError",
        "aml_kyc_disclaimer_text",
        "assert_no_kyc_fields",
        "collect_aml_attestations",
        "verify_aml_posture",
    }
    missing = sorted(required - set(getattr(module, "__all__", [])))
    if missing:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.public-surface",
            detail=(
                f"oracle.aml_compliance.__all__ is missing "
                f"required symbols: {missing}"
            ),
        ))
        return

    # Enum / allowlist consistency.
    report.checked.append("oracle.aml_compliance:enum-allowlist-consistent")
    AmlProgramAttestation = getattr(module, "AmlProgramAttestation")
    allowlist = getattr(module, "ALLOWED_AML_ATTESTATIONS")
    enum_values = frozenset(m.value for m in AmlProgramAttestation)
    if allowlist != enum_values:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.enum-allowlist-consistent",
            detail=(
                f"AmlProgramAttestation enum values "
                f"{sorted(enum_values)!r} do not match "
                f"ALLOWED_AML_ATTESTATIONS {sorted(allowlist)!r}. "
                f"Drift here would let a future enum addition "
                f"silently widen the boot gate."
            ),
        ))

    # Governance-pinned allowlist.
    report.checked.append("oracle.aml_compliance:allowlist-pinned")
    if frozenset(allowlist) != PINNED_ALLOWED_AML_ATTESTATIONS:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.allowlist-governance-pinned",
            detail=(
                f"ALLOWED_AML_ATTESTATIONS = "
                f"{sorted(allowlist)!r}, but the governance-approved "
                f"pin is {sorted(PINNED_ALLOWED_AML_ATTESTATIONS)!r}. "
                f"Widening this set requires updating "
                f"launch/legal/aml_kyc_notice.md AND "
                f"PINNED_ALLOWED_AML_ATTESTATIONS in this file in "
                f"lockstep."
            ),
        ))


def _check_attestation_carries_aml1_field(report: Report) -> None:
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "helixor-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        manifest_module = importlib.import_module("oracle.operator_manifest")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.manifest-module-importable",
            detail=f"oracle.operator_manifest not importable: {exc!r}",
        ))
        return

    OperatorAttestation = getattr(manifest_module, "OperatorAttestation")
    report.checked.append("oracle.operator_manifest:OperatorAttestation-aml1-field")
    field_names = {f.name for f in OperatorAttestation.__dataclass_fields__.values()}
    if "aml_program_attestation" not in field_names:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.attestation-aml1-field",
            detail=(
                "OperatorAttestation is missing AML-1 field "
                "'aml_program_attestation'. The boot gate cannot fire "
                "without this and the OFAC-1 sig binding cannot extend "
                "to cover it."
            ),
        ))


def _check_canonical_bytes_binds_aml1_field(report: Report) -> None:
    """The substrate-level invariant: mutating the AML-1 field must
    change the canonical bytes. If a refactor reverts the canonical
    format to the pre-AML-1 shape, this lights red."""
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "helixor-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        manifest_module = importlib.import_module("oracle.operator_manifest")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.canonical-bytes-bind",
            detail=f"oracle.operator_manifest not importable: {exc!r}",
        ))
        return

    OperatorAttestation = getattr(manifest_module, "OperatorAttestation")
    attestation_canonical_bytes = getattr(
        manifest_module, "attestation_canonical_bytes"
    )

    report.checked.append(
        "oracle.operator_manifest:attestation_canonical_bytes-binds-aml1"
    )

    base_kwargs = dict(
        node_id="audit-n0", pubkey="audit-pk0",
        operator_org="audit-org", operator_contact="audit@example",
        jurisdiction="US",
        compensation_model="FLAT_FEE_PER_CERT_FROM_TREASURY",
        conflicts_disclosed=(),
        aml_program_attestation="NO_AML_PROGRAM_REQUIRED_FOR_HELIXOR_ACTIVITY",
    )
    base = OperatorAttestation(**base_kwargs)
    base_bytes = attestation_canonical_bytes(base)

    mutated = OperatorAttestation(
        **{**base_kwargs,
           "aml_program_attestation": "EXTERNAL_AML_PROGRAM_DECLARED"}
    )
    if attestation_canonical_bytes(mutated) == base_bytes:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.canonical-bytes-bind-aml-attestation",
            detail=(
                "attestation_canonical_bytes does not change when "
                "aml_program_attestation is mutated. The OFAC-1 sig "
                "binding is structurally unable to detect a lie about "
                "the operator's AML posture."
            ),
        ))


def _check_kyc_forbidden_fields_against_data_categories(report: Report) -> None:
    """The DataCategory enum (DP-1) must not contain KYC-shaped
    substrings. A future PR that adds a category named e.g.
    `CUSTOMER_LEGAL_NAME` would silently invert the AML carve-out."""
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "helixor-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        aml_module = importlib.import_module("oracle.aml_compliance")
        dp_module = importlib.import_module("oracle.data_protection_policy")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.kyc-guard-modules-importable",
            detail=f"aml / data_protection modules not importable: {exc!r}",
        ))
        return

    assert_no_kyc_fields = getattr(aml_module, "assert_no_kyc_fields")
    KycFieldRefusedError = getattr(aml_module, "KycFieldRefusedError")
    DataCategory = getattr(dp_module, "DataCategory", None)

    report.checked.append(
        "oracle.data_protection_policy:DataCategory-kyc-clean"
    )
    if DataCategory is None:
        # DP-1 substrate missing — let the DP-1 gate own that finding.
        return

    for member in DataCategory:
        try:
            assert_no_kyc_fields(member.value)
        except KycFieldRefusedError as exc:
            report.findings.append(Finding(
                severity="HARD",
                rule="AML-1.kyc-shaped-data-category",
                detail=(
                    f"DataCategory.{member.name} value {member.value!r} "
                    f"matches a KYC-forbidden pattern: {exc}. The "
                    f"cluster's AML posture rests on NOT collecting "
                    f"KYC data — this category inverts the carve-out."
                ),
            ))


# =============================================================================
# SDK + integration reader checks — the public-facing surface
# =============================================================================

_TS_SDK_PATH = REPO_ROOT / "helixor-sdk" / "src" / "safe_reader.ts"
_INTEGRATIONS_DIR = REPO_ROOT / "launch" / "integrations"


def _extract_ts_string_constant(ts_text: str, marker: str) -> str | None:
    """
    Parse a string constant out of the SDK source given its
    declaration marker (e.g. `"export const AML_KYC_DISCLAIMER: string ="`).

    The constant is a multi-line string concatenation AND the
    disclaimer body itself contains a `;` (terminator char), so we
    track string-literal state. Walk from the marker through the TS
    source one character at a time:

      * outside any string: accept `+`, whitespace, comments;
        terminate on the first `;`.
      * inside a string ("..."): collect every char, handle
        backslash escapes; on the closing `"` flip back to
        outside-string state.

    Returns None if the constant is missing or unparseable.
    """
    idx = ts_text.find(marker)
    if idx == -1:
        return None
    cursor = idx + len(marker)
    n = len(ts_text)

    segments: list[str] = []
    in_string = False
    in_line_comment = False
    in_block_comment = False
    buf: list[str] = []

    while cursor < n:
        c = ts_text[cursor]

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            cursor += 1
            continue
        if in_block_comment:
            if c == "*" and cursor + 1 < n and ts_text[cursor + 1] == "/":
                in_block_comment = False
                cursor += 2
                continue
            cursor += 1
            continue

        if in_string:
            if c == "\\" and cursor + 1 < n:
                nxt = ts_text[cursor + 1]
                buf.append({"n": "\n", "t": "\t", "\\": "\\",
                            '"': '"', "'": "'"}.get(nxt, nxt))
                cursor += 2
                continue
            if c == '"':
                segments.append("".join(buf))
                buf = []
                in_string = False
                cursor += 1
                continue
            buf.append(c)
            cursor += 1
            continue

        # outside-string state
        if c == ";":
            return "".join(segments) if segments else None
        if c == '"':
            in_string = True
            cursor += 1
            continue
        if c == "/" and cursor + 1 < n:
            nxt = ts_text[cursor + 1]
            if nxt == "/":
                in_line_comment = True
                cursor += 2
                continue
            if nxt == "*":
                in_block_comment = True
                cursor += 2
                continue
        # Whitespace, `+`, etc. are all skip-able.
        cursor += 1

    return None


def _check_sdk_aml_disclaimer_matches(report: Report) -> None:
    """The SDK constant must match the Python source-of-truth
    byte-for-byte."""
    report.checked.append(str(_TS_SDK_PATH.relative_to(REPO_ROOT)))
    if not _TS_SDK_PATH.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.sdk-safe-reader-present",
            detail=(
                f"missing {_TS_SDK_PATH.relative_to(REPO_ROOT)} — the "
                f"SDK AML_KYC_DISCLAIMER source-of-truth lives here"
            ),
        ))
        return

    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "helixor-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        aml_module = importlib.import_module("oracle.aml_compliance")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.disclaimer-substrate-importable",
            detail=f"oracle.aml_compliance not importable: {exc!r}",
        ))
        return
    python_disclaimer: str = getattr(aml_module, "AML_KYC_DISCLAIMER", "")
    if not python_disclaimer:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.python-disclaimer-non-empty",
            detail=(
                "AML_KYC_DISCLAIMER in oracle.aml_compliance is empty "
                "— the cross-reference cannot proceed"
            ),
        ))
        return

    ts_text = _TS_SDK_PATH.read_text()
    if "AML_KYC_DISCLAIMER" not in ts_text:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.sdk-aml-disclaimer-marker",
            detail=(
                f"{_TS_SDK_PATH.relative_to(REPO_ROOT)} does not export "
                f"AML_KYC_DISCLAIMER — every consumer-facing surface "
                f"that returns a score must render the AML disclaimer"
            ),
        ))
        return

    ts_disclaimer = _extract_ts_string_constant(
        ts_text, "export const AML_KYC_DISCLAIMER: string ="
    )
    if ts_disclaimer is None:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.sdk-aml-disclaimer-parseable",
            detail=(
                "could not parse AML_KYC_DISCLAIMER body from "
                f"{_TS_SDK_PATH.relative_to(REPO_ROOT)} — the constant "
                "must be a double-quoted string concatenation"
            ),
        ))
        return

    report.checked.append("oracle.aml_compliance:disclaimer-matches-sdk")
    if ts_disclaimer != python_disclaimer:
        report.findings.append(Finding(
            severity="HARD",
            rule="AML-1.disclaimer-byte-identity",
            detail=(
                f"AML_KYC_DISCLAIMER differs between Python "
                f"({len(python_disclaimer)} chars) and SDK "
                f"({len(ts_disclaimer)} chars). The two must match "
                f"byte-for-byte — drift means consumers receive "
                f"different disclosure text than the public notice "
                f"claims. python={python_disclaimer!r} "
                f"ts={ts_disclaimer!r}"
            ),
        ))


def _check_integration_readers_surface_aml_disclaimer(report: Report) -> None:
    """Every reader.ts under launch/integrations must reference
    AML_KYC_DISCLAIMER. A reader that returns a score without
    surfacing the disclaimer violates the public AML posture."""
    report.checked.append(
        str(_INTEGRATIONS_DIR.relative_to(REPO_ROOT)) + ":reader-aml-disclaimer"
    )
    if not _INTEGRATIONS_DIR.is_dir():
        return
    readers = list(_INTEGRATIONS_DIR.glob("*/reader.ts"))
    if not readers:
        return
    for reader_path in sorted(readers):
        text = reader_path.read_text()
        if "AML_KYC_DISCLAIMER" not in text:
            report.findings.append(Finding(
                severity="HARD",
                rule="AML-1.integration-reader-surfaces-disclaimer",
                detail=(
                    f"{reader_path.relative_to(REPO_ROOT)} does not "
                    f"reference AML_KYC_DISCLAIMER — every published "
                    f"reference reader must surface the AML-1 "
                    f"disclaimer alongside the returned score"
                ),
            ))


# =============================================================================
# Entry point
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", default="-",
        help="path for the JSON report (default: stdout)",
    )
    args = parser.parse_args()

    report = Report()
    _check_substrate_present(report)
    _check_oracle_public_surface(report)
    _check_attestation_carries_aml1_field(report)
    _check_canonical_bytes_binds_aml1_field(report)
    _check_kyc_forbidden_fields_against_data_categories(report)
    _check_sdk_aml_disclaimer_matches(report)
    _check_integration_readers_surface_aml_disclaimer(report)

    text = report.to_json()
    if args.json == "-" or args.json == "":
        sys.stdout.write(text + "\n")
    else:
        Path(args.json).write_text(text + "\n")

    return 1 if report.hard() else 0


if __name__ == "__main__":
    sys.exit(main())
