#!/usr/bin/env python3
"""
audit/securities_compliance_check.py — SEC-1 securities-posture gate.

The substrate is `phylanx-oracle/oracle/securities_compliance.py`,
which declares the closed-enum `CompensationModel`, the
`ConflictDisclosure` shape, and `verify_compensation_independence`.
The `OperatorAttestation` dataclass in `oracle/operator_manifest.py`
carries `compensation_model` + `conflicts_disclosed` and folds both
into `attestation_canonical_bytes` so the existing OFAC-1 Ed25519
sig binding extends to cover them.

This gate is the mechanical regression alarm: if a refactor quietly
removes either substrate, widens the compensation allowlist past
governance-approved boundaries, drops a field from
`attestation_canonical_bytes`, or de-binds the sig from the new
fields, this lights red BEFORE mainnet.

WHAT IT VERIFIES
----------------
1. The `securities_compliance` module exists at the expected path.
2. The module exports the audit-pinned public surface
   (`CompensationModel`, `ConflictDisclosure`,
   `ALLOWED_COMPENSATION_MODELS`, `ADVISORY_DISCLAIMER`,
   `verify_compensation_independence`, etc.).
3. `ALLOWED_COMPENSATION_MODELS` contains only the values declared
   in `CompensationModel` (no drift between enum and allowlist).
4. The compensation allowlist still contains exactly the
   governance-pinned today-set:
   {`FLAT_FEE_PER_CERT_FROM_TREASURY`}. Widening this set requires
   updating PINNED_ALLOWED_COMPENSATION_MODELS in this file in
   lockstep with `launch/legal/securities_notice.md`.
5. `OperatorAttestation` declares the two SEC-1 fields
   (`compensation_model`, `conflicts_disclosed`).
6. `attestation_canonical_bytes` folds both new fields in — a sig
   over the OLD format (no SEC-1 fields) must NOT match the new
   canonical bytes (downgrade defense).
7. The SDK's `safe_reader.ts` carries an `ADVISORY_DISCLAIMER`
   constant whose string content matches the Python substrate
   byte-for-byte. Drift here means SDK consumers receive different
   disclosure text than the public notice claims they receive.
8. Every published integration reader under
   `launch/integrations/*/reader.ts` imports and references
   `ADVISORY_DISCLAIMER` — a reader that returns a score without
   surfacing the disclaimer violates the public posture.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any
HARD finding. Wired into `audit/run_all.sh` after the DP-1 gate.
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

#: The governance-approved compensation-model allowlist. Widening
#: this set requires updating the public notice
#: (`launch/legal/securities_notice.md`) and this file in lockstep —
#: the gate refuses any module-level allowlist that does not match.
PINNED_ALLOWED_COMPENSATION_MODELS: frozenset[str] = frozenset(
    {"FLAT_FEE_PER_CERT_FROM_TREASURY"}
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
    path = REPO_ROOT / "phylanx-oracle" / "oracle" / "securities_compliance.py"
    report.checked.append(str(path.relative_to(REPO_ROOT)))
    if not path.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.substrate-exists",
            detail=(
                f"missing {path.relative_to(REPO_ROOT)} — SEC-1 "
                f"securities-posture compliance cannot fire without "
                f"the substrate"
            ),
        ))


def _check_oracle_public_surface(report: Report) -> None:
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "phylanx-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        module = importlib.import_module("oracle.securities_compliance")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.module-importable",
            detail=f"securities_compliance not importable: {exc!r}",
        ))
        return

    report.checked.append("oracle.securities_compliance:exports")
    required = {
        "ADVISORY_DISCLAIMER",
        "ALLOWED_COMPENSATION_MODELS",
        "CompensationModel",
        "ConflictDisclosure",
        "SecuritiesComplianceError",
        "SecuritiesComplianceReport",
        "collect_disclosed_conflicts",
        "disclaimer_text",
        "serialize_conflicts",
        "verify_compensation_independence",
    }
    missing = sorted(required - set(getattr(module, "__all__", [])))
    if missing:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.public-surface",
            detail=(
                f"oracle.securities_compliance.__all__ is missing "
                f"required symbols: {missing}"
            ),
        ))
        return

    # Enum / allowlist consistency.
    report.checked.append("oracle.securities_compliance:enum-allowlist-consistent")
    CompensationModel = getattr(module, "CompensationModel")
    allowlist = getattr(module, "ALLOWED_COMPENSATION_MODELS")
    enum_values = frozenset(m.value for m in CompensationModel)
    if allowlist != enum_values:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.enum-allowlist-consistent",
            detail=(
                f"CompensationModel enum values {sorted(enum_values)!r} "
                f"do not match ALLOWED_COMPENSATION_MODELS "
                f"{sorted(allowlist)!r}. Drift here would let a future "
                f"enum addition silently widen the boot gate."
            ),
        ))

    # Governance-pinned allowlist.
    report.checked.append("oracle.securities_compliance:allowlist-pinned")
    if frozenset(allowlist) != PINNED_ALLOWED_COMPENSATION_MODELS:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.allowlist-governance-pinned",
            detail=(
                f"ALLOWED_COMPENSATION_MODELS = "
                f"{sorted(allowlist)!r}, but the governance-approved "
                f"pin is {sorted(PINNED_ALLOWED_COMPENSATION_MODELS)!r}. "
                f"Widening this set requires updating "
                f"launch/legal/securities_notice.md AND "
                f"PINNED_ALLOWED_COMPENSATION_MODELS in this file in "
                f"lockstep."
            ),
        ))


def _check_attestation_carries_sec1_fields(report: Report) -> None:
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "phylanx-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        manifest_module = importlib.import_module("oracle.operator_manifest")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.manifest-module-importable",
            detail=f"oracle.operator_manifest not importable: {exc!r}",
        ))
        return

    OperatorAttestation = getattr(manifest_module, "OperatorAttestation")
    report.checked.append("oracle.operator_manifest:OperatorAttestation-sec1-fields")
    field_names = {f.name for f in OperatorAttestation.__dataclass_fields__.values()}
    missing = sorted(
        {"compensation_model", "conflicts_disclosed"} - field_names
    )
    if missing:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.attestation-sec1-fields",
            detail=(
                f"OperatorAttestation is missing SEC-1 field(s): "
                f"{missing}. The boot gate cannot fire without these "
                f"and the OFAC-1 sig binding cannot extend to cover "
                f"them."
            ),
        ))


def _check_canonical_bytes_binds_sec1_fields(report: Report) -> None:
    """The substrate-level invariant: mutating either SEC-1 field
    must change the canonical bytes. If a refactor reverts the
    canonical format to the pre-SEC-1 shape, this lights red."""
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "phylanx-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        manifest_module = importlib.import_module("oracle.operator_manifest")
        sec_module = importlib.import_module("oracle.securities_compliance")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.canonical-bytes-bind",
            detail=f"modules not importable: {exc!r}",
        ))
        return

    OperatorAttestation = getattr(manifest_module, "OperatorAttestation")
    attestation_canonical_bytes = getattr(
        manifest_module, "attestation_canonical_bytes"
    )
    ConflictDisclosure = getattr(sec_module, "ConflictDisclosure")

    report.checked.append(
        "oracle.operator_manifest:attestation_canonical_bytes-binds-sec1"
    )

    base_kwargs = dict(
        node_id="audit-n0", pubkey="audit-pk0",
        operator_org="audit-org", operator_contact="audit@example",
        jurisdiction="US",
        compensation_model="FLAT_FEE_PER_CERT_FROM_TREASURY",
        conflicts_disclosed=(),
    )
    base = OperatorAttestation(**base_kwargs)
    base_bytes = attestation_canonical_bytes(base)

    mutated_comp = OperatorAttestation(
        **{**base_kwargs, "compensation_model": "PERFORMANCE_FEE"}
    )
    if attestation_canonical_bytes(mutated_comp) == base_bytes:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.canonical-bytes-bind-compensation",
            detail=(
                "attestation_canonical_bytes does not change when "
                "compensation_model is mutated. The OFAC-1 sig binding "
                "is structurally unable to detect a lie about the "
                "operator's compensation arrangement."
            ),
        ))

    mutated_conflicts = OperatorAttestation(
        **{**base_kwargs, "conflicts_disclosed": (
            ConflictDisclosure("Wal-x", "EMPLOYEE"),
        )}
    )
    if attestation_canonical_bytes(mutated_conflicts) == base_bytes:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.canonical-bytes-bind-conflicts",
            detail=(
                "attestation_canonical_bytes does not change when "
                "conflicts_disclosed is mutated. The OFAC-1 sig "
                "binding cannot detect a hidden self-dealing "
                "disclosure."
            ),
        ))


# =============================================================================
# SDK + integration reader checks — the public-facing surface
# =============================================================================

_TS_SDK_PATH = REPO_ROOT / "phylanx-sdk" / "src" / "safe_reader.ts"
_INTEGRATIONS_DIR = REPO_ROOT / "launch" / "integrations"


def _extract_ts_disclaimer(ts_text: str) -> str | None:
    """
    Parse the `ADVISORY_DISCLAIMER` string literal out of the SDK
    source. The constant is a multi-line + string concatenation —
    AND the disclaimer body itself contains a `;` and other potential
    terminator chars, so we have to track string-literal state
    properly. Walk from the opening `=` through the TS source one
    character at a time:

      * outside any string: accept `+`, whitespace, comments;
        terminate on the first `;`.
      * inside a string ("..."): collect every char, handle backslash
        escapes; on the closing `"` flip back to outside-string state.

    Returns None if the constant is missing or unparseable.
    """
    marker = "export const ADVISORY_DISCLAIMER: string ="
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


def _check_sdk_advisory_disclaimer_matches(report: Report) -> None:
    """The SDK constant must match the Python source-of-truth byte-for-byte."""
    report.checked.append(str(_TS_SDK_PATH.relative_to(REPO_ROOT)))
    if not _TS_SDK_PATH.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.sdk-safe-reader-present",
            detail=(
                f"missing {_TS_SDK_PATH.relative_to(REPO_ROOT)} — the "
                f"SDK ADVISORY_DISCLAIMER source-of-truth lives here"
            ),
        ))
        return

    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "phylanx-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        sec_module = importlib.import_module("oracle.securities_compliance")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.disclaimer-substrate-importable",
            detail=f"oracle.securities_compliance not importable: {exc!r}",
        ))
        return
    python_disclaimer: str = getattr(sec_module, "ADVISORY_DISCLAIMER", "")
    if not python_disclaimer:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.python-disclaimer-non-empty",
            detail=(
                "ADVISORY_DISCLAIMER in oracle.securities_compliance is "
                "empty — the cross-reference cannot proceed"
            ),
        ))
        return

    ts_text = _TS_SDK_PATH.read_text()
    if "ADVISORY_DISCLAIMER" not in ts_text:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.sdk-advisory-disclaimer-marker",
            detail=(
                f"{_TS_SDK_PATH.relative_to(REPO_ROOT)} does not export "
                f"ADVISORY_DISCLAIMER — every consumer-facing surface "
                f"that returns a score must render the disclaimer"
            ),
        ))
        return

    ts_disclaimer = _extract_ts_disclaimer(ts_text)
    if ts_disclaimer is None:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.sdk-advisory-disclaimer-parseable",
            detail=(
                "could not parse ADVISORY_DISCLAIMER body from "
                f"{_TS_SDK_PATH.relative_to(REPO_ROOT)} — the constant "
                "must be a double-quoted string concatenation"
            ),
        ))
        return

    report.checked.append("oracle.securities_compliance:disclaimer-matches-sdk")
    if ts_disclaimer != python_disclaimer:
        report.findings.append(Finding(
            severity="HARD",
            rule="SEC-1.disclaimer-byte-identity",
            detail=(
                f"ADVISORY_DISCLAIMER differs between Python "
                f"({len(python_disclaimer)} chars) and SDK "
                f"({len(ts_disclaimer)} chars). The two must match "
                f"byte-for-byte — drift means consumers receive "
                f"different disclosure text than the public notice "
                f"claims they receive. python={python_disclaimer!r} "
                f"ts={ts_disclaimer!r}"
            ),
        ))


def _check_integration_readers_surface_disclaimer(report: Report) -> None:
    """Every reader.ts under launch/integrations must reference
    ADVISORY_DISCLAIMER. A reader that returns a score without
    surfacing the disclaimer violates the public posture."""
    report.checked.append(
        str(_INTEGRATIONS_DIR.relative_to(REPO_ROOT)) + ":reader-disclaimer"
    )
    if not _INTEGRATIONS_DIR.is_dir():
        # No integrations dir is fine — nothing to check.
        return
    readers = list(_INTEGRATIONS_DIR.glob("*/reader.ts"))
    if not readers:
        return
    for reader_path in sorted(readers):
        text = reader_path.read_text()
        if "ADVISORY_DISCLAIMER" not in text:
            report.findings.append(Finding(
                severity="HARD",
                rule="SEC-1.integration-reader-surfaces-disclaimer",
                detail=(
                    f"{reader_path.relative_to(REPO_ROOT)} does not "
                    f"reference ADVISORY_DISCLAIMER — every published "
                    f"reference reader must surface the SEC-1 "
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
    _check_attestation_carries_sec1_fields(report)
    _check_canonical_bytes_binds_sec1_fields(report)
    _check_sdk_advisory_disclaimer_matches(report)
    _check_integration_readers_surface_disclaimer(report)

    text = report.to_json()
    if args.json == "-" or args.json == "":
        sys.stdout.write(text + "\n")
    else:
        Path(args.json).write_text(text + "\n")

    return 1 if report.hard() else 0


if __name__ == "__main__":
    sys.exit(main())
