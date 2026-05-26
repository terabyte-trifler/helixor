#!/usr/bin/env python3
"""
audit/consumer_integration_check.py — DBP-1 mechanical regression alarm
for the red-team Path 4 "DeFi Bypass" attack chain.

WHAT THIS GATE IS FOR
---------------------
Path 4 of the drain-DeFi attack tree lives ENTIRELY in the consumer's
code, not Helixor's. The Helixor-side defences against the leaves
(VULN-23 SafeCertReader, SOL-3 per-operation freshness, AW-01 input
provenance, AW-01-EXT slot-anchor verification) all already ship — but
they only fire if a partner ACTUALLY USES them.

This gate makes the safe path machine-checkable. Any DeFi partner that
wants the "Verified Integrator" badge — and the downstream-of-downstream
contract surface that comes with it (DBP-2 on-chain `VerifiedConsumer`
PDA, DBP-4 freshness webhooks, SLA-backed support) — publishes a
JSON manifest under `launch/integrations/*.json` declaring their
cert-reader entrypoint and the safety surfaces it wires. This linter
verifies the partner's claim is structurally accurate against their
checked-in source BEFORE the manifest can be registered on chain.

The gate ALSO cross-checks that the SafeCertReader / Operation /
verifyAgainstSolanaLedger anchors the partners depend on still exist
in the canonical locations. A refactor that renames `SafeCertReader`
or removes `verifyAgainstSolanaLedger` without updating partner
manifests would silently leave every integrator's claim void; this
gate lights red BEFORE that ships.

THE FIVE CHECKS
---------------
  DBP-1a   per-manifest schema + source verification
            (`launch/integrations/<partner>.json` -> cert-reader source)
  DBP-1b   VULN-23 anchor — `SafeCertReader` + `CERT_MAX_AGE_SECONDS`
            present in `helixor-sdk/src/safe_reader.ts`.
  DBP-1c   SOL-3 anchor — `Operation` enum + all four per-op constants
            present in `helixor-oracle/oracle/operation_freshness.py`.
  DBP-1d   AW-01-EXT anchor — `verifyAgainstSolanaLedger` exported
            from `helixor-sdk/src/input_provenance.ts`.
  DBP-1e   DBP-3 safe-default invariant — `@helixor/sdk/unsafe` subpath
            is exported from `helixor-sdk/src/unsafe.ts`, and any
            partner cert-reader source that imports `@helixor/sdk/unsafe`
            ALSO uses `SafeCertReader` (the linter's "wrapped, not raw"
            check).

Designed to be runnable by anyone — partners run it self-serve on their
own checked-out fork as a pre-flight before opening a manifest PR.

USAGE
-----
    python3 audit/consumer_integration_check.py [--json <path>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
INTEGRATIONS_DIR = REPO_ROOT / "launch" / "integrations"


# =============================================================================
# Result types
# =============================================================================

SEVERITY_HARD = "HARD"
SEVERITY_SOFT = "SOFT"


@dataclass(frozen=True, slots=True)
class Finding:
    family: str
    severity: str
    rule: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "family": self.family,
            "severity": self.severity,
            "rule": self.rule,
            "detail": self.detail,
        }


@dataclass
class Report:
    checked: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def hard(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_HARD]

    def soft(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_SOFT]

    def to_json(self) -> str:
        return json.dumps(
            {
                "checked": self.checked,
                "findings": [f.to_dict() for f in self.findings],
                "summary": {
                    "checks": len(self.checked),
                    "hard_findings": len(self.hard()),
                    "soft_findings": len(self.soft()),
                },
            },
            indent=2,
            sort_keys=True,
        )


# =============================================================================
# Helpers
# =============================================================================

def _read(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def _require(
    report: Report,
    *,
    family: str,
    rule: str,
    condition: bool,
    detail: str,
    severity: str = SEVERITY_HARD,
) -> None:
    if not condition:
        report.add(Finding(family=family, severity=severity, rule=rule, detail=detail))


# =============================================================================
# Constants the linter cross-checks against
# =============================================================================

KNOWN_OPERATIONS: tuple[str, ...] = (
    "LOAN_ISSUE",
    "LOAN_INCREASE",
    "LIQUIDATION_CHECK",
    "STATUS_READ",
)

# Partner-side source markers per operation. The linter accepts EITHER the
# Python-style constant OR the TS-style enum label since partners code in
# either language.
OPERATION_SOURCE_MARKERS: dict[str, tuple[str, ...]] = {
    "LOAN_ISSUE": ("LOAN_ISSUE_MAX_AGE_SECONDS", "Operation.LOAN_ISSUE", "'LOAN_ISSUE'", '"LOAN_ISSUE"'),
    "LOAN_INCREASE": ("LOAN_INCREASE_MAX_AGE_SECONDS", "Operation.LOAN_INCREASE", "'LOAN_INCREASE'", '"LOAN_INCREASE"'),
    "LIQUIDATION_CHECK": ("LIQUIDATION_CHECK_MAX_AGE_SECONDS", "Operation.LIQUIDATION_CHECK", "'LIQUIDATION_CHECK'", '"LIQUIDATION_CHECK"'),
    "STATUS_READ": ("STATUS_READ_MAX_AGE_SECONDS", "Operation.STATUS_READ", "'STATUS_READ'", '"STATUS_READ"'),
}

REQUIRED_MANIFEST_FIELDS: tuple[str, ...] = (
    "partner_name",
    "partner_wallet",
    "integration_version",
    "cert_reader_source_paths",
    "operations_bound",
    "safe_reader_imported",
    "input_provenance_verified",
    "slot_anchor_verified",
    "integration_hash",
    "signature_ed25519",
)

BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

# The audit-mandated SOL-3 per-operation floor constants (in seconds).
SOL3_FLOORS: dict[str, int] = {
    "LOAN_ISSUE_MAX_AGE_SECONDS": 4 * 3600,
    "LOAN_INCREASE_MAX_AGE_SECONDS": 8 * 3600,
    "LIQUIDATION_CHECK_MAX_AGE_SECONDS": 12 * 3600,
    "STATUS_READ_MAX_AGE_SECONDS": 48 * 3600,
}


# =============================================================================
# DBP-1a — per-manifest checks
# =============================================================================

def _canonical_hash(manifest: dict) -> str:
    m = {k: v for k, v in manifest.items() if k not in ("integration_hash", "signature_ed25519")}
    canonical = json.dumps(m, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _check_manifest(report: Report, manifest_path: Path) -> None:
    family = f"DBP-1a[{manifest_path.name}]"
    report.checked.append(family)

    raw = _read(manifest_path)
    _require(
        report,
        family=family,
        rule="manifest-readable",
        condition=bool(raw.strip()),
        detail=f"{manifest_path} is empty or unreadable",
    )
    if not raw.strip():
        return

    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        _require(
            report,
            family=family,
            rule="manifest-valid-json",
            condition=False,
            detail=f"{manifest_path} is not valid JSON: {exc}",
        )
        return

    # ---- required fields
    for fld in REQUIRED_MANIFEST_FIELDS:
        _require(
            report,
            family=family,
            rule=f"required-field:{fld}",
            condition=fld in manifest,
            detail=f"{manifest_path} missing required field {fld!r}",
        )
    if any(f not in manifest for f in REQUIRED_MANIFEST_FIELDS):
        return

    # ---- partner_name
    _require(
        report,
        family=family,
        rule="partner-name-nonempty",
        condition=isinstance(manifest["partner_name"], str)
        and 0 < len(manifest["partner_name"]) <= 64,
        detail=f"partner_name must be a non-empty string of length <= 64",
    )

    # ---- partner_wallet
    wallet = manifest.get("partner_wallet", "")
    _require(
        report,
        family=family,
        rule="partner-wallet-base58",
        condition=(
            isinstance(wallet, str)
            and 32 <= len(wallet) <= 44
            and set(wallet).issubset(BASE58_ALPHABET)
        ),
        detail=(
            f"partner_wallet={wallet!r} must be a base58 string of length 32-44 "
            f"(typical Solana pubkey)"
        ),
    )

    # ---- integration_version
    _require(
        report,
        family=family,
        rule="integration-version-nonempty",
        condition=isinstance(manifest["integration_version"], str)
        and manifest["integration_version"].strip() != "",
        detail="integration_version must be a non-empty string (use SemVer)",
    )

    # ---- cert_reader_source_paths
    paths = manifest.get("cert_reader_source_paths", [])
    _require(
        report,
        family=family,
        rule="cert-reader-paths-nonempty",
        condition=isinstance(paths, list) and len(paths) > 0,
        detail="cert_reader_source_paths must be a non-empty list",
    )
    if not isinstance(paths, list):
        paths = []

    # ---- operations_bound
    ops = manifest.get("operations_bound", [])
    _require(
        report,
        family=family,
        rule="operations-bound-nonempty",
        condition=isinstance(ops, list) and len(ops) > 0,
        detail="operations_bound must be a non-empty list",
    )
    if not isinstance(ops, list):
        ops = []
    for op in ops:
        _require(
            report,
            family=family,
            rule="operations-bound-known",
            condition=op in KNOWN_OPERATIONS,
            detail=f"operations_bound contains unknown operation {op!r} "
            f"(known: {KNOWN_OPERATIONS})",
        )

    # ---- the three "I attest" flags must all be true
    for flag in ("safe_reader_imported", "input_provenance_verified", "slot_anchor_verified"):
        _require(
            report,
            family=family,
            rule=f"attest-flag:{flag}",
            condition=manifest.get(flag) is True,
            detail=f"{flag} must be true (a Verified Integrator wires the safe surfaces)",
        )

    # ---- integration_hash matches canonical recompute
    expected = _canonical_hash(manifest)
    actual = manifest.get("integration_hash", "")
    _require(
        report,
        family=family,
        rule="integration-hash-matches",
        condition=actual == expected,
        detail=(
            f"integration_hash mismatch — manifest claims {actual!r}, "
            f"canonical recompute = {expected!r}. Regenerate via the helper in "
            f"launch/integrations/MANIFEST_SCHEMA.md"
        ),
    )

    # ---- signature_ed25519 present (linter does NOT verify the signature —
    # that's the on-chain DBP-2 register_verified_consumer ix's job)
    sig = manifest.get("signature_ed25519", "")
    _require(
        report,
        family=family,
        rule="signature-present",
        condition=isinstance(sig, str) and len(sig) > 0,
        detail="signature_ed25519 must be a non-empty string",
    )

    # ---- per-source verification
    for src_rel in paths:
        if not isinstance(src_rel, str):
            _require(
                report,
                family=family,
                rule="cert-reader-path-string",
                condition=False,
                detail=f"cert_reader_source_paths entry must be string, got {type(src_rel).__name__}",
            )
            continue
        src_path = REPO_ROOT / src_rel
        _require(
            report,
            family=family,
            rule=f"cert-reader-exists[{src_rel}]",
            condition=src_path.is_file(),
            detail=f"cert_reader_source_paths entry {src_rel!r} does not exist on disk",
        )
        if not src_path.is_file():
            continue

        src = _read(src_path)

        # VULN-23 marker — SafeCertReader (TS) or SafeCertReader (Python equiv)
        _require(
            report,
            family=family,
            rule=f"safe-reader-marker[{src_rel}]",
            condition="SafeCertReader" in src,
            detail=f"{src_rel} does not contain the SafeCertReader marker — "
            f"VULN-23 freshness+velocity floor is not wired",
        )

        # AW-01 input-provenance marker
        _require(
            report,
            family=family,
            rule=f"input-provenance-marker[{src_rel}]",
            condition="verifyInputProvenance" in src,
            detail=f"{src_rel} does not contain verifyInputProvenance — "
            f"AW-01 input provenance is not wired",
        )

        # AW-01-EXT slot-anchor marker
        _require(
            report,
            family=family,
            rule=f"slot-anchor-marker[{src_rel}]",
            condition="verifyAgainstSolanaLedger" in src,
            detail=f"{src_rel} does not contain verifyAgainstSolanaLedger — "
            f"AW-01-EXT slot-anchor verification is not wired",
        )

        # Per-operation floor markers
        for op in ops:
            if op not in OPERATION_SOURCE_MARKERS:
                continue
            markers = OPERATION_SOURCE_MARKERS[op]
            _require(
                report,
                family=family,
                rule=f"operation-floor-marker[{src_rel}:{op}]",
                condition=any(m in src for m in markers),
                detail=(
                    f"{src_rel} does not reference operation {op!r} via any of "
                    f"{markers!r} — partner claims to bind {op} in manifest but "
                    f"source has no matching constant or enum label"
                ),
            )

        # DBP-3 — if the source imports from `@helixor/sdk/unsafe`, it MUST
        # wrap the raw client in `SafeCertReader`. A bare `/unsafe` import
        # without a SafeCertReader anchor in the same file is the exact
        # pattern Path-4 attackers exploit: raw `getScore()` with no
        # freshness or velocity guard.
        imports_unsafe = (
            "@helixor/sdk/unsafe" in src
            or "'@helixor/sdk/unsafe'" in src
        )
        if imports_unsafe:
            _require(
                report,
                family=family,
                rule=f"unsafe-import-must-wrap[{src_rel}]",
                condition="SafeCertReader" in src,
                detail=(
                    f"{src_rel} imports from @helixor/sdk/unsafe but does NOT "
                    f"use SafeCertReader in the same file. A Verified "
                    f"Integrator that touches raw cert-reading MUST wrap it "
                    f"in SafeCertReader to keep the VULN-23 freshness + "
                    f"velocity guard. See launch/integrations/example_safe_"
                    f"partner/reader.ts for the canonical pattern."
                ),
            )


def check_manifests(report: Report) -> None:
    if not INTEGRATIONS_DIR.is_dir():
        report.checked.append("DBP-1a[no manifests dir]")
        _require(
            report,
            family="DBP-1a[no manifests dir]",
            rule="integrations-dir-exists",
            condition=False,
            detail=f"{INTEGRATIONS_DIR} does not exist",
            severity=SEVERITY_SOFT,
        )
        return

    manifests = sorted(INTEGRATIONS_DIR.glob("*.json"))
    if not manifests:
        report.checked.append("DBP-1a[no manifests]")
        report.add(
            Finding(
                family="DBP-1a[no manifests]",
                severity=SEVERITY_SOFT,
                rule="at-least-one-manifest",
                detail=(
                    f"No partner manifests found under {INTEGRATIONS_DIR}. At "
                    f"minimum the reference example_safe_partner.json should be "
                    f"present so the linter has a canonical green target."
                ),
            )
        )
        return

    for path in manifests:
        _check_manifest(report, path)


# =============================================================================
# DBP-1b — VULN-23 anchor (SafeCertReader in helixor-sdk)
# =============================================================================

def check_vuln23_anchor(report: Report) -> None:
    family = "DBP-1b[VULN-23 anchor]"
    report.checked.append(family)

    src = _read(REPO_ROOT / "helixor-sdk" / "src" / "safe_reader.ts")
    _require(
        report,
        family=family,
        rule="safe-cert-reader-class-present",
        condition="export class SafeCertReader" in src,
        detail="helixor-sdk/src/safe_reader.ts no longer exports class SafeCertReader",
    )
    _require(
        report,
        family=family,
        rule="cert-max-age-pinned",
        condition="CERT_MAX_AGE_SECONDS = 48 * 60 * 60" in src,
        detail="helixor-sdk/src/safe_reader.ts no longer pins CERT_MAX_AGE_SECONDS = 48 * 60 * 60",
    )
    _require(
        report,
        family=family,
        rule="max-score-velocity-pinned",
        condition="MAX_SCORE_VELOCITY = 200" in src,
        detail="helixor-sdk/src/safe_reader.ts no longer pins MAX_SCORE_VELOCITY = 200",
    )
    _require(
        report,
        family=family,
        rule="velocity-window-pinned",
        condition="VELOCITY_WINDOW_EPOCHS = 3" in src,
        detail="helixor-sdk/src/safe_reader.ts no longer pins VELOCITY_WINDOW_EPOCHS = 3",
    )
    _require(
        report,
        family=family,
        rule="min-history-pinned",
        condition="MIN_HISTORY_REQUIRED = 2" in src,
        detail="helixor-sdk/src/safe_reader.ts no longer pins MIN_HISTORY_REQUIRED = 2",
    )

    index_src = _read(REPO_ROOT / "helixor-sdk" / "src" / "index.ts")
    _require(
        report,
        family=family,
        rule="safe-cert-reader-reexported",
        condition="SafeCertReader" in index_src and "from \"./safe_reader\"" in index_src,
        detail="@helixor/sdk no longer re-exports SafeCertReader from ./safe_reader",
    )


# =============================================================================
# DBP-1c — SOL-3 anchor (Operation enum + per-op constants)
# =============================================================================

def check_sol3_anchor(report: Report) -> None:
    family = "DBP-1c[SOL-3 anchor]"
    report.checked.append(family)

    src = _read(REPO_ROOT / "helixor-oracle" / "oracle" / "operation_freshness.py")
    _require(
        report,
        family=family,
        rule="operation-enum-present",
        condition="class Operation(str, Enum):" in src,
        detail="helixor-oracle/oracle/operation_freshness.py no longer exports the Operation enum",
    )
    _require(
        report,
        family=family,
        rule="verify-operation-freshness-present",
        condition="def verify_operation_freshness(" in src,
        detail="helixor-oracle/oracle/operation_freshness.py no longer exports verify_operation_freshness",
    )

    for op, seconds in SOL3_FLOORS.items():
        # Allow either `4 * 3600` or `14400` style literal.
        candidates = (
            f"{op} = {seconds // 3600} * 3600",
            f"{op} = {seconds}",
            f"{op}: int = {seconds // 3600} * 3600",
            f"{op}: int = {seconds}",
        )
        _require(
            report,
            family=family,
            rule=f"sol3-constant[{op}]",
            condition=any(c in src for c in candidates),
            detail=(
                f"helixor-oracle/oracle/operation_freshness.py no longer pins "
                f"{op} = {seconds} seconds. SOL-3 floors must match the "
                f"audit-mandated values."
            ),
        )

    # The enum labels themselves are referenced by the linter's
    # OPERATION_SOURCE_MARKERS — pin them here too so a rename lights red.
    for op in KNOWN_OPERATIONS:
        _require(
            report,
            family=family,
            rule=f"sol3-enum-label[{op}]",
            condition=f"{op} = " in src or f'"{op}"' in src,
            detail=(
                f"helixor-oracle/oracle/operation_freshness.py no longer "
                f"references the {op!r} enum label that partner manifests bind."
            ),
        )


# =============================================================================
# DBP-1d — AW-01-EXT anchor (verifyAgainstSolanaLedger in SDK)
# =============================================================================

def check_aw01ext_anchor(report: Report) -> None:
    family = "DBP-1d[AW-01-EXT anchor]"
    report.checked.append(family)

    src = _read(REPO_ROOT / "helixor-sdk" / "src" / "input_provenance.ts")
    _require(
        report,
        family=family,
        rule="verify-against-solana-ledger-present",
        condition="verifyAgainstSolanaLedger" in src,
        detail="helixor-sdk/src/input_provenance.ts no longer exports verifyAgainstSolanaLedger",
    )
    _require(
        report,
        family=family,
        rule="verify-input-provenance-present",
        condition="verifyInputProvenance" in src,
        detail="helixor-sdk/src/input_provenance.ts no longer exports verifyInputProvenance",
    )

    index_src = _read(REPO_ROOT / "helixor-sdk" / "src" / "index.ts")
    _require(
        report,
        family=family,
        rule="aw01ext-reexported",
        condition="verifyAgainstSolanaLedger" in index_src,
        detail="@helixor/sdk no longer re-exports verifyAgainstSolanaLedger",
    )


# =============================================================================
# DBP-1e — DBP-3 safe-default invariant
#
# Two parts:
#   (1) `helixor-sdk/src/unsafe.ts` exists and re-exports HelixorClient +
#       HelixorChainClient. If a refactor deletes this file, every
#       partner who imports from `@helixor/sdk/unsafe` will silently
#       resolve to `undefined` at runtime — lint that BEFORE it ships.
#   (2) The default `helixor-sdk/src/index.ts` no longer exports the
#       raw cert-reader primitives (`HelixorClient` / `HelixorChainClient`).
#       Re-introducing them to the default surface defeats the DBP-3
#       safe-by-default invariant: misuse becomes opt-out instead of
#       opt-in.
# =============================================================================

# Pinned to match the surfaces declared in helixor-sdk/src/unsafe.ts.
UNSAFE_REEXPORTS: tuple[str, ...] = (
    "HelixorClient",
    "HelixorChainClient",
)


def check_unsafe_surface(report: Report) -> None:
    family = "DBP-1e[DBP-3 safe-default]"
    report.checked.append(family)

    unsafe_src = _read(REPO_ROOT / "helixor-sdk" / "src" / "unsafe.ts")
    _require(
        report,
        family=family,
        rule="unsafe-subpath-exists",
        condition=bool(unsafe_src.strip()),
        detail=(
            "helixor-sdk/src/unsafe.ts no longer exists. The @helixor/sdk/"
            "unsafe subpath that partners (e.g. example_safe_partner) "
            "import from is unreachable — restore the file or coordinate "
            "a deprecation rollout with active partners."
        ),
    )
    for name in UNSAFE_REEXPORTS:
        _require(
            report,
            family=family,
            rule=f"unsafe-reexports[{name}]",
            condition=name in unsafe_src,
            detail=(
                f"helixor-sdk/src/unsafe.ts no longer re-exports {name!r}. "
                f"Any partner that imports {name!r} from @helixor/sdk/unsafe "
                f"will get `undefined`. Restore the re-export or coordinate "
                f"the partner migration."
            ),
        )

    default_src = _read(REPO_ROOT / "helixor-sdk" / "src" / "index.ts")
    for name in UNSAFE_REEXPORTS:
        # The default `@helixor/sdk` entry MUST NOT name the raw client
        # surface in its export list. We grep the export keyword adjacent
        # to the name to avoid matching a banal comment mention; the SDK
        # convention is `export { Name, ... }`.
        leak_patterns = (
            f"export {{ {name}",
            f"export {{\n  {name}",
            f"  {name},",
            f"  {name}\n",
        )
        # A leak fires only if the symbol is present in the source AND
        # appears inside an export list. The simple heuristic: the
        # default `index.ts` must not contain the symbol name at all,
        # since it does not legitimately reference these classes.
        _require(
            report,
            family=family,
            rule=f"default-does-not-leak[{name}]",
            condition=name not in default_src,
            detail=(
                f"helixor-sdk/src/index.ts references {name!r} — the DBP-3 "
                f"safe-by-default invariant requires raw cert-reader "
                f"primitives to live ONLY under @helixor/sdk/unsafe. Move "
                f"the export to unsafe.ts."
            ),
        )
        # Defensive double-check on the leak-pattern shape; redundant with
        # the above but pins the export list specifically in case the
        # default ever needs to legitimately mention the name (e.g. in a
        # comment with a quoted import example).
        _ = leak_patterns  # noqa: F841 — kept inline as the intent doc


# =============================================================================
# Driver
# =============================================================================

def run() -> Report:
    report = Report()
    check_manifests(report)
    check_vuln23_anchor(report)
    check_sol3_anchor(report)
    check_aw01ext_anchor(report)
    check_unsafe_surface(report)
    return report


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--json",
        dest="json_out",
        default=None,
        help="write the JSON report to this path",
    )
    args = p.parse_args(argv)

    report = run()

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report.to_json())

    summary = (
        f"consumer_integration_check: {len(report.checked)} checks, "
        f"{len(report.hard())} hard, {len(report.soft())} soft"
    )
    if args.json_out:
        summary += f" -> {args.json_out}"
    print(summary)

    if report.hard():
        for f in report.hard():
            print(f"  HARD [{f.family}] {f.rule}: {f.detail}", file=sys.stderr)
        return 1
    if report.soft():
        for f in report.soft():
            print(f"  SOFT [{f.family}] {f.rule}: {f.detail}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
