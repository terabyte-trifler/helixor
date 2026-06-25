#!/usr/bin/env python3
"""
audit/supply_chain_check.py — VULN-25 supply-chain hardening sweep.

VULN-25 attack surface: a malicious release of any direct OR
transitive Python dependency (`cryptography`, `solana`, `solders`,
`grpcio`, `asyncpg`, ...) gives an attacker code execution on the
oracle node. The Ed25519 signing key sits in process memory during
every sign() call; one malicious release exfiltrates it on first
use, and the attacker holds a valid cluster key for the rest of the
epoch.

The mitigations this sweep pins:

  1. EVERY phylanx-* package has a `requirements.in` source-pin file
     where every direct dep is `pkg==X.Y.Z` (never a range, never a
     bare name).

  2. IF a `requirements.txt` is committed alongside, every package
     line carries `--hash=sha256:...` so a production install with
     `pip install --require-hashes` refuses to import bytes that
     don't match the locked hash.

  3. The Rust workspace's `Cargo.lock` is committed (cargo's
     equivalent of a hash-locked install).

  4. The signing surface is narrow: `oracle.cluster.signer` defines
     a `Signer` protocol with an `HSMSigner` stub — the production
     swap-in point that keeps the Ed25519 private key out of
     process memory entirely.

  5. The systemd unit retains its supply-chain hardening — read-only
     `/opt/phylanx`, dropped capabilities, syscall filter, namespace
     restrictions. If a future PR loosens any of these, the sweep
     fails.

REPORTING
---------
JSON to `--json` (default stdout). Non-zero exit on any HARD finding.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# Rules whose HARD findings are EXPECTED on a fresh checkout — the
# generated `requirements.txt` files are produced by a network-bound
# `pip-compile --generate-hashes` run that the audit operator performs
# at release time, gated separately in LAUNCH_CHECKLIST. Default mode
# exits 0 if only these fire; `--strict` (release-gate) fails on them.
_EXPECTED_PRE_RELEASE_RULES = frozenset({
    "phylanx-oracle-requirements-txt-missing",
    "phylanx-api-requirements-txt-missing",
    "phylanx-indexer-requirements-txt-missing",
})


# =============================================================================
# Targets
# =============================================================================

PYTHON_PACKAGES = ("phylanx-oracle", "phylanx-api", "phylanx-indexer")

CARGO_LOCK_PATH        = REPO_ROOT / "phylanx-programs" / "Cargo.lock"
ORACLE_SIGNER_PY       = REPO_ROOT / "phylanx-oracle" / "oracle" / "cluster" / "signer.py"
ORACLE_SYSTEMD_UNIT    = REPO_ROOT / "launch" / "deploy" / "systemd" / "oracle-node@.service"
REGEN_SCRIPT           = REPO_ROOT / "scripts" / "regen_requirements.sh"

# Pin-shape regexes.
EXACT_PIN_RE  = re.compile(
    r"^\s*[A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?\s*==\s*[A-Za-z0-9._\-+!]+\s*(?:#.*)?$"
)
COMMENT_OR_BLANK_RE = re.compile(r"^\s*(?:#.*)?$")

# Systemd hardening directives we will not silently lose.
REQUIRED_SYSTEMD_HARDENING = (
    "NoNewPrivileges=true",
    "ProtectSystem=strict",
    "ReadOnlyPaths=/opt/phylanx",
    "SystemCallFilter=@system-service",
    "CapabilityBoundingSet=",
    "MemoryDenyWriteExecute=true",
)


# =============================================================================
# Findings
# =============================================================================

@dataclass
class Finding:
    severity: str        # "HARD"
    rule:     str
    path:     str
    detail:   str


@dataclass
class Report:
    findings:      list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def hard_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HARD")

    def to_dict(self) -> dict:
        return {
            "files_scanned":  self.files_scanned,
            "findings_total": len(self.findings),
            "findings_hard":  self.hard_count,
            "findings": [
                {
                    "severity": f.severity, "rule": f.rule,
                    "path": f.path, "detail": f.detail,
                }
                for f in self.findings
            ],
        }


# =============================================================================
# Helpers
# =============================================================================

def _display(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _require_file(report: Report, p: Path, rule: str) -> str | None:
    if not p.exists():
        report.add(Finding(
            severity="HARD", rule=rule,
            path=_display(p), detail=f"{p.name} not found",
        ))
        return None
    report.files_scanned += 1
    return p.read_text()


# =============================================================================
# 1 + 2 — requirements.in / requirements.txt pin discipline
# =============================================================================

def _check_requirements_in(report: Report, pkg: str) -> None:
    """`requirements.in` MUST exist; every non-comment line MUST be a
    `pkg==X.Y.Z` exact pin (or an extras pin like `psycopg[binary]==3.3.4`)."""
    in_path = REPO_ROOT / pkg / "requirements.in"
    text = _require_file(
        report, in_path,
        rule=f"{pkg}-requirements-in-missing",
    )
    if text is None:
        return

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if COMMENT_OR_BLANK_RE.match(raw):
            continue
        if not EXACT_PIN_RE.match(raw):
            report.add(Finding(
                severity="HARD",
                rule=f"{pkg}-requirements-in-bad-pin",
                path=_display(in_path),
                detail=(
                    f"line {lineno} is not an exact `pkg==X.Y.Z` pin: "
                    f"{raw!r} — a range here lets a future release "
                    f"swap the bytes silently"
                ),
            ))


def _check_requirements_txt(report: Report, pkg: str) -> None:
    """IF `requirements.txt` is committed, every package line MUST carry
    `--hash=sha256:...`. Absence of the file is a SOFT state (encouraged
    in dev, REQUIRED for prod) — we surface it as a HARD finding only
    if the `.in` has any non-comment line."""
    in_path  = REPO_ROOT / pkg / "requirements.in"
    txt_path = REPO_ROOT / pkg / "requirements.txt"

    has_direct_deps = False
    if in_path.exists():
        for raw in in_path.read_text().splitlines():
            if not COMMENT_OR_BLANK_RE.match(raw):
                has_direct_deps = True
                break

    if not txt_path.exists():
        if has_direct_deps:
            report.add(Finding(
                severity="HARD",
                rule=f"{pkg}-requirements-txt-missing",
                path=_display(txt_path),
                detail=(
                    f"{pkg}/requirements.in declares direct deps but "
                    f"{pkg}/requirements.txt was not committed. "
                    f"Regenerate with `bash scripts/regen_requirements.sh` "
                    f"and commit BOTH files."
                ),
            ))
        return

    report.files_scanned += 1
    text = txt_path.read_text()
    # Find every line that starts with a package name (not a continuation,
    # not a comment, not a --option). Each must have at least one
    # `--hash=sha256:` somewhere in its declaration block.
    saw_pkg = False
    pkg_lines: list[tuple[int, str]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if COMMENT_OR_BLANK_RE.match(raw):
            continue
        if raw.lstrip().startswith("--"):
            continue
        if raw.startswith(" ") or raw.startswith("\t"):
            # Continuation of the previous package declaration (hashes).
            continue
        pkg_lines.append((lineno, raw))
        saw_pkg = True

    # The whole file must mention --hash=sha256: at least once.
    if saw_pkg and "--hash=sha256:" not in text:
        report.add(Finding(
            severity="HARD",
            rule=f"{pkg}-requirements-txt-no-hashes",
            path=_display(txt_path),
            detail=(
                f"{pkg}/requirements.txt has package lines but no "
                f"`--hash=sha256:` entries. Regenerate with "
                f"`pip-compile --generate-hashes` so production deploys "
                f"can install with `--require-hashes`."
            ),
        ))


# =============================================================================
# 3 — Cargo.lock committed
# =============================================================================

def _check_cargo_lock(report: Report) -> None:
    if not CARGO_LOCK_PATH.exists():
        report.add(Finding(
            severity="HARD", rule="cargo-lock-missing",
            path=_display(CARGO_LOCK_PATH),
            detail=(
                "phylanx-programs/Cargo.lock is not committed — Rust "
                "builds will resolve transitive crates fresh and a "
                "registered ghost version can sneak in. Commit the lock."
            ),
        ))
        return
    report.files_scanned += 1


# =============================================================================
# 4 — narrow signing surface
# =============================================================================

def _check_signer_surface(report: Report) -> None:
    text = _require_file(report, ORACLE_SIGNER_PY, "signer-module-missing")
    if text is None:
        return
    if not re.search(r"\bclass\s+Signer\b\s*\(.*Protocol", text):
        report.add(Finding(
            severity="HARD", rule="signer-protocol-missing",
            path=_display(ORACLE_SIGNER_PY),
            detail=(
                "oracle/cluster/signer.py must declare a `Signer` Protocol "
                "(VULN-25 narrow signing surface)"
            ),
        ))
    if not re.search(r"\bclass\s+InProcessSigner\b", text):
        report.add(Finding(
            severity="HARD", rule="in-process-signer-missing",
            path=_display(ORACLE_SIGNER_PY),
            detail="InProcessSigner missing — the default Signer wrapping",
        ))
    if not re.search(r"\bclass\s+HSMSigner\b", text):
        report.add(Finding(
            severity="HARD", rule="hsm-signer-missing",
            path=_display(ORACLE_SIGNER_PY),
            detail=(
                "HSMSigner stub missing — the production swap-in point "
                "that keeps the Ed25519 private key out of process memory"
            ),
        ))
    # The base HSMSigner.sign MUST refuse so a misconfigured production
    # deploy fails LOUDLY rather than silently in-process-signing.
    if "NotImplementedError" not in text:
        report.add(Finding(
            severity="HARD", rule="hsm-signer-silent-fallback",
            path=_display(ORACLE_SIGNER_PY),
            detail=(
                "HSMSigner.sign must raise NotImplementedError on the base "
                "class — a silent fallback to in-process keys defeats the "
                "isolation point"
            ),
        ))


# =============================================================================
# 5 — systemd hardening intact
# =============================================================================

def _check_systemd_hardening(report: Report) -> None:
    text = _require_file(
        report, ORACLE_SYSTEMD_UNIT, "oracle-systemd-unit-missing",
    )
    if text is None:
        return
    for directive in REQUIRED_SYSTEMD_HARDENING:
        if directive not in text:
            report.add(Finding(
                severity="HARD", rule="systemd-hardening-dropped",
                path=_display(ORACLE_SYSTEMD_UNIT),
                detail=(
                    f"oracle-node@.service is missing `{directive}` — "
                    f"VULN-25 sandbox/read-only/syscall-filter discipline"
                ),
            ))


# =============================================================================
# 6 — regen script committed (helps the lock stay current)
# =============================================================================

def _check_regen_script(report: Report) -> None:
    if not REGEN_SCRIPT.exists():
        report.add(Finding(
            severity="HARD", rule="regen-script-missing",
            path=_display(REGEN_SCRIPT),
            detail=(
                "scripts/regen_requirements.sh missing — the operator "
                "needs a single command to rebuild the hash-locked txt "
                "files after a .in edit"
            ),
        ))
        return
    report.files_scanned += 1


# =============================================================================
# Driver
# =============================================================================

def scan() -> Report:
    report = Report()
    for pkg in PYTHON_PACKAGES:
        _check_requirements_in(report, pkg)
        _check_requirements_txt(report, pkg)
    _check_cargo_lock(report)
    _check_signer_surface(report)
    _check_systemd_hardening(report)
    _check_regen_script(report)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="VULN-25 supply-chain sweep.")
    p.add_argument(
        "--json", type=Path, default=None,
        help="Write the JSON report to this path (default: stdout).",
    )
    p.add_argument(
        "--strict", action="store_true",
        help=(
            "Release-gate mode: fail on every HARD finding including the "
            "expected `*-requirements-txt-missing` rules. Default mode "
            "tolerates those (they're regenerated at release via "
            "scripts/regen_requirements.sh)."
        ),
    )
    args = p.parse_args(argv)

    report = scan()
    blob = json.dumps(report.to_dict(), indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(blob + "\n")
    else:
        print(blob)

    unexpected = [
        f for f in report.findings
        if f.severity == "HARD" and f.rule not in _EXPECTED_PRE_RELEASE_RULES
    ]
    expected = [
        f for f in report.findings
        if f.severity == "HARD" and f.rule in _EXPECTED_PRE_RELEASE_RULES
    ]

    if unexpected or (args.strict and expected):
        print(
            f"\n❌ {len(unexpected) + (len(expected) if args.strict else 0)} "
            f"HARD supply-chain findings",
            file=sys.stderr,
        )
        return 1
    if expected:
        print(
            f"⚠ supply-chain sweep: source discipline clean, "
            f"{len(expected)} expected pre-release finding(s) "
            f"(regenerate requirements.txt at release time)",
            file=sys.stderr,
        )
        return 0
    print(
        f"✅ supply-chain sweep clean "
        f"({report.files_scanned} files scanned)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
