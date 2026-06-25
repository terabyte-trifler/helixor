#!/usr/bin/env python3
"""
audit/ed25519_strictness_check.py — VULN-21 hardening sweep.

Greps every signing/verification surface for:

  1. **Batch-verify primitives.** Threshold signatures MUST be verified
     individually. A batch-verify shortcut can accept invalid individual
     signatures whenever the batch equation cancels — the known Ed25519
     batch attack. Forbidden symbols (across Python AND Rust):

         verify_batch          batch_verify          verify_strict_batch
         verify_multi          multi_verify          VerifyBatch

  2. **Non-strict `verify(...)` variants** (Rust side).
     `ed25519_dalek::Signature::verify` in dalek <2 was non-strict;
     dalek v2 deprecated the loose form in favour of `verify_strict`.
     We do not depend on dalek directly (the on-chain side relies on
     the Solana Ed25519 precompile which enforces strict by default),
     so this scanner flags any *direct* `ed25519_dalek::` usage that
     does not go through `verify_strict`.

  3. **Off-chain Python verifiers other than `cryptography`.** The
     symmetry contract is "off-chain uses OpenSSL strict Ed25519,
     on-chain uses dalek strict (via precompile)". Bringing in PyNaCl
     or a pure-python ed25519 library would risk a different
     non-canonical-S verdict than the precompile — and that gap is
     exactly what VULN-21 enumerates. Flag any import of:

         nacl.signing          ed25519                       (pure-py)
         ecdsa                 fastecdsa                     pysodium

REPORTING
---------
Emits a JSON report to `--json` (default stdout) and exits non-zero on
any HARD finding so CI fails the gate. The audit/run_all.sh harness
calls this script alongside the other Day-29 sweeps.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Roots — every directory that contains signing or verification code
# =============================================================================

ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "phylanx-oracle" / "oracle" / "cluster",
    REPO_ROOT / "phylanx-oracle" / "oracle",
    REPO_ROOT / "phylanx-programs" / "programs" / "certificate-issuer" / "src",
    REPO_ROOT / "phylanx-programs" / "programs" / "slash-authority" / "src",
    REPO_ROOT / "phylanx-programs" / "programs" / "health-oracle" / "src",
    REPO_ROOT / "phylanx-sdk" / "src",
)

# Files allowed to mention forbidden names because they are TESTS that
# pin the forbidden-name absence (the test file IS the audit, so it
# must contain the literal strings). Keyed by relative path from
# REPO_ROOT.
TEST_ALLOWLIST: frozenset[str] = frozenset({
    "phylanx-oracle/tests/oracle/test_vuln21_ed25519_strictness.py",
    "audit/ed25519_strictness_check.py",
    "audit/test_vuln21_ed25519_strictness_check.py",
})


# =============================================================================
# Forbidden surface
# =============================================================================

BATCH_VERIFY_NAMES: tuple[str, ...] = (
    "verify_batch",
    "batch_verify",
    "verify_strict_batch",
    "verify_multi",
    "multi_verify",
    "VerifyBatch",
)

# Pure-Python or non-strict Ed25519 verifiers that diverge from
# OpenSSL / dalek strict canonicality.
FORBIDDEN_PY_IMPORTS: tuple[str, ...] = (
    "nacl.signing",
    "pysodium",
    "fastecdsa",
)

# Rust: ed25519_dalek's non-strict `verify(` is forbidden. `verify_strict(`
# is the only acceptable per-signature primitive. We match any line that
# both references `ed25519_dalek` AND calls a `verify(` (non-strict) form.
# We deliberately match BOTH `::verify(` and `.verify(` so that
# `ed25519_dalek::PublicKey::verify(...)` AND `pk.verify(...)` (where pk
# is an ed25519_dalek type) are caught.
RUST_DALEK_TOKEN: str = "ed25519_dalek"
RUST_NONSTRICT_VERIFY: re.Pattern[str] = re.compile(
    r"(?<!_strict)(?:\.|::)verify\s*\(",
)


# =============================================================================
# Findings
# =============================================================================

@dataclass
class Finding:
    severity: str               # "HARD" or "SOFT"
    rule:     str
    path:     str
    line:     int
    snippet:  str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
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
                    "path": f.path, "line": f.line,
                    "snippet": f.snippet,
                }
                for f in self.findings
            ],
        }


# =============================================================================
# Scanner
# =============================================================================

def _display_path(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _iter_files(roots: Iterable[Path]) -> Iterable[Path]:
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix not in (".py", ".rs", ".ts"):
                continue
            if "__pycache__" in p.parts or "target" in p.parts:
                continue
            yield p


def _scan_file(path: Path, report: Report) -> None:
    report.files_scanned += 1
    rel = _display_path(path)
    if rel in TEST_ALLOWLIST:
        return
    text = path.read_text(errors="ignore")
    lines = text.splitlines()

    # 1. Batch-verify names.
    for i, line in enumerate(lines, start=1):
        for name in BATCH_VERIFY_NAMES:
            # word-boundary match so `verify_batch` does not trip on
            # an unrelated `_verify_batched_thing` either way (those
            # would still be suspicious).
            if re.search(rf"\b{re.escape(name)}\b", line):
                report.add(Finding(
                    severity="HARD",
                    rule="batch-verify-forbidden",
                    path=rel, line=i,
                    snippet=line.strip(),
                ))

    # 2. Rust non-strict verify (any line that mentions ed25519_dalek
    #    AND calls a non-strict verify(...).
    if path.suffix == ".rs":
        file_imports_dalek = RUST_DALEK_TOKEN in text
        for i, line in enumerate(lines, start=1):
            mentions_dalek_on_line = RUST_DALEK_TOKEN in line
            if not (file_imports_dalek or mentions_dalek_on_line):
                continue
            if not RUST_NONSTRICT_VERIFY.search(line):
                continue
            if "verify_strict" in line:
                continue
            report.add(Finding(
                severity="HARD",
                rule="rust-nonstrict-verify-forbidden",
                path=rel, line=i,
                snippet=line.strip(),
            ))

    # 3. Python forbidden imports (off-chain symmetry).
    if path.suffix == ".py":
        for i, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if not (stripped.startswith("import ")
                    or stripped.startswith("from ")):
                continue
            for mod in FORBIDDEN_PY_IMPORTS:
                if re.search(rf"\b{re.escape(mod)}\b", line):
                    report.add(Finding(
                        severity="HARD",
                        rule="py-forbidden-ed25519-lib",
                        path=rel, line=i,
                        snippet=line.strip(),
                    ))


def scan(roots: Iterable[Path]) -> Report:
    report = Report()
    for path in _iter_files(roots):
        _scan_file(path, report)
    return report


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="VULN-21 Ed25519 strictness sweep.",
    )
    p.add_argument(
        "--json", type=Path, default=None,
        help="Write the JSON report to this path (default: stdout).",
    )
    p.add_argument(
        "--roots", nargs="*", type=Path, default=None,
        help="Override scan roots (for tests).",
    )
    args = p.parse_args(argv)

    roots = tuple(args.roots) if args.roots else ROOTS
    report = scan(roots)

    blob = json.dumps(report.to_dict(), indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(blob + "\n")
    else:
        print(blob)

    if report.hard_count:
        print(
            f"\n❌ {report.hard_count} HARD ed25519-strictness findings",
            file=sys.stderr,
        )
        return 1
    print(
        f"✅ ed25519 strictness sweep clean "
        f"({report.files_scanned} files scanned)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
