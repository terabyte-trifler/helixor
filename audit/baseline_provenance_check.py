#!/usr/bin/env python3
"""
audit/baseline_provenance_check.py — AW-03 baseline-DA pin sweep.

AW-03 (Baseline Data Availability) closed the gap where the on-chain
`baseline_hash` was a commitment with NO mechanism for third parties to
fetch and verify the underlying behavioral data. The fix is layered:

  * On chain: a per-(agent, commit_nonce) `BaselineDataAccount` PDA stores
    the canonical payload bytes; `record_baseline` enforces
    `sha256(account.payload) == baseline_hash` at write time.
  * In the digest: `cert_payload_digest` folds the 8-byte
    `baseline_commit_nonce` into the signed bytes so the threshold
    signatures attest to a SPECIFIC ROTATION of the baseline.
  * In the SDK: `verifyBaselineProvenance` re-fetches the DA account
    from the chain and re-asserts the hash binding.

Every call to the affected signing/issuing surfaces MUST thread the
`baseline_commit_nonce` (Python/Rust) or `baselineCommitNonce` (TS).
A regression that quietly drops the argument would let a malicious
cluster rotate the baseline mid-attack and still emit a cert with a
stale hash that no longer points at a fetchable DA account — defeating
the AW-03 binding without raising a type error (the Python signature
defaults the nonce to `0` for legacy compat, and Anchor's `methods`
generator is stringly-typed at the TS layer).

This sweep enumerates every callsite of those functions across the
repo, extracts each call's argument region with balanced-paren
matching, and fails the gate if any callsite does not contain the
nonce keyword.

REPORTING
---------
Emits a JSON report to `--json` (default stdout) and exits non-zero on
any HARD finding. Wired into `audit/run_all.sh` alongside the AW-01
input-provenance sweep.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Scan roots — where Helixor calls live
# =============================================================================

# Scoped narrowly to PRODUCTION oracle code. Test files deliberately
# exercise the kwarg's default-0 legacy path; the audit's job is to
# enforce that production callers always thread the nonce explicitly.
PYTHON_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "helixor-oracle" / "oracle",
)

TS_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "helixor-programs" / "tests",
    REPO_ROOT / "helixor-sdk" / "src",
    REPO_ROOT / "helixor-sdk" / "test",
)


# Allowlisted files: the scanner itself, the scanner's tests, and any
# helper/fixture file that deliberately exercises the missing-arg path
# to test the AW-03 rejection branches.
DEFAULT_ALLOWLIST: frozenset[str] = frozenset({
    "audit/baseline_provenance_check.py",
    "audit/test_baseline_provenance_check.py",
})


# =============================================================================
# Pin definitions
# =============================================================================

@dataclass(frozen=True)
class Pin:
    """One pin: every call of `function` must mention `keyword` in its args."""
    function: str
    keyword:  str          # the token that must appear inside the (...) args
    label:    str          # human-readable rule name


PINS: tuple[Pin, ...] = (
    # Python: the cluster signing surface. `cert_payload_digest` accepts the
    # nonce as a keyword-only argument with default `0` so pre-AW-03 callers
    # remain compatible — but EVERY production caller must pass it
    # explicitly to bind the cert to a fetchable DA account. The scanner
    # enforces this convention so a future refactor that re-defaults the
    # kwarg cannot silently drop the binding from a production site.
    Pin(
        function="cert_payload_digest",
        keyword="baseline_commit_nonce",
        label="cert_payload_digest-missing-baseline_commit_nonce",
    ),
    # TS: integration tests and SDK helpers that recompute the digest
    # locally. Anchor's typed-method generator does not enforce arg presence
    # at compile time, so a missing arg there would not fail typecheck.
    Pin(
        function="certPayloadDigest",
        keyword="baselineCommitNonce",
        label="certPayloadDigest-missing-baselineCommitNonce",
    ),
    # TS: the SDK PDA derivation must thread the nonce — otherwise a
    # consumer would derive the wrong DA-account PDA and the hash check
    # would fail with `AccountNotFound` instead of a precise reason. The
    # keyword is `nonce` (lowercase substring) because callers commonly
    # rebind the value to a local `nonce` variable — `commitNonce` would
    # still match by substring.
    Pin(
        function="baselineDataPda",
        keyword="nonce",
        label="baselineDataPda-missing-nonce",
    ),
)


# =============================================================================
# Findings
# =============================================================================

@dataclass
class Finding:
    severity: str
    rule:     str
    path:     str
    line:     int
    snippet:  str


@dataclass
class Report:
    findings:      list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    callsites_checked: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def hard_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HARD")

    def to_dict(self) -> dict:
        return {
            "files_scanned":      self.files_scanned,
            "callsites_checked":  self.callsites_checked,
            "findings_total":     len(self.findings),
            "findings_hard":      self.hard_count,
            "findings": [
                {
                    "severity": f.severity, "rule": f.rule,
                    "path": f.path, "line": f.line, "snippet": f.snippet,
                }
                for f in self.findings
            ],
        }


# =============================================================================
# Balanced-paren extractor (TS only — Python uses AST below)
# =============================================================================

_STRING_CHARS = {'"', "'", "`"}


def _is_word_boundary(text: str, idx: int) -> bool:
    if idx == 0:
        return True
    prev = text[idx - 1]
    return not (prev.isalnum() or prev == "_")


def _skip_string_or_comment(text: str, i: int, suffix: str) -> int | None:
    ch = text[i]
    if ch == "#" and suffix == ".py":
        j = text.find("\n", i)
        return len(text) if j < 0 else j
    if ch == "/" and suffix in (".ts", ".rs") and i + 1 < len(text):
        nxt = text[i + 1]
        if nxt == "/":
            j = text.find("\n", i)
            return len(text) if j < 0 else j
        if nxt == "*":
            j = text.find("*/", i + 2)
            return len(text) if j < 0 else j + 2
    if ch in _STRING_CHARS:
        quote = ch
        j = i + 1
        if suffix == ".py" and text[i:i + 3] == quote * 3:
            j = text.find(quote * 3, i + 3)
            return len(text) if j < 0 else j + 3
        while j < len(text):
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == quote:
                return j + 1
            j += 1
        return len(text)
    return None


def _open_paren_after(text: str, i: int) -> int | None:
    while i < len(text) and text[i] in " \t\n\r":
        i += 1
    if i < len(text) and text[i] == "(":
        return i
    return None


def _find_calls(text: str, name: str, suffix: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number_1based, argument_region) for every call to `name(`."""
    name_len = len(name)
    i = 0
    line_starts = [0]
    for idx, c in enumerate(text):
        if c == "\n":
            line_starts.append(idx + 1)

    def _line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= pos:
                lo = mid + 1
            else:
                hi = mid - 1
        return hi + 1

    while i < len(text):
        skipped = _skip_string_or_comment(text, i, suffix)
        if skipped is not None:
            i = skipped
            continue
        if (
            text.startswith(name, i)
            and i + name_len < len(text)
            and _is_word_boundary(text, i)
            and _open_paren_after(text, i + name_len) is not None
        ):
            open_idx = _open_paren_after(text, i + name_len)
            assert open_idx is not None
            depth = 1
            j = open_idx + 1
            while j < len(text) and depth > 0:
                inner = _skip_string_or_comment(text, j, suffix)
                if inner is not None:
                    j = inner
                    continue
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if depth == 0:
                argument_region = text[open_idx + 1: j]
                yield _line_of(i), argument_region
                i = j + 1
                continue
        i += 1


# =============================================================================
# Scanner
# =============================================================================

def _display_path(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _iter_files(roots: Iterable[Path], suffixes: tuple[str, ...]) -> Iterable[Path]:
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix not in suffixes:
                continue
            if "__pycache__" in p.parts or "target" in p.parts:
                continue
            if "node_modules" in p.parts or "dist" in p.parts:
                continue
            yield p


# `cert_payload_digest` accepts `baseline_commit_nonce` as a keyword-only
# arg with default `0`. Production callers MUST pass it explicitly — the
# AST scanner accepts a kwarg match only (positional fallback is not
# possible since the arg is keyword-only).
def _scan_py_file(
    path:      Path,
    pin:       Pin,
    report:    Report,
    allowlist: frozenset[str],
) -> None:
    rel = _display_path(path)
    if rel in allowlist:
        return
    text = path.read_text(errors="ignore")
    if pin.function not in text:
        return
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called_name = (
            func.id if isinstance(func, ast.Name)
            else func.attr if isinstance(func, ast.Attribute)
            else None
        )
        if called_name != pin.function:
            continue
        report.callsites_checked += 1
        has_kw = any(
            kw.arg == pin.keyword for kw in node.keywords if kw.arg is not None
        )
        # `**kwargs` star-expansion supplies unknown keywords; trust it.
        has_starkw = any(kw.arg is None for kw in node.keywords)
        if has_kw or has_starkw:
            continue
        snippet = f"{pin.function}(...no '{pin.keyword}' kwarg)"
        report.add(Finding(
            severity="HARD", rule=pin.label,
            path=rel, line=node.lineno, snippet=snippet,
        ))


def _scan_ts_file(
    path:      Path,
    pin:       Pin,
    report:    Report,
    allowlist: frozenset[str],
) -> None:
    rel = _display_path(path)
    if rel in allowlist:
        return
    text = path.read_text(errors="ignore")
    if pin.function not in text:
        return
    keyword_lc = pin.keyword.lower()
    for line_no, args in _find_calls(text, pin.function, ".ts"):
        report.callsites_checked += 1
        # A positional or destructured spread that mentions the keyword
        # (case-insensitive) is accepted — the convention is that the
        # binding name is visible in the argument region.
        if keyword_lc in args.lower():
            continue
        snippet = f"{pin.function}({args.strip()[:90]}{'…' if len(args) > 90 else ''})"
        report.add(Finding(
            severity="HARD", rule=pin.label,
            path=rel, line=line_no, snippet=snippet,
        ))


def scan(
    python_roots: Iterable[Path] = PYTHON_ROOTS,
    ts_roots:     Iterable[Path] = TS_ROOTS,
    allowlist:    frozenset[str] = DEFAULT_ALLOWLIST,
) -> Report:
    report = Report()
    py_pins = tuple(p for p in PINS if p.function == "cert_payload_digest")
    ts_pins = tuple(p for p in PINS if p.function in (
        "certPayloadDigest", "baselineDataPda",
    ))
    seen: set[Path] = set()
    for path in _iter_files(python_roots, (".py",)):
        if path not in seen:
            seen.add(path)
            report.files_scanned += 1
        for pin in py_pins:
            _scan_py_file(path, pin, report, allowlist)
    for path in _iter_files(ts_roots, (".ts",)):
        if path not in seen:
            seen.add(path)
            report.files_scanned += 1
        for pin in ts_pins:
            _scan_ts_file(path, pin, report, allowlist)
    return report


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AW-03 baseline-DA pin sweep.")
    p.add_argument(
        "--json", type=Path, default=None,
        help="Write the JSON report to this path (default: stdout).",
    )
    p.add_argument(
        "--python-roots", nargs="*", type=Path, default=None,
        help="Override python scan roots (for tests).",
    )
    p.add_argument(
        "--ts-roots", nargs="*", type=Path, default=None,
        help="Override TS scan roots (for tests).",
    )
    args = p.parse_args(argv)

    report = scan(
        python_roots=tuple(args.python_roots) if args.python_roots else PYTHON_ROOTS,
        ts_roots=tuple(args.ts_roots) if args.ts_roots else TS_ROOTS,
    )

    blob = json.dumps(report.to_dict(), indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(blob + "\n")
    else:
        print(blob)

    if report.hard_count:
        print(
            f"\nFAIL: {report.hard_count} HARD AW-03 baseline-provenance pin findings",
            file=sys.stderr,
        )
        return 1
    print(
        f"\nOK: {report.callsites_checked} callsites checked, "
        f"{report.files_scanned} files scanned, 0 findings",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
