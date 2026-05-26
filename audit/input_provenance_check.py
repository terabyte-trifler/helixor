#!/usr/bin/env python3
"""
audit/input_provenance_check.py — AW-01 pin-discipline sweep.

AW-01 (Trust Transitivity) closed the cluster-input-integrity gap by
extending three callsites with an `input_commitment` argument:

  * Python  oracle.signing.cert_payload_digest(...)            (signing surface)
  * Anchor  certificate_issuer::issue_certificate(...)          (on-chain ix)
  * Anchor  health_oracle::submit_score(...)                    (CPI entry)

Every CALL of those functions MUST pass the commitment. A regression that
quietly drops the argument would let an oracle node, an indexer-poisoning
attacker, or a refactor of the test suite slip past the AW-01 fix —
producing certs whose on-chain signature attests to a derived score but
NOT to the inputs the cluster scored over. That is exactly the gap AW-01
was meant to close.

This sweep enumerates every callsite of those functions across the repo,
extracts each call's argument region with balanced-paren matching, and
fails the gate if any callsite does not contain the commitment keyword.

REPORTING
---------
Emits a JSON report to `--json` (default stdout) and exits non-zero on
any HARD finding. Wired into `audit/run_all.sh` alongside the other
audit-mandated sweeps.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Scan roots — where Helixor calls live
# =============================================================================

PYTHON_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "helixor-oracle" / "oracle",
    REPO_ROOT / "helixor-oracle" / "tests",
    REPO_ROOT / "helixor-api",
    REPO_ROOT / "helixor-indexer",
)

TS_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "helixor-programs" / "tests",
    REPO_ROOT / "helixor-sdk" / "src",
    REPO_ROOT / "helixor-sdk" / "test",
)

RUST_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "helixor-programs" / "programs",
)


# Allowlisted files: documentation, the scanner itself, the scanner's tests,
# or stubs that are KNOWN to omit the argument by design (e.g. a Python
# helper that synthesises raw bytes for testing the missing-arg path).
DEFAULT_ALLOWLIST: frozenset[str] = frozenset({
    "audit/input_provenance_check.py",
    "audit/test_input_provenance_check.py",
})


# =============================================================================
# Pin definitions — the (function_name, commitment_keyword, file_glob) trio
# =============================================================================

@dataclass(frozen=True)
class Pin:
    """One pin: every call of `function` must mention `keyword` in its args."""
    function: str
    keyword:  str          # the token that must appear inside the (...) args
    label:    str          # human-readable rule name

PINS: tuple[Pin, ...] = (
    # Python: the cluster signing surface. `cert_payload_digest`'s signature
    # has `input_commitment` AND `slot_anchor` as REQUIRED positionals, so a
    # missing-arg call would TypeError at runtime — but the scanner enforces
    # the convention in tests and helpers so a future
    # kwarg-default-back-to-optional refactor cannot silently slip past us.
    Pin(
        function="cert_payload_digest",
        keyword="input_commitment",
        label="cert_payload_digest-missing-input_commitment",
    ),
    Pin(
        function="cert_payload_digest",
        keyword="slot_anchor",
        label="cert_payload_digest-missing-slot_anchor",
    ),
    # Python: the per-node commitment primitive. Same convention guard for
    # the AW-01-EXT slot_anchor — if a test fixture or runner ever forgets
    # to bind the anchor, the input-commitment loses its third source of
    # truth and the cluster-majority check reverts to AW-01's pre-EXT
    # threat envelope.
    Pin(
        function="compute_input_commitment",
        keyword="slot_anchor",
        label="compute_input_commitment-missing-slot_anchor",
    ),
    # Rust: the CPI from health-oracle into certificate-issuer. A missing
    # arg is a signature-level TypeError on rustc, but again — guard the
    # convention. Each AW-01 / AW-01-EXT arg is its own pin so a regression
    # that drops one specific arg is named in the finding.
    Pin(
        function="cpi_issue_certificate",
        keyword="input_commitment",
        label="cpi_issue_certificate-missing-input_commitment",
    ),
    Pin(
        function="cpi_issue_certificate",
        keyword="slot_anchor_slot",
        label="cpi_issue_certificate-missing-slot_anchor_slot",
    ),
    Pin(
        function="cpi_issue_certificate",
        keyword="slot_anchor_hash",
        label="cpi_issue_certificate-missing-slot_anchor_hash",
    ),
    # TS: the Anchor SDK call paths from the integration tests + scripts.
    # Anchor's typed-method generator does NOT enforce arg presence at
    # compile time (it stringly-types args), so a missing arg there would
    # NOT fail typecheck — exactly the kind of regression the audit catches.
    Pin(
        function="issueCertificate",
        keyword="inputCommitment",
        label="issueCertificate-missing-inputCommitment",
    ),
    Pin(
        function="issueCertificate",
        keyword="slotAnchor",
        label="issueCertificate-missing-slotAnchor",
    ),
    Pin(
        function="submitScore",
        keyword="inputCommitment",
        label="submitScore-missing-inputCommitment",
    ),
    Pin(
        function="submitScore",
        keyword="slotAnchor",
        label="submitScore-missing-slotAnchor",
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
# Balanced-paren extractor — finds every call of `name(` and returns the
# argument region between its matching parens. Skips occurrences inside
# string literals and line comments (//, #).
# =============================================================================

_STRING_CHARS = {'"', "'", "`"}


def _is_word_boundary(text: str, idx: int) -> bool:
    if idx == 0:
        return True
    prev = text[idx - 1]
    return not (prev.isalnum() or prev == "_")


def _skip_string_or_comment(
    text: str, i: int, suffix: str,
) -> int | None:
    """If position `i` opens a string or comment, advance past it and return
    the new position; otherwise return None."""
    ch = text[i]
    if ch == "#" and suffix == ".py":
        # python line comment — skip to newline
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
        # Triple-quoted python strings
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


def _find_calls(text: str, name: str, suffix: str) -> Iterable[tuple[int, str]]:
    """Yield (line_number_1based, argument_region) for every call to `name(`."""
    name_len = len(name)
    i = 0
    line_no = 1
    # Pre-walk to compute line offsets.
    line_starts = [0]
    for idx, c in enumerate(text):
        if c == "\n":
            line_starts.append(idx + 1)

    def _line_of(pos: int) -> int:
        # binary search in line_starts
        lo, hi = 0, len(line_starts) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if line_starts[mid] <= pos:
                lo = mid + 1
            else:
                hi = mid - 1
        return hi + 1  # 1-based

    while i < len(text):
        # skip strings/comments cheaply
        skipped = _skip_string_or_comment(text, i, suffix)
        if skipped is not None:
            i = skipped
            continue

        # match `name(` with a word boundary on the LEFT
        if (
            text.startswith(name, i)
            and i + name_len < len(text)
            and _is_word_boundary(text, i)
            # require an opening paren after possible whitespace
            and _open_paren_after(text, i + name_len) is not None
        ):
            open_idx = _open_paren_after(text, i + name_len)
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


def _open_paren_after(text: str, i: int) -> int | None:
    """Return the index of the next `(` skipping whitespace; else None."""
    while i < len(text) and text[i] in " \t\n\r":
        i += 1
    if i < len(text) and text[i] == "(":
        return i
    return None


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


# cert_payload_digest's true signature has 9 required positional args
# (AW-01-EXT added `slot_anchor` as #9). A call that supplies fewer than
# 9 positionals AND no kwarg for the pinned keyword has silently dropped
# the binding. compute_input_commitment has 7 required positionals (the
# 7th is `slot_anchor`).
PY_REQUIRED_POSITIONALS = {
    "cert_payload_digest":      9,
    "compute_input_commitment": 7,
}


def _scan_py_file(
    path:      Path,
    pin:       Pin,
    report:    Report,
    allowlist: frozenset[str],
) -> None:
    """AST-based scanner for Python — counts positional args explicitly so
    callsites passing the commitment as a positional (e.g. test constants
    like `INPUT_COMMITMENT` or `b"\\x77"*32`) are accepted."""
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
    required = PY_REQUIRED_POSITIONALS.get(pin.function, 0)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # match `name(...)` or `module.name(...)`
        called_name = (
            func.id if isinstance(func, ast.Name)
            else func.attr if isinstance(func, ast.Attribute)
            else None
        )
        if called_name != pin.function:
            continue
        report.callsites_checked += 1

        pos_count = len(node.args)
        # `*args` star expansion counts as supplying unknown positionals;
        # be conservative and trust it.
        has_starargs = any(isinstance(a, ast.Starred) for a in node.args)
        if has_starargs or pos_count >= required:
            continue
        has_kw = any(
            kw.arg == pin.keyword for kw in node.keywords if kw.arg is not None
        )
        if has_kw:
            continue
        snippet = (
            f"{pin.function}(...positional={pos_count}, no '{pin.keyword}' kwarg)"
        )
        report.add(Finding(
            severity="HARD", rule=pin.label,
            path=rel, line=node.lineno, snippet=snippet,
        ))


def _scan_file_for_pin(
    path:      Path,
    pin:       Pin,
    suffix:    str,
    report:    Report,
    allowlist: frozenset[str],
) -> None:
    if suffix == ".py":
        _scan_py_file(path, pin, report, allowlist)
        return
    rel = _display_path(path)
    if rel in allowlist:
        return
    text = path.read_text(errors="ignore")
    if pin.function not in text:
        return
    # Case-insensitive match: TS / Rust callers may pass either an
    # `inputCommitment` keyword, an `INPUT_COMMITMENT` test constant, or
    # a `[...inputCommitment]` spread. Any of those proves the caller
    # knows to bind the commitment.
    keyword_lc = pin.keyword.lower()
    for line_no, args in _find_calls(text, pin.function, suffix):
        report.callsites_checked += 1
        if keyword_lc in args.lower():
            continue
        snippet = f"{pin.function}({args.strip()[:90]}{'…' if len(args) > 90 else ''})"
        report.add(Finding(
            severity="HARD",
            rule=pin.label,
            path=rel, line=line_no,
            snippet=snippet,
        ))


def scan(
    python_roots: Iterable[Path] = PYTHON_ROOTS,
    ts_roots:     Iterable[Path] = TS_ROOTS,
    rust_roots:   Iterable[Path] = RUST_ROOTS,
    allowlist:    frozenset[str] = DEFAULT_ALLOWLIST,
) -> Report:
    report = Report()
    # (suffixes, roots, pins-for-language)
    plan: tuple[tuple[tuple[str, ...], Iterable[Path], tuple[Pin, ...]], ...] = (
        ((".py",), python_roots, tuple(
            p for p in PINS
            if p.function in ("cert_payload_digest", "compute_input_commitment")
        )),
        ((".ts",), ts_roots, tuple(
            p for p in PINS
            if p.function in ("issueCertificate", "submitScore")
        )),
        ((".rs",), rust_roots, tuple(
            p for p in PINS if p.function == "cpi_issue_certificate"
        )),
    )
    seen: set[Path] = set()
    for suffixes, roots, pins in plan:
        for path in _iter_files(roots, suffixes):
            if path not in seen:
                seen.add(path)
                report.files_scanned += 1
            for pin in pins:
                _scan_file_for_pin(path, pin, path.suffix, report, allowlist)
    return report


# =============================================================================
# CLI
# =============================================================================

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AW-01 input-provenance pin sweep.")
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
    p.add_argument(
        "--rust-roots", nargs="*", type=Path, default=None,
        help="Override Rust scan roots (for tests).",
    )
    args = p.parse_args(argv)

    report = scan(
        python_roots=tuple(args.python_roots) if args.python_roots else PYTHON_ROOTS,
        ts_roots=tuple(args.ts_roots) if args.ts_roots else TS_ROOTS,
        rust_roots=tuple(args.rust_roots) if args.rust_roots else RUST_ROOTS,
    )

    blob = json.dumps(report.to_dict(), indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(blob + "\n")
    else:
        print(blob)

    if report.hard_count:
        print(
            f"\n❌ {report.hard_count} HARD AW-01 input-provenance pin findings"
            f" across {report.callsites_checked} callsites",
            file=sys.stderr,
        )
        return 1
    print(
        f"✅ AW-01 input-provenance sweep clean "
        f"({report.files_scanned} files scanned, "
        f"{report.callsites_checked} callsites)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
