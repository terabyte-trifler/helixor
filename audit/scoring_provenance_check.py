#!/usr/bin/env python3
"""
audit/scoring_provenance_check.py — AW-04 scoring-provenance pin sweep.

AW-04 (Scoring Engine is a Black Box to On-Chain Consumers) closed the gap
where the on-chain cert carried a score (u16) + flags (u32) but no
mechanism for a third party to verify the score was COMPUTED correctly —
the cluster signature only attested that some signed cluster emitted the
number, not that the number was a faithful reduction of behavioral inputs.

The architectural fix is three-pronged:

  * On chain: a per-(agent, epoch) `ScoreComponentsAccount` PDA stores
    the canonical-JSON payload of dimension breakdowns; `init` enforces
    `sha256(account.payload) == components_hash` at write time. The
    HealthCertificate gains `scoring_code_hash` (the deterministic
    bundle hash of the scoring kernel).
  * In the digest: `cert_payload_digest` folds 32 + 32 = 64 new bytes
    (`scoring_code_hash || score_components_hash`) into the signed
    bytes. The threshold signatures now attest to a SPECIFIC code
    version + SPECIFIC components blob.
  * In the SDK: `verifyScoreComputation` re-fetches the PDA, re-asserts
    the hash binding, parses the payload, and replays the score
    arithmetic. `verifyScoringCodeHash` checks the bundle hash against
    a caller-supplied expected value.

Every callsite of the affected signing/issuing surfaces MUST thread
BOTH AW-04 kwargs:

  Python: `cert_payload_digest(..., scoring_code_hash=..., score_components_hash=...)`
  TS:     `certPayloadDigest(..., scoringCodeHash, scoreComponentsHash, ...)`

The Python signature defaults both to 32 zero bytes for legacy compat,
so a regression that quietly drops the kwarg would not raise — it would
SILENTLY emit certs that bind to "no code" + "no components", defeating
AW-04 without any type error. The SDK PDA derivation also needs `epoch`
to address the right `ScoreComponentsAccount`.

REPORTING
---------
Emits a JSON report to `--json` (default stdout) and exits non-zero on
any HARD finding. Wired into `audit/run_all.sh` as section 1j, sitting
next to the AW-01/AW-03 sweeps.
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
# exercise the kwarg-defaults path; the audit's job is to enforce that
# production callers always thread the AW-04 hashes explicitly.
PYTHON_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "helixor-oracle" / "oracle",
)

TS_ROOTS: tuple[Path, ...] = (
    REPO_ROOT / "helixor-programs" / "tests",
    REPO_ROOT / "helixor-sdk" / "src",
    REPO_ROOT / "helixor-sdk" / "test",
)


# Allowlisted files: the scanner itself and its self-test. Both
# deliberately reference the function names without binding the AW-04
# kwargs — they are not production callers.
DEFAULT_ALLOWLIST: frozenset[str] = frozenset({
    "audit/scoring_provenance_check.py",
    "audit/test_scoring_provenance_check.py",
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
    # Python: the cluster signing surface. `cert_payload_digest` accepts
    # `scoring_code_hash` AND `score_components_hash` as keyword-only
    # arguments, each defaulting to 32 zero bytes for legacy compat. Every
    # production caller MUST pass both explicitly to bind the cert to a
    # specific code version AND a fetchable ScoreComponentsAccount PDA.
    # A regression that drops either argument would silently emit certs
    # that no consumer can replay against the on-chain payload.
    Pin(
        function="cert_payload_digest",
        keyword="scoring_code_hash",
        label="cert_payload_digest-missing-scoring_code_hash",
    ),
    Pin(
        function="cert_payload_digest",
        keyword="score_components_hash",
        label="cert_payload_digest-missing-score_components_hash",
    ),
    # TS: integration tests and SDK helpers that recompute the digest
    # locally. Anchor's typed-method generator does not enforce arg
    # presence at compile time, so a missing arg would not fail typecheck
    # — and the digest would drift from the on-chain value.
    Pin(
        function="certPayloadDigest",
        keyword="scoringCodeHash",
        label="certPayloadDigest-missing-scoringCodeHash",
    ),
    Pin(
        function="certPayloadDigest",
        keyword="scoreComponentsHash",
        label="certPayloadDigest-missing-scoreComponentsHash",
    ),
    # TS: the SDK PDA derivation for ScoreComponentsAccount. The PDA
    # seeds are ["score_components", agent_wallet, epoch_le] — every
    # caller must thread `epoch` (the AW-04 binding is per-epoch, since
    # one components blob is produced per scoring run). A regression
    # that hardcodes 0 would derive the wrong PDA on every fetch and
    # surface as `AccountNotFound` rather than the precise rejection.
    Pin(
        function="scoreComponentsPda",
        keyword="epoch",
        label="scoreComponentsPda-missing-epoch",
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


# `cert_payload_digest` accepts the AW-04 hashes as keyword-only args
# with 32-zero defaults. Production callers MUST pass them explicitly —
# the AST scanner accepts a kwarg match only (positional fallback is
# not possible since the args are keyword-only).
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
        "certPayloadDigest", "scoreComponentsPda",
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
    p = argparse.ArgumentParser(description="AW-04 scoring-provenance pin sweep.")
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
            f"\nFAIL: {report.hard_count} HARD AW-04 scoring-provenance pin findings",
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
