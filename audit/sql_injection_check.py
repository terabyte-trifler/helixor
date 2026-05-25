#!/usr/bin/env python3
"""
audit/sql_injection_check.py — VULN-20 hardening sweep.

AST-based scanner that REJECTS any `cursor.execute(...)` / `conn.execute(...)`
call whose SQL argument is built from dynamic string operations (f-string,
%-format, .format(), or `+` concatenation). The Helixor data path uses
psycopg 3, which accepts `%s` placeholders + a params sequence — that is
the only safe shape. Any other shape is a SQLi surface and must be
removed before mainnet.

WHAT IT FLAGS
-------------
The scanner walks every `.py` file under three roots:

    helixor-oracle/db/         the canonical TimescaleDB repository
    helixor-oracle/baseline/   the baseline + scoring read path
    helixor-api/api/           the FastAPI read API
    helixor-indexer/           the live ingest pipeline

For each call whose attribute chain matches `<expr>.execute`, the FIRST
positional argument MUST be one of:

  * `ast.Constant` (str)              — a literal SQL string
  * `ast.Name`                        — a module-level SQL constant
  * `ast.Attribute`                   — e.g. `_FETCH_WINDOW_SQL` namespaced

UNSAFE shapes (always HARD findings):

  * `ast.JoinedStr` (f-string)        — interpolates raw values
  * `ast.BinOp` with `Add`/`Mod`      — string concat / printf-style
  * `ast.Call` whose `.func.attr` is `format` — `"... {} ...".format(x)`

WHY THE WHITELIST IS THIS NARROW
--------------------------------
A parameter-shaped query (`%s` + `params=[...]`) is what the audit's
mitigation list demands. Anything that even LOOKS like it might splice
strings is a refactor surface the auditor wants forbidden — not a thing
to grep for once and forget about. The scanner runs in CI so any future
PR that re-introduces f-string SQL is rejected at submission time, not
post-incident.

EXIT CODES
----------
  0  no HARD findings
  1  >=1 HARD finding (CI must fail)

USAGE
-----
    python3 audit/sql_injection_check.py
    python3 audit/sql_injection_check.py --json audit/reports/sql_injection.json
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path


# =============================================================================
# Scan roots
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_SCAN_ROOTS = (
    REPO_ROOT / "helixor-oracle" / "db",
    REPO_ROOT / "helixor-oracle" / "baseline",
    REPO_ROOT / "helixor-api"    / "api",
    REPO_ROOT / "helixor-indexer",
)

# Test code is allowed to construct synthetic SQL violations to exercise
# the scanner itself; skip any path that contains a `tests/` segment.
EXCLUDED_SEGMENTS = ("tests", "__pycache__", ".venv", "venv", "node_modules")


# =============================================================================
# Finding model
# =============================================================================

@dataclass
class Finding:
    severity: str       # "HARD"
    kind:     str       # f-string | concat | percent-format | dot-format | call-expr
    file:     str
    line:     int
    col:      int
    snippet:  str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int      = 0

    @property
    def hard(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HARD"]

    def to_json(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "hard_count":    len(self.hard),
            "findings": [f.__dict__ for f in self.findings],
        }


# =============================================================================
# AST visitor
# =============================================================================

class _ExecuteVisitor(ast.NodeVisitor):
    """Find `<x>.execute(<sql>, ...)` calls and classify the SQL arg."""

    def __init__(self, file: Path, source: str) -> None:
        self._file   = file
        self._source = source.splitlines()
        self.findings: list[Finding] = []

    # The relevant method names we care about. `executemany` is the
    # psycopg variant for batched inserts; same SQL contract.
    _EXECUTE_NAMES = frozenset({"execute", "executemany"})

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        if not isinstance(node.func, ast.Attribute):
            return
        if node.func.attr not in self._EXECUTE_NAMES:
            return
        if not node.args:
            return
        sql_arg = node.args[0]
        self._classify(sql_arg, node)

    def _classify(self, sql_arg: ast.AST, call: ast.Call) -> None:
        # SAFE — a literal string.
        if isinstance(sql_arg, ast.Constant) and isinstance(sql_arg.value, str):
            return
        # SAFE — a module-level Name (`_FETCH_WINDOW_SQL`) or attribute
        # (`SQL.fetch_window`). These point at constants by convention.
        if isinstance(sql_arg, (ast.Name, ast.Attribute)):
            return

        kind: str | None = None

        # UNSAFE — f-string.
        if isinstance(sql_arg, ast.JoinedStr):
            kind = "f-string"

        # UNSAFE — string concat (`"... " + agent_wallet + " ..."`) or
        # printf-style (`"... %s ..." % agent_wallet`).
        elif isinstance(sql_arg, ast.BinOp):
            if isinstance(sql_arg.op, ast.Add):
                kind = "concat"
            elif isinstance(sql_arg.op, ast.Mod):
                kind = "percent-format"

        # UNSAFE — `"... {} ...".format(x)`.
        elif (
            isinstance(sql_arg, ast.Call)
            and isinstance(sql_arg.func, ast.Attribute)
            and sql_arg.func.attr == "format"
        ):
            kind = "dot-format"

        # UNSAFE — any other call/expression. Could be a helper that
        # builds SQL dynamically. Force the developer to either add a
        # safe shape or refactor.
        elif isinstance(sql_arg, ast.Call):
            kind = "call-expr"

        if kind is None:
            # Other expression types (Subscript, IfExp, ...) — flag to
            # force a human decision.
            kind = f"unknown-{type(sql_arg).__name__}"

        line = call.lineno
        col  = call.col_offset
        snippet = self._source[line - 1] if 0 < line <= len(self._source) else ""
        self.findings.append(Finding(
            severity="HARD",
            kind=kind,
            file=_display_path(self._file),
            line=line,
            col=col,
            snippet=snippet.strip(),
        ))


def _is_excluded(path: Path) -> bool:
    return any(seg in EXCLUDED_SEGMENTS for seg in path.parts)


def _display_path(p: Path) -> str:
    """Repo-relative when possible, absolute when not — keeps test
    fixtures (which live outside REPO_ROOT) reportable."""
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def scan_path(root: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    files = 0
    if not root.exists():
        return findings, files
    for py in root.rglob("*.py"):
        if _is_excluded(py.relative_to(root)):
            continue
        files += 1
        try:
            source = py.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            tree = ast.parse(source, filename=str(py))
        except SyntaxError as e:
            findings.append(Finding(
                severity="HARD",
                kind="syntax-error",
                file=_display_path(py),
                line=e.lineno or 0,
                col=e.offset or 0,
                snippet=(e.text or "").strip(),
            ))
            continue
        v = _ExecuteVisitor(py, source)
        v.visit(tree)
        findings.extend(v.findings)
    return findings, files


# =============================================================================
# CLI
# =============================================================================

def _format_findings(findings: list[Finding]) -> str:
    lines = []
    for f in findings:
        lines.append(
            f"  {f.severity:4s} {f.kind:18s} {f.file}:{f.line}:{f.col}"
        )
        if f.snippet:
            lines.append(f"       └─ {f.snippet}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="VULN-20 SQL-injection AST sweep over the Helixor data path",
    )
    parser.add_argument(
        "--json", dest="json_out", default=None,
        help="write the report as JSON to this path",
    )
    parser.add_argument(
        "--root", dest="roots", action="append", default=None,
        help="override scan roots (can be supplied multiple times)",
    )
    args = parser.parse_args(argv)

    roots = (
        [Path(r) for r in args.roots] if args.roots
        else list(DEFAULT_SCAN_ROOTS)
    )

    report = Report()
    for root in roots:
        findings, files = scan_path(root)
        report.findings.extend(findings)
        report.files_scanned += files

    print(f"sql_injection_check: scanned {report.files_scanned} .py files "
          f"across {len(roots)} roots")
    if report.findings:
        print("findings:")
        print(_format_findings(report.findings))
    else:
        print("✅ no unsafe .execute(...) shapes found")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_json(), indent=2))
        print(f"report written to {out}")

    return 1 if report.hard else 0


if __name__ == "__main__":
    sys.exit(main())
