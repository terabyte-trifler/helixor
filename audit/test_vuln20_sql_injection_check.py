"""
audit/test_vuln20_sql_injection_check.py — pin tests for the SQLi sweep.

Two layers:

  1. Synthetic violation files exercise every UNSAFE shape the scanner
     must catch (f-string, %-format, .format(), `+` concat, helper call).
  2. The real codebase is scanned and asserted CLEAN — a regression that
     re-introduces an unsafe shape fails this test in CI.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest


# The audit/ directory is not a package — add it to sys.path so the
# sibling module loads cleanly regardless of pytest's invocation cwd.
_AUDIT_DIR = Path(__file__).resolve().parent
if str(_AUDIT_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_DIR))

from sql_injection_check import (  # type: ignore  # noqa: E402
    DEFAULT_SCAN_ROOTS, Report, scan_path,
)


REPO_ROOT = _AUDIT_DIR.parent


# =============================================================================
# Helpers
# =============================================================================

def _scan_text(tmp_path: Path, source: str) -> Report:
    """Write `source` to a temp .py file and run the scanner on its dir."""
    target = tmp_path / "synthetic.py"
    target.write_text(textwrap.dedent(source))
    findings, files = scan_path(tmp_path)
    rep = Report()
    rep.findings.extend(findings)
    rep.files_scanned = files
    return rep


# =============================================================================
# SAFE shapes — the scanner must NOT flag these
# =============================================================================

class TestSafeShapes:

    def test_literal_string_is_safe(self, tmp_path):
        rep = _scan_text(tmp_path, '''
            class C:
                def go(self, conn):
                    conn.execute("SELECT 1", [])
        ''')
        assert rep.hard == []

    def test_module_level_constant_is_safe(self, tmp_path):
        rep = _scan_text(tmp_path, '''
            _SQL = "SELECT * FROM t WHERE a = %s"
            class C:
                def go(self, conn, x):
                    conn.execute(_SQL, [x])
        ''')
        assert rep.hard == []

    def test_attribute_constant_is_safe(self, tmp_path):
        rep = _scan_text(tmp_path, '''
            class SQL:
                FETCH = "SELECT * FROM t WHERE a = %s"
            class C:
                def go(self, conn, x):
                    conn.execute(SQL.FETCH, [x])
        ''')
        assert rep.hard == []


# =============================================================================
# UNSAFE shapes — the scanner MUST flag these
# =============================================================================

class TestUnsafeShapes:

    def test_f_string_is_flagged(self, tmp_path):
        rep = _scan_text(tmp_path, '''
            class C:
                def go(self, conn, agent):
                    conn.execute(f"SELECT * FROM t WHERE a = '{agent}'")
        ''')
        kinds = {f.kind for f in rep.hard}
        assert "f-string" in kinds

    def test_percent_format_is_flagged(self, tmp_path):
        rep = _scan_text(tmp_path, '''
            class C:
                def go(self, conn, agent):
                    conn.execute("SELECT * FROM t WHERE a = '%s'" % agent)
        ''')
        kinds = {f.kind for f in rep.hard}
        assert "percent-format" in kinds

    def test_concat_is_flagged(self, tmp_path):
        rep = _scan_text(tmp_path, '''
            class C:
                def go(self, conn, agent):
                    conn.execute("SELECT * FROM t WHERE a = '" + agent + "'")
        ''')
        kinds = {f.kind for f in rep.hard}
        assert "concat" in kinds

    def test_dot_format_is_flagged(self, tmp_path):
        rep = _scan_text(tmp_path, '''
            class C:
                def go(self, conn, agent):
                    conn.execute("SELECT * FROM t WHERE a = '{}'".format(agent))
        ''')
        kinds = {f.kind for f in rep.hard}
        assert "dot-format" in kinds

    def test_helper_call_is_flagged(self, tmp_path):
        """A helper that builds SQL at call time. Force a refactor."""
        rep = _scan_text(tmp_path, '''
            def build_sql(agent):
                return "SELECT * FROM t WHERE a = '" + agent + "'"
            class C:
                def go(self, conn, agent):
                    conn.execute(build_sql(agent), [])
        ''')
        kinds = {f.kind for f in rep.hard}
        assert "call-expr" in kinds

    def test_executemany_is_also_checked(self, tmp_path):
        """psycopg's executemany must follow the same rule."""
        rep = _scan_text(tmp_path, '''
            class C:
                def go(self, conn, agent):
                    conn.executemany(f"INSERT INTO t VALUES ('{agent}')", [])
        ''')
        kinds = {f.kind for f in rep.hard}
        assert "f-string" in kinds


# =============================================================================
# Real codebase — pin test
# =============================================================================

class TestRealCodebase:
    """
    The currently-shipped Helixor codebase MUST scan clean. A future PR
    that introduces an f-string SQL call will fail this test in CI long
    before review.
    """

    def test_all_default_roots_are_clean(self):
        all_findings = []
        for root in DEFAULT_SCAN_ROOTS:
            findings, _ = scan_path(root)
            all_findings.extend(findings)
        hard = [f for f in all_findings if f.severity == "HARD"]
        assert hard == [], (
            "VULN-20 regression — the following unsafe execute() shapes "
            "appeared in the codebase:\n"
            + "\n".join(
                f"  {f.kind:18s} {f.file}:{f.line}  {f.snippet}" for f in hard
            )
        )


# =============================================================================
# CLI surface
# =============================================================================

def test_cli_runs_clean_on_repo(tmp_path):
    """Invoke the script's main() like CI would. Exit 0 means no HARD."""
    from sql_injection_check import main  # type: ignore
    out_path = tmp_path / "sql.json"
    rc = main(["--json", str(out_path)])
    assert rc == 0
    assert out_path.exists()
    data = out_path.read_text()
    assert '"hard_count": 0' in data
