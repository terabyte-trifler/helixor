"""
audit/test_vuln23_cert_consumption_check.py — pin tests for VULN-23.

Asserts the live codebase is clean AND exercises the CLI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


# audit/ is not a package — make the sibling scanner importable.
_AUDIT_DIR = Path(__file__).resolve().parent
if str(_AUDIT_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_DIR))

from cert_consumption_check import (  # type: ignore  # noqa: E402
    main, scan,
)


class TestRealCodebaseClean:

    def test_repo_has_no_cert_consumption_findings(self):
        report = scan()
        assert report.findings == [], (
            "the repo grew a VULN-23 cert-consumption finding:\n"
            + "\n".join(
                f"  - {f.rule} @ {f.path}: {f.detail}"
                for f in report.findings
            )
        )
        assert report.files_scanned > 0, (
            "scan found no files — targets may be misconfigured"
        )


class TestCli:

    def test_cli_emits_json_to_path(self, tmp_path):
        out = tmp_path / "report.json"
        rc = main(["--json", str(out)])
        assert rc == 0
        assert out.exists()
        blob = json.loads(out.read_text())
        assert blob["findings_hard"] == 0
        assert blob["files_scanned"] > 0
