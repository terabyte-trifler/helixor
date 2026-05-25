"""
audit/test_vuln21_ed25519_strictness_check.py — pin tests for the
Ed25519 strictness sweep.

Two layers:

  1. Synthetic violation files exercise every shape the scanner must
     catch (batch-verify symbols in Python AND Rust, the non-strict
     dalek `.verify(` form, and a forbidden Python crypto import).
  2. The real codebase is scanned and asserted CLEAN — a regression
     that re-introduces any of the above shapes fails this test in
     CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# audit/ is not a package — make the sibling scanner importable.
_AUDIT_DIR = Path(__file__).resolve().parent
if str(_AUDIT_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_DIR))

from ed25519_strictness_check import (  # type: ignore  # noqa: E402
    BATCH_VERIFY_NAMES, FORBIDDEN_PY_IMPORTS, ROOTS as REAL_ROOTS, scan,
)


REPO_ROOT = _AUDIT_DIR.parent


# =============================================================================
# Synthetic-violation tests
# =============================================================================

class TestBatchVerifySurface:

    @pytest.mark.parametrize("name", BATCH_VERIFY_NAMES)
    def test_python_batch_verify_call_is_flagged(self, tmp_path, name):
        f = tmp_path / "evil.py"
        f.write_text(
            "from somewhere import verifier\n"
            f"verifier.{name}([sig1, sig2, sig3])\n"
        )
        report = scan([tmp_path])
        assert any(
            x.rule == "batch-verify-forbidden" and x.path.endswith("evil.py")
            for x in report.findings
        ), f"scanner did not flag {name!r} in a python file"

    @pytest.mark.parametrize("name", BATCH_VERIFY_NAMES)
    def test_rust_batch_verify_call_is_flagged(self, tmp_path, name):
        f = tmp_path / "evil.rs"
        f.write_text(
            "fn main() {\n"
            f"    let _ = verifier::{name}(&sigs);\n"
            "}\n"
        )
        report = scan([tmp_path])
        assert any(
            x.rule == "batch-verify-forbidden" and x.path.endswith("evil.rs")
            for x in report.findings
        ), f"scanner did not flag {name!r} in a rust file"


class TestRustNonStrictVerify:

    def test_dalek_nonstrict_verify_is_flagged(self, tmp_path):
        f = tmp_path / "nonstrict.rs"
        f.write_text(
            "use ed25519_dalek::Signature;\n"
            "fn check(pk: PublicKey, sig: Signature, msg: &[u8]) -> bool {\n"
            "    ed25519_dalek::PublicKey::verify(&pk, msg, &sig).is_ok()\n"
            "}\n"
        )
        report = scan([tmp_path])
        assert any(
            x.rule == "rust-nonstrict-verify-forbidden"
            for x in report.findings
        ), "scanner did not flag a non-strict ed25519_dalek::*.verify( call"

    def test_dalek_verify_strict_is_NOT_flagged(self, tmp_path):
        f = tmp_path / "strict.rs"
        f.write_text(
            "use ed25519_dalek::Signature;\n"
            "fn check(pk: PublicKey, sig: Signature, msg: &[u8]) -> bool {\n"
            "    ed25519_dalek::PublicKey::verify_strict(&pk, msg, &sig).is_ok()\n"
            "}\n"
        )
        report = scan([tmp_path])
        # `verify_strict` does NOT match the pattern — but it also doesn't
        # match any batch-verify name. So no findings.
        rust_findings = [
            x for x in report.findings
            if x.rule == "rust-nonstrict-verify-forbidden"
        ]
        assert rust_findings == [], (
            f"verify_strict was flagged incorrectly: {rust_findings}"
        )


class TestForbiddenPyImports:

    @pytest.mark.parametrize("mod", FORBIDDEN_PY_IMPORTS)
    def test_forbidden_import_is_flagged(self, tmp_path, mod):
        f = tmp_path / "bad_import.py"
        f.write_text(f"import {mod}\n")
        report = scan([tmp_path])
        assert any(
            x.rule == "py-forbidden-ed25519-lib"
            for x in report.findings
        ), f"scanner did not flag forbidden import {mod!r}"

    def test_cryptography_import_is_NOT_flagged(self, tmp_path):
        f = tmp_path / "ok_import.py"
        f.write_text(
            "from cryptography.hazmat.primitives.asymmetric.ed25519 "
            "import Ed25519PublicKey\n"
        )
        report = scan([tmp_path])
        assert report.findings == [], (
            f"`cryptography` import was flagged: {report.findings}"
        )


# =============================================================================
# Real-codebase clean
# =============================================================================

class TestRealCodebaseClean:

    def test_repo_has_no_ed25519_strictness_findings(self):
        report = scan(REAL_ROOTS)
        assert report.findings == [], (
            "the repo grew an ed25519 strictness finding:\n"
            + "\n".join(
                f"  - {f.rule} @ {f.path}:{f.line} -- {f.snippet}"
                for f in report.findings
            )
        )
        assert report.files_scanned > 0, (
            "scan found no files — roots may be misconfigured"
        )


# =============================================================================
# CLI sanity
# =============================================================================

class TestCli:

    def test_cli_emits_json_to_path(self, tmp_path):
        from ed25519_strictness_check import main  # type: ignore
        out = tmp_path / "report.json"
        rc = main([
            "--roots", str(tmp_path),
            "--json",  str(out),
        ])
        assert rc == 0
        assert out.exists()
        import json
        blob = json.loads(out.read_text())
        assert blob["findings_hard"] == 0
