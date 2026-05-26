"""
audit/test_input_provenance_check.py — self-test for the AW-01 audit sweep.

Pins the audit scanner's CONTRACT — the gate exists to catch regressions, so
we test the gate itself the way we'd test any other detector: by feeding it
both fixtures it MUST flag and fixtures it MUST NOT flag.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# audit/ is not a package — make the sibling scanner importable.
_AUDIT_DIR = Path(__file__).resolve().parent
if str(_AUDIT_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_DIR))

from input_provenance_check import scan  # type: ignore  # noqa: E402


# =============================================================================
# Fixture builders
# =============================================================================

def _write(tmp: Path, rel: str, contents: str) -> Path:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(contents)
    return p


# =============================================================================
# Python: cert_payload_digest
# =============================================================================

class TestPythonCertPayloadDigestPin:

    def test_positional_8th_arg_passes(self, tmp_path):
        _write(tmp_path, "src/ok.py", """
from oracle.cluster.cert_signing import cert_payload_digest

INPUT_COMMITMENT = b"\\x77" * 32
BASELINE = b"\\x00" * 32

cert_payload_digest(b"agent"*4, 1, 851, 2, 0, BASELINE, True, INPUT_COMMITMENT)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=(), rust_roots=())
        assert r.hard_count == 0

    def test_kwarg_passes(self, tmp_path):
        _write(tmp_path, "src/ok_kw.py", """
from oracle.cluster.cert_signing import cert_payload_digest

cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    input_commitment=b"\\x77"*32,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=(), rust_roots=())
        assert r.hard_count == 0

    def test_missing_eighth_arg_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad.py", """
from oracle.cluster.cert_signing import cert_payload_digest

# AW-01 regression: only 7 positional args, no commitment kwarg.
cert_payload_digest(b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=(), rust_roots=())
        assert r.hard_count == 1
        assert "cert_payload_digest" in r.findings[0].rule

    def test_star_args_accepted_conservatively(self, tmp_path):
        # *args expansion is opaque; trust it so we do not false-positive
        # on legitimate wrapper helpers.
        _write(tmp_path, "src/star.py", """
from oracle.cluster.cert_signing import cert_payload_digest

args = (b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True, b"\\x77"*32)
cert_payload_digest(*args)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=(), rust_roots=())
        assert r.hard_count == 0


# =============================================================================
# TypeScript: issueCertificate / submitScore
# =============================================================================

class TestTsAnchorMethodPins:

    def test_submit_score_with_inputCommitment_passes(self, tmp_path):
        _write(tmp_path, "tests/ok.ts", """
await oracleProgram.methods.submitScore(
  new BN(1), 916, 0, 0, false,
  [...inputCommitment],
).rpc();
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,), rust_roots=())
        assert r.hard_count == 0

    def test_submit_score_without_inputCommitment_is_flagged(self, tmp_path):
        _write(tmp_path, "tests/bad.ts", """
await oracleProgram.methods.submitScore(new BN(1), 916, 0, 0, false).rpc();
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,), rust_roots=())
        assert r.hard_count == 1
        assert "submitScore" in r.findings[0].rule

    def test_issueCertificate_with_inputCommitment_passes(self, tmp_path):
        _write(tmp_path, "tests/ok.ts", """
await certProgram.methods.issueCertificate(
  new BN(1), 916, 0, 0, false, [...inputCommitment],
).rpc();
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,), rust_roots=())
        assert r.hard_count == 0

    def test_issueCertificate_without_inputCommitment_is_flagged(self, tmp_path):
        _write(tmp_path, "tests/bad.ts", """
await certProgram.methods.issueCertificate(new BN(1), 916, 0, 0, false).rpc();
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,), rust_roots=())
        assert r.hard_count == 1


# =============================================================================
# Rust: cpi_issue_certificate
# =============================================================================

class TestRustCpiPin:

    def test_cpi_with_input_commitment_passes(self, tmp_path):
        _write(tmp_path, "programs/x/src/lib.rs", """
cpi_issue_certificate(
    cpi_ctx, epoch, score, alert_tier, flags, immediate_red,
    input_commitment,
)?;
""")
        r = scan(python_roots=(), ts_roots=(), rust_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_cpi_without_input_commitment_is_flagged(self, tmp_path):
        _write(tmp_path, "programs/x/src/lib.rs", """
cpi_issue_certificate(
    cpi_ctx, epoch, score, alert_tier, flags, immediate_red,
)?;
""")
        r = scan(python_roots=(), ts_roots=(), rust_roots=(tmp_path,))
        assert r.hard_count == 1


# =============================================================================
# String / comment-only mentions must NOT trip the scanner
# =============================================================================

class TestNoFalsePositives:

    def test_function_name_in_docstring_is_ignored(self, tmp_path):
        _write(tmp_path, "src/doc.py", '''
"""
This module talks about cert_payload_digest(a, b, c) in its docstring,
but does not call it.
"""
x = 1
''')
        r = scan(python_roots=(tmp_path,), ts_roots=(), rust_roots=())
        assert r.hard_count == 0

    def test_function_name_in_ts_line_comment_is_ignored(self, tmp_path):
        _write(tmp_path, "src/comment.ts", """
// Sample: issueCertificate(arg1) — no real call here.
const x = 1;
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,), rust_roots=())
        assert r.hard_count == 0


# =============================================================================
# Live repo: must be clean
# =============================================================================

class TestLiveRepo:

    def test_repo_sweep_is_clean(self):
        """The whole repo must pass the AW-01 pin sweep. If this fails, the
        AW-01 fix has regressed somewhere."""
        report = scan()
        assert report.hard_count == 0, (
            f"AW-01 pin regressions: "
            + "\n".join(
                f"{f.path}:{f.line} {f.rule}" for f in report.findings
            )
        )
