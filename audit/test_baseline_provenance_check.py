"""
audit/test_baseline_provenance_check.py — self-test for the AW-03 audit sweep.

Pins the audit scanner's contract: the gate exists to catch regressions that
quietly drop the AW-03 `baseline_commit_nonce` (Python) /
`baselineCommitNonce` (TS) / `commitNonce` (TS PDA) binding. We test the gate
the way we'd test any detector: with fixtures it MUST flag and fixtures it
MUST NOT flag.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# audit/ is not a package — make the sibling scanner importable.
_AUDIT_DIR = Path(__file__).resolve().parent
if str(_AUDIT_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_DIR))

from baseline_provenance_check import scan  # type: ignore  # noqa: E402


def _write(tmp: Path, rel: str, contents: str) -> Path:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(contents)
    return p


# =============================================================================
# Python: cert_payload_digest
# =============================================================================

class TestPythonCertPayloadDigestPin:

    def test_kwarg_baseline_commit_nonce_passes(self, tmp_path):
        _write(tmp_path, "src/ok.py", """
from oracle.cluster.cert_signing import cert_payload_digest

cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
    baseline_commit_nonce=7,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 0

    def test_missing_kwarg_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad.py", """
from oracle.cluster.cert_signing import cert_payload_digest

# AW-03 regression: nonce dropped — defaults silently to 0.
cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 1
        assert "baseline_commit_nonce" in r.findings[0].rule

    def test_starstar_kwargs_accepted_conservatively(self, tmp_path):
        # **kwargs expansion is opaque; trust it so we do not false-positive
        # on legitimate wrapper helpers.
        _write(tmp_path, "src/star.py", """
from oracle.cluster.cert_signing import cert_payload_digest

opts = {"baseline_commit_nonce": 3}
cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
    **opts,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 0


# =============================================================================
# TS: certPayloadDigest + baselineDataPda
# =============================================================================

class TestTsCertPayloadDigestPin:

    def test_keyword_in_args_passes(self, tmp_path):
        _write(tmp_path, "src/ok.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
  baselineCommitNonce,    // AW-03
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_keyword_in_comment_passes(self, tmp_path):
        # A literal `baselineCommitNonce` mention anywhere in the args
        # region — including comments — is a positive intent signal.
        _write(tmp_path, "src/ok_comment.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
  1n,                        // AW-03: baselineCommitNonce stamped on chain
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_missing_keyword_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 1
        assert "certPayloadDigest" in r.findings[0].rule


class TestTsBaselineDataPdaPin:

    def test_keyword_variant_passes(self, tmp_path):
        _write(tmp_path, "src/ok_pda.ts", """
const pda = baselineDataPda(healthOracle, agent, commitNonce);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_nonce_substring_variant_passes(self, tmp_path):
        # A locally-bound `nonce` variable is the most common form.
        _write(tmp_path, "src/ok_pda_nonce.ts", """
const pda = baselineDataPda(healthOracle, agent, nonce);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_no_nonce_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad_pda.ts", """
const pda = baselineDataPda(healthOracle, agent, 7);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 1
        assert "baselineDataPda" in r.findings[0].rule


# =============================================================================
# Allowlist + integration
# =============================================================================

class TestAllowlistAndShape:

    def test_findings_have_full_metadata(self, tmp_path):
        _write(tmp_path, "src/bad.ts", "certPayloadDigest(a, b, c);\n")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 1
        f = r.findings[0]
        assert f.severity == "HARD"
        assert f.path.endswith("bad.ts")
        assert f.line == 1
        assert "certPayloadDigest" in f.snippet
