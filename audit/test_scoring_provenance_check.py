"""
audit/test_scoring_provenance_check.py — self-test for the AW-04 audit sweep.

Pins the AW-04 audit scanner's contract: the gate exists to catch
regressions that quietly drop either of the AW-04 hashes
(`scoring_code_hash` / `score_components_hash`) from production callers
of `cert_payload_digest` (Python) or `certPayloadDigest` (TS), or that
drop `epoch` from `scoreComponentsPda` (TS).

Pattern matches the AW-01 / AW-03 self-tests next door: feed the
scanner synthetic source trees, assert findings on the bad fixtures and
zero findings on the good ones.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# audit/ is not a package — make the sibling scanner importable.
_AUDIT_DIR = Path(__file__).resolve().parent
if str(_AUDIT_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_DIR))

from scoring_provenance_check import scan  # type: ignore  # noqa: E402


def _write(tmp: Path, rel: str, contents: str) -> Path:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(contents)
    return p


# =============================================================================
# Python: cert_payload_digest
# =============================================================================

class TestPythonCertPayloadDigestPin:

    def test_both_kwargs_present_passes(self, tmp_path):
        _write(tmp_path, "src/ok.py", """
from oracle.cluster.cert_signing import cert_payload_digest

cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
    baseline_commit_nonce=7,
    scoring_code_hash=b"\\xab"*32,
    score_components_hash=b"\\xcd"*32,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 0

    def test_missing_scoring_code_hash_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad_code.py", """
from oracle.cluster.cert_signing import cert_payload_digest

# AW-04 regression: scoring_code_hash dropped — defaults silently to 32 zero bytes.
cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
    baseline_commit_nonce=7,
    score_components_hash=b"\\xcd"*32,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 1
        assert r.findings[0].rule == "cert_payload_digest-missing-scoring_code_hash"

    def test_missing_score_components_hash_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad_components.py", """
from oracle.cluster.cert_signing import cert_payload_digest

# AW-04 regression: score_components_hash dropped — defaults silently to 32 zero bytes.
cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
    baseline_commit_nonce=7,
    scoring_code_hash=b"\\xab"*32,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 1
        assert r.findings[0].rule == "cert_payload_digest-missing-score_components_hash"

    def test_both_missing_flags_both(self, tmp_path):
        _write(tmp_path, "src/bad_both.py", """
from oracle.cluster.cert_signing import cert_payload_digest

cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
    baseline_commit_nonce=7,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 2
        rules = {f.rule for f in r.findings}
        assert rules == {
            "cert_payload_digest-missing-scoring_code_hash",
            "cert_payload_digest-missing-score_components_hash",
        }

    def test_starstar_kwargs_accepted_conservatively(self, tmp_path):
        # **kwargs expansion is opaque; trust it so we do not false-positive
        # on legitimate wrapper helpers.
        _write(tmp_path, "src/star.py", """
from oracle.cluster.cert_signing import cert_payload_digest

opts = {
    "scoring_code_hash": b"\\xab"*32,
    "score_components_hash": b"\\xcd"*32,
}
cert_payload_digest(
    b"agent"*4, 1, 851, 2, 0, b"\\x00"*32, True,
    b"\\x77"*32, slot_anchor=None,
    baseline_commit_nonce=7,
    **opts,
)
""")
        r = scan(python_roots=(tmp_path,), ts_roots=())
        assert r.hard_count == 0


# =============================================================================
# TS: certPayloadDigest
# =============================================================================

class TestTsCertPayloadDigestPin:

    def test_both_keywords_in_args_passes(self, tmp_path):
        _write(tmp_path, "src/ok.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
  baselineCommitNonce,
  scoringCodeHash,        // AW-04
  scoreComponentsHash,    // AW-04
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_keywords_in_comments_pass(self, tmp_path):
        # A literal mention anywhere in the args region — including
        # comments — is a positive intent signal.
        _write(tmp_path, "src/ok_comment.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
  1n,
  CODE_BUF,    // AW-04: scoringCodeHash stamped on chain
  COMP_BUF,    // AW-04: scoreComponentsHash for THIS epoch
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_missing_scoring_code_hash_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad_code.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
  baselineCommitNonce,
  scoreComponentsHash,
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 1
        assert r.findings[0].rule == "certPayloadDigest-missing-scoringCodeHash"

    def test_missing_score_components_hash_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad_components.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
  baselineCommitNonce,
  scoringCodeHash,
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 1
        assert r.findings[0].rule == "certPayloadDigest-missing-scoreComponentsHash"

    def test_neither_keyword_flags_both(self, tmp_path):
        _write(tmp_path, "src/bad_both.ts", """
const digest = certPayloadDigest(
  agent, epoch, score, alertTier, flags, baselineHash, immediateRed,
  inputCommitment,
  slotAnchorSlot, slotAnchorHash,
  baselineCommitNonce,
);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 2
        rules = {f.rule for f in r.findings}
        assert rules == {
            "certPayloadDigest-missing-scoringCodeHash",
            "certPayloadDigest-missing-scoreComponentsHash",
        }


# =============================================================================
# TS: scoreComponentsPda
# =============================================================================

class TestTsScoreComponentsPdaPin:

    def test_epoch_keyword_passes(self, tmp_path):
        _write(tmp_path, "src/ok_pda.ts", """
const pda = scoreComponentsPda(certIssuer, agent, epoch);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_epoch_substring_in_local_binding_passes(self, tmp_path):
        # A locally-bound variable that contains "epoch" is the most
        # common form — `currentEpoch`, `epochId`, etc.
        _write(tmp_path, "src/ok_pda_local.ts", """
const pda = scoreComponentsPda(certIssuer, agent, currentEpoch);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 0

    def test_no_epoch_is_flagged(self, tmp_path):
        _write(tmp_path, "src/bad_pda.ts", """
const pda = scoreComponentsPda(certIssuer, agent, 0);
""")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        assert r.hard_count == 1
        assert r.findings[0].rule == "scoreComponentsPda-missing-epoch"


# =============================================================================
# Allowlist + integration
# =============================================================================

class TestAllowlistAndShape:

    def test_findings_have_full_metadata(self, tmp_path):
        _write(tmp_path, "src/bad.ts", "certPayloadDigest(a, b, c);\n")
        r = scan(python_roots=(), ts_roots=(tmp_path,))
        # Two pins fire: missing scoringCodeHash AND missing scoreComponentsHash.
        assert r.hard_count == 2
        for f in r.findings:
            assert f.severity == "HARD"
            assert f.path.endswith("bad.ts")
            assert f.line == 1
            assert "certPayloadDigest" in f.snippet

    def test_real_repo_has_no_aw04_findings(self, tmp_path):
        # Smoke test against the actual repo — every production caller
        # should already thread the AW-04 hashes (the work was completed
        # in tasks #147-#150). If this regresses, the launch is blocked.
        from scoring_provenance_check import (  # type: ignore
            PYTHON_ROOTS, TS_ROOTS, scan,
        )
        r = scan(python_roots=PYTHON_ROOTS, ts_roots=TS_ROOTS)
        assert r.hard_count == 0, (
            "AW-04 regression in production code:\n"
            + "\n".join(
                f"  {f.path}:{f.line}  [{f.rule}]  {f.snippet}"
                for f in r.findings
            )
        )
