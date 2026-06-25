"""
audit/test_vuln25_supply_chain_check.py — pin tests for VULN-25.

Asserts the live codebase passes AND exercises the CLI. Note: the
`requirements.txt` HARD finding for missing hashes is the EXPECTED
state when `pip-compile` has not been run yet (e.g. fresh checkout
on a sandbox without network). The scanner ONLY trips the
`requirements-txt-missing` rule if the matching `.in` declares
direct deps. Indexer's `.in` is dep-free, so its `.txt` may stay
absent.

These tests pin the source-side discipline that is always under our
control: `.in` files exist, every line is an exact `==` pin, the
signer surface is narrow, Cargo.lock is committed, the systemd
hardening directives stay intact.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


_AUDIT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _AUDIT_DIR.parent
_ORACLE_PKG = _REPO_ROOT / "phylanx-oracle"
for p in (_AUDIT_DIR, _ORACLE_PKG):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from supply_chain_check import (  # type: ignore  # noqa: E402
    PYTHON_PACKAGES, REQUIRED_SYSTEMD_HARDENING,
    Finding, main, scan,
)


# Findings rules that are EXPECTED-present on a fresh checkout because
# we don't ship the generated requirements.txt files (they require a
# network-enabled `pip-compile --generate-hashes` run, which the audit
# operator does at release time, not at every checkout).
_GENERATED_TXT_RULES = {
    "phylanx-oracle-requirements-txt-missing",
    "phylanx-api-requirements-txt-missing",
}


def _split(findings: list[Finding]):
    expected = [f for f in findings if f.rule in _GENERATED_TXT_RULES]
    unexpected = [f for f in findings if f.rule not in _GENERATED_TXT_RULES]
    return expected, unexpected


class TestRealCodebaseClean:

    def test_no_unexpected_supply_chain_findings(self):
        # Source-side discipline must always be clean. Generated-txt
        # gaps are expected pre-release and are gated separately in
        # LAUNCH_CHECKLIST.
        report = scan()
        _, unexpected = _split(report.findings)
        assert unexpected == [], (
            "the repo grew an unexpected supply-chain finding:\n"
            + "\n".join(
                f"  - {f.rule} @ {f.path}: {f.detail}"
                for f in unexpected
            )
        )
        assert report.files_scanned > 0


class TestSourceDiscipline:

    def test_every_python_pkg_has_requirements_in(self):
        from supply_chain_check import REPO_ROOT  # type: ignore
        for pkg in PYTHON_PACKAGES:
            assert (REPO_ROOT / pkg / "requirements.in").exists(), (
                f"{pkg}/requirements.in is missing"
            )

    def test_systemd_hardening_directives_pinned(self):
        from supply_chain_check import ORACLE_SYSTEMD_UNIT  # type: ignore
        text = ORACLE_SYSTEMD_UNIT.read_text()
        for d in REQUIRED_SYSTEMD_HARDENING:
            assert d in text, f"systemd unit missing required directive: {d}"

    def test_signer_module_exposes_protocol(self):
        # The whole point of the module is the Signer Protocol — if a
        # future refactor drops it the audit scanner won't catch it
        # silently, this test will.
        from oracle.cluster.signer import HSMSigner, InProcessSigner, Signer
        assert Signer is not None
        assert InProcessSigner is not None
        assert HSMSigner is not None


class TestCli:

    def test_cli_emits_json_to_path(self, tmp_path):
        # Default mode tolerates the expected `txt-missing` rules — they're
        # produced by the network-bound `pip-compile --generate-hashes`
        # at release time, gated separately in LAUNCH_CHECKLIST.
        out = tmp_path / "report.json"
        rc = main(["--json", str(out)])
        assert out.exists()
        blob = json.loads(out.read_text())
        assert rc == 0, (
            "default-mode CLI must tolerate expected `txt-missing` "
            "findings; unexpected ones:\n"
            + "\n".join(
                f"  - {f['rule']} @ {f['path']}: {f['detail']}"
                for f in blob["findings"]
                if f["rule"] not in _GENERATED_TXT_RULES
            )
        )

    def test_cli_strict_mode_fails_on_txt_missing(self, tmp_path):
        # `--strict` is the release-gate stance: every HARD finding
        # (including the expected `txt-missing` set) must be resolved
        # before the production deploy proceeds.
        out = tmp_path / "report.json"
        rc = main(["--strict", "--json", str(out)])
        blob = json.loads(out.read_text())
        if any(f["rule"] in _GENERATED_TXT_RULES for f in blob["findings"]):
            assert rc == 1, (
                "--strict must fail when txt-missing rules are present"
            )
