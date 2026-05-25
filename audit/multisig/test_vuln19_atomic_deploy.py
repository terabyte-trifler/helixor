"""
audit/multisig/test_vuln19_atomic_deploy.py — VULN-19 pin tests.

Exercise the argument-parsing refusal paths in launch/deploy/deploy_programs.sh
to confirm the mainnet path can never reach `anchor deploy` without the
Squads vault arguments that drive the atomic per-program transfer.

These tests do NOT run `anchor build` / `anchor deploy` / `npx ts-node` —
every refusal check in the script happens BEFORE any external command is
invoked, so the tests exit early on the expected stderr message + exit
code. That keeps the suite hermetic on machines without a Solana toolchain.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_SCRIPT = REPO_ROOT / "launch" / "deploy" / "deploy_programs.sh"


def _run_deploy(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the deploy script, capturing stdout/stderr, with a short timeout
    so a buggy refusal path doesn't hang the test suite."""
    return subprocess.run(
        ["bash", str(DEPLOY_SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )


# =============================================================================
# Sanity — the script parses
# =============================================================================

def test_script_is_executable_and_parses():
    """Bash syntax-check; catches a stray `;;` / `fi` mismatch immediately."""
    result = subprocess.run(
        ["bash", "-n", str(DEPLOY_SCRIPT)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"bash -n failed: {result.stderr}"


def test_help_shape_when_cluster_missing():
    """No --cluster => usage message + exit 2."""
    result = _run_deploy()
    assert result.returncode == 2
    assert "--cluster" in result.stderr or "--cluster" in result.stdout


# =============================================================================
# Mainnet refusal gates
# =============================================================================

class TestMainnetRefusal:

    def test_mainnet_without_opt_in_refused(self):
        result = _run_deploy("--cluster", "mainnet-beta")
        assert result.returncode == 2
        assert "REFUSING to deploy to mainnet-beta without --mainnet-ok" in result.stderr

    def test_mainnet_with_no_transfer_refused(self):
        """
        VULN-19: mainnet must NEVER run with --no-transfer. The window
        between deploy and transfer is the exact compromise surface this
        vuln addresses.
        """
        result = _run_deploy(
            "--cluster", "mainnet-beta",
            "--mainnet-ok",
            "--no-transfer",
        )
        assert result.returncode == 2
        assert "--no-transfer" in result.stderr
        assert "VULN-19" in result.stderr

    def test_mainnet_without_squads_vault_refused(self):
        result = _run_deploy(
            "--cluster", "mainnet-beta",
            "--mainnet-ok",
        )
        assert result.returncode == 2
        assert "--squads-vault" in result.stderr
        assert "VULN-19" in result.stderr

    def test_mainnet_without_squads_owner_refused(self):
        result = _run_deploy(
            "--cluster", "mainnet-beta",
            "--mainnet-ok",
            "--squads-vault", "GgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGg",
        )
        assert result.returncode == 2
        assert "--squads-owner" in result.stderr
        assert "VULN-19" in result.stderr

    def test_mainnet_without_deployer_keypair_refused(self):
        result = _run_deploy(
            "--cluster", "mainnet-beta",
            "--mainnet-ok",
            "--squads-vault", "GgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGg",
            "--squads-owner", "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu",
        )
        assert result.returncode == 2
        assert "--deployer-keypair" in result.stderr


# =============================================================================
# Atomic-transfer arg consistency on non-mainnet
# =============================================================================

class TestAtomicTransferArgConsistency:
    """
    The three transfer args are all-or-nothing. Passing one without the
    others is a misconfiguration the script must catch even on devnet.
    """

    def test_partial_args_rejected_on_devnet(self):
        result = _run_deploy(
            "--cluster", "devnet",
            "--squads-vault", "GgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGg",
        )
        assert result.returncode == 2
        assert "must be passed together" in result.stderr


# =============================================================================
# Unsupported cluster
# =============================================================================

def test_unsupported_cluster_rejected():
    result = _run_deploy("--cluster", "fakenet")
    assert result.returncode == 2
    assert "unsupported cluster" in result.stderr


# =============================================================================
# Static contract — the deploy script imports the per-program transfer
# =============================================================================

class TestStaticContract:
    """
    Even when we can't run the toolchain end-to-end, the script's BODY
    must show that the atomic flow is wired up. Cheap grep-tests catch a
    refactor that drops a critical line without us needing a real cluster.
    """

    def test_deploy_script_calls_per_program_transfer(self):
        body = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        assert "transfer_upgrade_authority.ts" in body
        assert "--program" in body
        assert "--program-id" in body
        assert "--vault" in body
        assert "--execute" in body

    def test_deploy_script_runs_preflight_before_anchor_build(self):
        """
        The vault preflight must run BEFORE `anchor build` so we never
        even start the deploy chain with a misconfigured vault.
        """
        body = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        preflight_idx = body.index("preflight_vault.ts")
        build_idx     = body.index("anchor build")
        assert preflight_idx < build_idx, (
            "preflight_vault.ts must be invoked BEFORE `anchor build` so the "
            "deploy never proceeds against a misconfigured vault"
        )

    def test_deploy_script_writes_verified_marker_only_after_all_transfers(self):
        body = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        # The marker is emitted only when DO_TRANSFER=1 AND ALL_TRANSFERRED=1.
        assert "ALL_TRANSFERRED" in body
        assert "deploy_verified.json" in body
        # The "Announce program IDs publicly" line lives inside that branch.
        marker_idx  = body.index("ALL_TRANSFERRED")
        announce_idx = body.index("Announce program IDs publicly")
        # Marker setup happens before the announce instruction
        assert marker_idx < announce_idx


# =============================================================================
# Preflight script — present + parses
# =============================================================================

PREFLIGHT_SCRIPT = REPO_ROOT / "launch" / "deploy" / "preflight_vault.ts"


def test_preflight_script_exists():
    assert PREFLIGHT_SCRIPT.is_file(), (
        "VULN-19 requires launch/deploy/preflight_vault.ts to verify the "
        "Squads vault BEFORE the first anchor deploy"
    )


def test_preflight_takes_expected_args():
    body = PREFLIGHT_SCRIPT.read_text(encoding="utf-8")
    for flag in ("--vault", "--cluster", "--expected-owner"):
        assert flag in body, f"preflight_vault.ts must accept {flag}"


# =============================================================================
# Per-program mode in transfer_upgrade_authority.ts
# =============================================================================

TRANSFER_SCRIPT = REPO_ROOT / "audit" / "multisig" / "transfer_upgrade_authority.ts"


def test_transfer_script_supports_per_program_mode():
    body = TRANSFER_SCRIPT.read_text(encoding="utf-8")
    assert "onlyProgram" in body
    assert "onlyProgramId" in body
    assert "--program" in body
    assert "--program-id" in body
