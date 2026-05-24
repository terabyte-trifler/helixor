"""
tests/test_main_network_guard.py — main.py honors the network guard.

The guard runs at MODULE IMPORT. Importing api.main with
HELIXOR_NETWORK=mainnet-beta and no opt-in must exit 2 — this is the
property that systemd's RestartPreventExitStatus=2 relies on.

We run a subprocess so the import side effect isolates from the test
process. A failed import in-process would pollute the import cache.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


HELIXOR_ORACLE = (
    Path(__file__).resolve().parent.parent.parent / "helixor-oracle"
)
HELIXOR_API = Path(__file__).resolve().parent.parent


def _run(env_extra: dict[str, str]) -> subprocess.CompletedProcess:
    env = {**os.environ, **env_extra}
    env["PYTHONPATH"] = f"{HELIXOR_API}:{HELIXOR_ORACLE}"
    return subprocess.run(
        [sys.executable, "-c", "import api.main"],
        env=env, capture_output=True, text=True, timeout=20,
    )


class TestMainNetworkGuard:

    def test_mainnet_without_opt_in_exits_2(self):
        out = _run({"HELIXOR_NETWORK": "mainnet-beta",
                    "HELIXOR_MAINNET_OK": ""})
        assert out.returncode == 2, (
            f"expected exit 2 for unguarded mainnet, got {out.returncode}\n"
            f"stdout:\n{out.stdout}\nstderr:\n{out.stderr}"
        )
        # The error message MUST guide the operator. The runbook
        # mainnet_refusal_triggered.md depends on this exact text.
        assert "REFUSING" in (out.stdout + out.stderr)
        assert "HELIXOR_MAINNET_OK" in (out.stdout + out.stderr)

    def test_mainnet_with_opt_in_imports_cleanly(self):
        out = _run({"HELIXOR_NETWORK":     "mainnet-beta",
                    "HELIXOR_MAINNET_OK":  "1"})
        assert out.returncode == 0, (
            f"opted-in mainnet should import cleanly, got {out.returncode}\n"
            f"stdout:\n{out.stdout}\nstderr:\n{out.stderr}"
        )
        # The opt-in path logs at WARNING (auditable).
        assert "PRODUCTION" in (out.stdout + out.stderr)

    def test_localnet_imports_cleanly(self):
        out = _run({"HELIXOR_NETWORK": "localnet"})
        assert out.returncode == 0

    def test_unknown_network_exits_2(self):
        out = _run({"HELIXOR_NETWORK": "some-other-cluster"})
        assert out.returncode == 2
