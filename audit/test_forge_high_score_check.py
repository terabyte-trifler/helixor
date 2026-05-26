"""
audit/test_forge_high_score_check.py — self-test for the FHS gate.

Runs the gate against the live repo and asserts:

  * Every FHS family (FHS-1..FHS-3) is probed, plus the VULN-01
    on-chain signing anchor that pairs with FHS-2.
  * The gate is currently GREEN — no hard findings on the as-shipped
    tree.
  * The JSON report serialises cleanly with a summary block.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_forge_high_score_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import forge_high_score_check  # noqa: E402


def test_all_fhs_families_are_checked():
    report = forge_high_score_check.run()
    checked = "\n".join(report.checked)
    for marker in ("FHS-1", "FHS-2", "FHS-3", "VULN-01"):
        assert marker in checked, (
            f"FHS gate missed family {marker!r} — every "
            f"Forge-High-Score-Cert mitigation (and its on-chain "
            f"anchor) must have a probe."
        )


def test_repo_is_currently_green():
    report = forge_high_score_check.run()
    hard = report.hard()
    assert not hard, (
        "FHS gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.fhs}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = forge_high_score_check.run().to_json()
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 4
    assert parsed["summary"]["hard_findings"] == 0
