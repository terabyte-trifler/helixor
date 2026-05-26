"""
audit/test_freeze_cert_check.py — self-test for the FRP gate.

Runs the gate against the live repo and asserts:

  * Every FRP family (FRP-1..FRP-3) is probed, plus the on-chain /
    cluster anchors that pair with each FRP (VULN-05, VULN-02,
    TA-6).
  * The gate is currently GREEN — no hard findings on the as-shipped
    tree.
  * The JSON report serialises cleanly with a summary block.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_freeze_cert_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import freeze_cert_check  # noqa: E402


def test_all_frp_families_are_checked():
    report = freeze_cert_check.run()
    checked = "\n".join(report.checked)
    for marker in ("FRP-1", "FRP-2", "FRP-3", "VULN-05", "VULN-02", "TA-6"):
        assert marker in checked, (
            f"FRP gate missed family {marker!r} — every "
            f"Freeze-Cert-at-High-Score mitigation (and its anchor "
            f"in the on-chain / cluster substrate) must have a "
            f"probe."
        )


def test_repo_is_currently_green():
    report = freeze_cert_check.run()
    hard = report.hard()
    assert not hard, (
        "FRP gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.frp}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = freeze_cert_check.run().to_json()
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 3
    assert parsed["summary"]["hard_findings"] == 0
