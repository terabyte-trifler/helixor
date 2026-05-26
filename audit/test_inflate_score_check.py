"""
audit/test_inflate_score_check.py — self-test for the ILS gate.

Runs the gate against the live repo and asserts:

  * Every ILS family (ILS-1..ILS-3) is probed, plus the on-chain /
    indexer / cluster anchors that pair with each ILS (VULN-06,
    VULN-07, VULN-03).
  * The gate is currently GREEN — no hard findings on the as-shipped
    tree.
  * The JSON report serialises cleanly with a summary block.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_inflate_score_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import inflate_score_check  # noqa: E402


def test_all_ils_families_are_checked():
    report = inflate_score_check.run()
    checked = "\n".join(report.checked)
    for marker in ("ILS-1", "ILS-2", "ILS-3", "VULN-06", "VULN-07", "VULN-03"):
        assert marker in checked, (
            f"ILS gate missed family {marker!r} — every "
            f"Inflate-Legitimate-Score mitigation (and its anchor "
            f"in the on-chain / indexer / cluster substrate) must "
            f"have a probe."
        )


def test_repo_is_currently_green():
    report = inflate_score_check.run()
    hard = report.hard()
    assert not hard, (
        "ILS gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.ils}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = inflate_score_check.run().to_json()
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 3
    assert parsed["summary"]["hard_findings"] == 0
