"""
audit/test_death_spiral_check.py — self-test for the PDS gate.

Runs the gate against the live repo and asserts:

  * Every PDS family (PDS-1..PDS-3) is probed.
  * The gate is currently GREEN — no hard findings on the as-shipped
    tree.
  * The JSON report serialises cleanly with a summary block.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_death_spiral_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import death_spiral_check  # noqa: E402


def test_all_pds_families_are_checked():
    report = death_spiral_check.run()
    checked = "\n".join(report.checked)
    for marker in ("PDS-1", "PDS-2", "PDS-3"):
        assert marker in checked, (
            f"PDS gate missed family {marker!r} — every Protocol Death "
            f"Spiral mitigation must have a probe."
        )


def test_repo_is_currently_green():
    report = death_spiral_check.run()
    hard = report.hard()
    assert not hard, (
        "PDS gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.pds}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = death_spiral_check.run().to_json()
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 3
    assert parsed["summary"]["hard_findings"] == 0
