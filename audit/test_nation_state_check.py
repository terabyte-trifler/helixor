"""
audit/test_nation_state_check.py — self-test for the NSS gate.

Runs the gate against the live repo and asserts:

  * Every NSS family (NSS-1..NSS-3) is probed.
  * The gate is currently GREEN — no hard findings on the as-shipped
    tree.
  * The JSON report serialises cleanly with a summary block.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_nation_state_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import nation_state_check  # noqa: E402


def test_all_nss_families_are_checked():
    report = nation_state_check.run()
    checked = "\n".join(report.checked)
    for marker in ("NSS-1", "NSS-2", "NSS-3"):
        assert marker in checked, (
            f"NSS gate missed family {marker!r} — every Nation-State "
            f"Silent Subversion mitigation must have a probe."
        )


def test_repo_is_currently_green():
    report = nation_state_check.run()
    hard = report.hard()
    assert not hard, (
        "NSS gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.nss}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = nation_state_check.run().to_json()
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 3
    assert parsed["summary"]["hard_findings"] == 0
