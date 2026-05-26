"""
audit/test_trust_assumption_check.py — self-test for the TA gate.

Runs the gate against the live repo and asserts:

  * Every TA family (TA-1..TA-8) is probed (`checked` list covers all
    eight).
  * The gate is currently GREEN — no hard findings on the as-shipped
    tree. A red gate here means a TA mitigation has regressed since the
    audit anchors were committed; the gate's existence justifies itself.
  * The JSON report serialises cleanly with a summary block, so the
    `--json` artefact is consumable by downstream tooling.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_trust_assumption_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import trust_assumption_check  # noqa: E402


def test_all_ta_families_are_checked():
    report = trust_assumption_check.run()
    checked = "\n".join(report.checked)
    for marker in (
        "TA-1", "TA-2", "TA-3", "TA-4",
        "TA-5", "TA-6", "TA-7", "TA-8",
    ):
        assert marker in checked, (
            f"TA gate missed family {marker!r} — every audit trust "
            f"assumption must have a probe."
        )


def test_repo_is_currently_green():
    report = trust_assumption_check.run()
    hard = report.hard()
    assert not hard, (
        "TA gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.ta}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = trust_assumption_check.run().to_json()
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 8
    assert parsed["summary"]["hard_findings"] == 0
