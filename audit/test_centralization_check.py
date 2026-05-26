"""
audit/test_centralization_check.py — self-test for the HCR gate.

Runs the gate against the live repo and asserts:

  * Every HCR family (HCR-1..HCR-4) is probed (`checked` list covers
    all four hidden-centralization risks).
  * The gate is currently GREEN — no hard findings on the as-shipped
    tree. A red gate here means an HCR mitigation has regressed since
    the audit anchors were committed.
  * The JSON report serialises cleanly with a summary block, so the
    `--json` artefact is consumable by downstream tooling.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_centralization_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import centralization_check  # noqa: E402


def test_all_hcr_families_are_checked():
    report = centralization_check.run()
    checked = "\n".join(report.checked)
    for marker in ("HCR-1", "HCR-2", "HCR-3", "HCR-4"):
        assert marker in checked, (
            f"centralization gate missed family {marker!r} — every "
            f"hidden-centralization risk must have a probe."
        )


def test_repo_is_currently_green():
    report = centralization_check.run()
    hard = report.hard()
    assert not hard, (
        "centralization gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.hcr}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = centralization_check.run().to_json()
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 4
    assert parsed["summary"]["hard_findings"] == 0
