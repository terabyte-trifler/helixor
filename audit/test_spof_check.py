"""
audit/test_spof_check.py — self-test for the unified SPOF audit gate.

Runs the gate against the live repo and asserts:

  * Every check fired (the report's `checked` list covers all six SPOF
    families).
  * The gate is currently GREEN (no hard findings on the as-shipped
    tree). A red gate here means a mitigation has regressed and the
    gate's existence justifies itself.

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_spof_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import spof_check  # noqa: E402


def test_all_spof_families_are_checked():
    report = spof_check.run()
    checked = "\n".join(report.checked)
    for marker in (
        "SPOF-#2",
        "SPOF-#3",
        "SPOF-#5",
        "SPOF-#6",
        "SPOF-#7+#9",
        "SPOF-#8",
    ):
        assert marker in checked, (
            f"SPOF gate missed family {marker!r} — every SPOF in the "
            f"resolution table must have a probe."
        )


def test_repo_is_currently_green():
    report = spof_check.run()
    hard = report.hard()
    assert not hard, (
        "SPOF gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.spof}] {f.rule}: {f.detail}" for f in hard)
    )


def test_report_serialises_to_json():
    body = spof_check.run().to_json()
    # Quick smoke: it is JSON and includes the summary block.
    import json
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] >= 6
    assert parsed["summary"]["hard_findings"] == 0
