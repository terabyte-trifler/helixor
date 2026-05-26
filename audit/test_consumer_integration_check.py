"""
audit/test_consumer_integration_check.py — self-test for the DBP-1 gate.

Runs the gate against the live repo and asserts:

  * Every DBP-1 family (DBP-1a..DBP-1d) is probed.
  * The reference example_safe_partner manifest is GREEN — no hard
    findings on the as-shipped tree.
  * The JSON report serialises cleanly with a summary block.
  * The canonical-hash recompute matches the reference manifest's
    pinned hash (catches accidental field drift in the schema).

Run with:
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest audit/test_consumer_integration_check.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from audit import consumer_integration_check  # noqa: E402


def test_all_dbp1_families_are_checked():
    report = consumer_integration_check.run()
    checked = "\n".join(report.checked)
    for marker in (
        "DBP-1a",  # per-manifest
        "DBP-1b",  # VULN-23 anchor
        "DBP-1c",  # SOL-3 anchor
        "DBP-1d",  # AW-01-EXT anchor
    ):
        assert marker in checked, (
            f"DBP-1 gate missed family {marker!r} — every Path-4 "
            f"closure substrate (per-manifest + VULN-23 + SOL-3 + "
            f"AW-01-EXT anchors) must have a probe."
        )


def test_reference_manifest_is_present_and_green():
    report = consumer_integration_check.run()
    hard = report.hard()
    assert not hard, (
        "DBP-1 gate has HARD findings on the as-shipped tree:\n"
        + "\n".join(f"  [{f.family}] {f.rule}: {f.detail}" for f in hard)
    )
    # The reference example manifest must be present so the linter has a
    # canonical green target.
    example = REPO_ROOT / "launch" / "integrations" / "example_safe_partner.json"
    assert example.is_file(), (
        "launch/integrations/example_safe_partner.json must exist — it is "
        "the reference Verified-Integrator manifest."
    )


def test_report_serialises_to_json():
    body = consumer_integration_check.run().to_json()
    parsed = json.loads(body)
    assert "summary" in parsed
    assert parsed["summary"]["checks"] == 4
    assert parsed["summary"]["hard_findings"] == 0


def test_canonical_hash_recompute_matches_manifest():
    example = REPO_ROOT / "launch" / "integrations" / "example_safe_partner.json"
    manifest = json.loads(example.read_text())
    expected = consumer_integration_check._canonical_hash(manifest)
    assert manifest["integration_hash"] == expected, (
        f"example_safe_partner.json integration_hash drift — "
        f"pinned {manifest['integration_hash']!r} vs recompute {expected!r}. "
        f"Regenerate via the helper in launch/integrations/MANIFEST_SCHEMA.md."
    )
