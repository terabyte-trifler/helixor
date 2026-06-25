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
        "DBP-1e",  # DBP-3 safe-default invariant
    ):
        assert marker in checked, (
            f"DBP-1 gate missed family {marker!r} — every Path-4 "
            f"closure substrate (per-manifest + VULN-23 + SOL-3 + "
            f"AW-01-EXT anchors + DBP-3 safe-default) must have a probe."
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
    assert parsed["summary"]["checks"] == 5
    assert parsed["summary"]["hard_findings"] == 0


def test_unsafe_import_without_safe_reader_is_rejected(tmp_path, monkeypatch):
    """DBP-1e: a per-source check — a partner cert-reader source that imports
    from `@phylanx/sdk/unsafe` WITHOUT also using `SafeCertReader` must HARD
    fail. This is the exact pattern Path-4 attackers exploit.
    """
    # Build a tiny throwaway manifest + reader source in a temp dir, then
    # point the linter at it via REPO_ROOT monkeypatch.
    integrations = tmp_path / "launch" / "integrations"
    integrations.mkdir(parents=True)
    sdk = tmp_path / "phylanx-sdk" / "src"
    sdk.mkdir(parents=True)
    oracle = tmp_path / "phylanx-oracle" / "oracle"
    oracle.mkdir(parents=True)

    # Stubs so the cross-checks don't trip on unrelated families.
    (sdk / "safe_reader.ts").write_text(
        'export class SafeCertReader {}\n'
        'export const CERT_MAX_AGE_SECONDS = 48 * 60 * 60;\n'
        'export const MAX_SCORE_VELOCITY = 200;\n'
        'export const VELOCITY_WINDOW_EPOCHS = 3;\n'
        'export const MIN_HISTORY_REQUIRED = 2;\n'
    )
    (sdk / "input_provenance.ts").write_text(
        'export function verifyAgainstSolanaLedger() {}\n'
        'export function verifyInputProvenance() {}\n'
    )
    (sdk / "index.ts").write_text(
        'export { SafeCertReader } from "./safe_reader";\n'
        'export { verifyAgainstSolanaLedger } from "./input_provenance";\n'
    )
    (sdk / "unsafe.ts").write_text(
        'export { PhylanxClient } from "./http_client";\n'
        'export { PhylanxChainClient } from "./client";\n'
    )
    (oracle / "operation_freshness.py").write_text(
        'from enum import Enum\n'
        'class Operation(str, Enum):\n'
        '    LOAN_ISSUE = "LOAN_ISSUE"\n'
        '    LOAN_INCREASE = "LOAN_INCREASE"\n'
        '    LIQUIDATION_CHECK = "LIQUIDATION_CHECK"\n'
        '    STATUS_READ = "STATUS_READ"\n'
        'LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600\n'
        'LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 3600\n'
        'LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 3600\n'
        'STATUS_READ_MAX_AGE_SECONDS = 48 * 3600\n'
        'def verify_operation_freshness(): pass\n'
    )

    # The bad reader: imports /unsafe but does NOT use SafeCertReader.
    bad_reader = tmp_path / "launch" / "integrations" / "bad_reader.ts"
    bad_reader.write_text(
        'import { PhylanxChainClient } from "@phylanx/sdk/unsafe";\n'
        '// raw read with no safety wrap, no provenance check, no\n'
        '// slot anchor — this is the Path-4 attack pattern.\n'
        'export async function readScore(c, ids, agent) {\n'
        '  return new PhylanxChainClient(c, ids).getScore(agent);\n'
        '}\n'
    )

    manifest = {
        "partner_name": "Bad Faith Partner",
        "partner_wallet": "11111111111111111111111111111111",
        "integration_version": "1.0.0",
        "cert_reader_source_paths": [
            "launch/integrations/bad_reader.ts",
        ],
        "operations_bound": ["STATUS_READ"],
        "safe_reader_imported": True,
        "input_provenance_verified": True,
        "slot_anchor_verified": True,
        "signature_ed25519": "deadbeef",
    }
    # Recompute the canonical hash for this manifest.
    manifest["integration_hash"] = consumer_integration_check._canonical_hash(
        manifest,
    )
    (integrations / "bad.json").write_text(json.dumps(manifest))

    monkeypatch.setattr(consumer_integration_check, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        consumer_integration_check, "INTEGRATIONS_DIR", integrations,
    )

    report = consumer_integration_check.run()
    rules = {f.rule for f in report.hard()}
    # The /unsafe-without-wrap finding MUST fire HARD against this source.
    assert any(
        r.startswith("unsafe-import-must-wrap[") for r in rules
    ), (
        "DBP-1e linter did not flag a cert-reader source that imports "
        "@phylanx/sdk/unsafe without using SafeCertReader. Findings: "
        f"{sorted(rules)}"
    )


def test_canonical_hash_recompute_matches_manifest():
    example = REPO_ROOT / "launch" / "integrations" / "example_safe_partner.json"
    manifest = json.loads(example.read_text())
    expected = consumer_integration_check._canonical_hash(manifest)
    assert manifest["integration_hash"] == expected, (
        f"example_safe_partner.json integration_hash drift — "
        f"pinned {manifest['integration_hash']!r} vs recompute {expected!r}. "
        f"Regenerate via the helper in launch/integrations/MANIFEST_SCHEMA.md."
    )
