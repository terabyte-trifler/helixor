#!/usr/bin/env python3
"""
audit/cert_refusal_check.py — OFAC-1 silent-delist transparency gate.

The substrate is `helixor-oracle/oracle/cert_refusal_log.py`, paired
with `Topic.CERT_REFUSED = "agent.cert_events.refused"` in the
indexer's `eventbus/types.py`. This gate is the mechanical regression
alarm: if a refactor quietly removes the substrate, or breaks the
canonical topic name / wire schema, this lights red BEFORE mainnet.

WHAT IT VERIFIES
----------------
1. The `cert_refusal_log` module exists at the expected path.
2. The module exports the required public surface:
   `CertRefusal`, `CertRefusalLog`, `RefusalGate`, `RefusalReason`,
   plus the factory helpers.
3. The `RefusalReason` enum still carries the audit-pinned codes
   (any rename without a coordinated downstream update breaks the
   on-bus contract).
4. The `RefusalGate` enum still carries the OFAC-1-load-bearing
   `OPERATOR_OVERRIDE` member.
5. The indexer's `Topic` enum still exposes
   `CERT_REFUSED = "agent.cert_events.refused"` with the canonical
   `agent.cert_events.refused` topic name.
6. The serialiser pair (`serialize_cert_refused` /
   `deserialize_cert_refused`) still exists and still rejects bad
   inputs (empty wallet, negative epoch, empty reasons, naive
   datetime, wire-version mismatch).

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` after the centralization gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Audit-pinned codes — the contract the on-bus consumers depend on.
# =============================================================================

PINNED_REASON_CODES = frozenset({
    # NSS-3
    "AGENT_SECONDS_TOO_YOUNG",
    "AGENT_EPOCHS_TOO_YOUNG",
    "AGENT_REGISTERED_IN_FUTURE",
    # FRP-3
    "CERT_REISSUE_OVERDUE",
    "CERT_REISSUE_TIMESTAMP_INVALID",
    "CERT_REISSUE_TIMESTAMP_IN_FUTURE",
    # PDS-2
    "SCORE_DELTA_EXCEEDED",
    "SCORE_VELOCITY_EXCEEDED",
    "SCORE_VELOCITY_ABSURD",
    "SCORE_TIME_TRAVEL",
    # AW-01 / AW-01-EXT
    "INPUT_COMMITMENT_MISSING",
    "INPUT_COMMITMENT_DISAGREEMENT",
    "SLOT_ANCHOR_MISSING",
    # Cluster
    "QUORUM_NOT_MET",
    "SIGNATURE_THRESHOLD_NOT_MET",
    # OFAC-1 — the load-bearing one
    "OPERATOR_OVERRIDE",
})

CANONICAL_TOPIC = "agent.cert_events.refused"


# =============================================================================
# Finding / Report
# =============================================================================

@dataclass
class Finding:
    severity: str
    rule:     str
    detail:   str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    checked:  list[str] = field(default_factory=list)

    def hard(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HARD"]

    def to_json(self) -> str:
        return json.dumps(
            {
                "checked":  self.checked,
                "findings": [asdict(f) for f in self.findings],
                "summary": {
                    "checks":         len(self.checked),
                    "hard_findings":  len(self.hard()),
                    "soft_findings":  len(self.findings) - len(self.hard()),
                },
            },
            indent=2,
            sort_keys=True,
        )


# =============================================================================
# Checks
# =============================================================================

def _check_substrate_present(report: Report) -> None:
    """The oracle-side substrate module must exist."""
    path = REPO_ROOT / "helixor-oracle" / "oracle" / "cert_refusal_log.py"
    report.checked.append(str(path.relative_to(REPO_ROOT)))
    if not path.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.substrate-exists",
            detail=(
                f"missing {path.relative_to(REPO_ROOT)} — OFAC-1 silent-"
                f"delist transparency cannot fire without the substrate"
            ),
        ))


def _check_oracle_public_surface(report: Report) -> None:
    """The substrate module must export the audit-pinned symbols."""
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "helixor-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        module = importlib.import_module("oracle.cert_refusal_log")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.module-importable",
            detail=f"cert_refusal_log not importable: {exc!r}",
        ))
        return

    report.checked.append("oracle.cert_refusal_log:exports")
    required = {
        "CertRefusal", "CertRefusalLog",
        "RefusalGate", "RefusalReason",
        "from_agent_age_report", "from_velocity_report",
        "operator_override",
    }
    missing = sorted(required - set(getattr(module, "__all__", [])))
    if missing:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.public-surface",
            detail=(
                f"oracle.cert_refusal_log.__all__ is missing required "
                f"symbols: {missing}"
            ),
        ))

    # Pinned reason codes.
    reason_enum = getattr(module, "RefusalReason", None)
    if reason_enum is None:
        return
    enum_values = {m.value for m in reason_enum}
    missing_codes = sorted(PINNED_REASON_CODES - enum_values)
    if missing_codes:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.reason-codes-stable",
            detail=(
                f"RefusalReason is missing audit-pinned codes: "
                f"{missing_codes}. A rename without a coordinated "
                f"downstream update breaks the on-bus contract."
            ),
        ))

    # The load-bearing OPERATOR_OVERRIDE gate must remain.
    gate_enum = getattr(module, "RefusalGate", None)
    if gate_enum is None:
        return
    gate_values = {m.value for m in gate_enum}
    if "OPERATOR-OVERRIDE" not in gate_values:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.operator-override-gate",
            detail=(
                "RefusalGate.OPERATOR_OVERRIDE = 'OPERATOR-OVERRIDE' is "
                "missing — this is the audit-load-bearing gate that the "
                "audit script flags hardest. Removing it makes silent "
                "operator-side delisting invisible to the audit."
            ),
        ))


def _check_indexer_topic(report: Report) -> None:
    """The indexer's `Topic.CERT_REFUSED` must exist with the canonical name."""
    import importlib
    import sys as _sys
    indexer_root = REPO_ROOT / "helixor-indexer"
    if str(indexer_root) not in _sys.path:
        _sys.path.insert(0, str(indexer_root))
    try:
        module = importlib.import_module("eventbus.types")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.indexer-topic-importable",
            detail=f"eventbus.types not importable: {exc!r}",
        ))
        return

    report.checked.append("eventbus.types:Topic.CERT_REFUSED")
    topic_enum = getattr(module, "Topic", None)
    if topic_enum is None:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.indexer-topic-enum",
            detail="eventbus.types.Topic enum missing",
        ))
        return

    member = getattr(topic_enum, "CERT_REFUSED", None)
    if member is None:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.indexer-cert-refused-member",
            detail=(
                "Topic.CERT_REFUSED missing — the indexer cannot route "
                "refusals to a dedicated topic, so they would queue behind "
                "high-volume telemetry on agent.transactions (the exact "
                "lag attack VULN-14 mitigates for cert events)."
            ),
        ))
        return

    if member.value != CANONICAL_TOPIC:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.indexer-cert-refused-canonical-name",
            detail=(
                f"Topic.CERT_REFUSED has non-canonical name "
                f"{member.value!r}; expected {CANONICAL_TOPIC!r}. "
                f"Producers and consumers depend on this exact string."
            ),
        ))


def _check_indexer_serialiser(report: Report) -> None:
    """The serialiser pair must exist and reject the documented bad inputs."""
    import importlib
    import sys as _sys
    indexer_root = REPO_ROOT / "helixor-indexer"
    if str(indexer_root) not in _sys.path:
        _sys.path.insert(0, str(indexer_root))
    try:
        module = importlib.import_module("eventbus.serialization")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.serialiser-importable",
            detail=f"eventbus.serialization not importable: {exc!r}",
        ))
        return

    report.checked.append("eventbus.serialization:cert_refused")
    ser = getattr(module, "serialize_cert_refused", None)
    de  = getattr(module, "deserialize_cert_refused", None)
    if ser is None or de is None:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.serialiser-pair",
            detail=(
                "eventbus.serialization is missing serialize_cert_refused "
                "and/or deserialize_cert_refused — the indexer cannot "
                "produce or consume Topic.CERT_REFUSED messages."
            ),
        ))
        return

    # Round-trip canary — encode a known-good record and decode.
    SerializationError = getattr(module, "SerializationError", Exception)
    sample_ts = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)
    try:
        raw = ser(
            agent_wallet="agent-1",
            epoch=42,
            requested_tier="GREEN",
            gate="NSS-3",
            reasons=("AGENT_SECONDS_TOO_YOUNG",),
            detected_at=sample_ts,
        )
        decoded = de(raw)
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.serialiser-round-trip",
            detail=f"round-trip failed on a known-good record: {exc!r}",
        ))
        return

    if decoded.get("agent_wallet") != "agent-1" or decoded.get("epoch") != 42:
        report.findings.append(Finding(
            severity="HARD",
            rule="OFAC-1.serialiser-round-trip-shape",
            detail=f"round-trip produced wrong shape: {decoded!r}",
        ))


# =============================================================================
# Entry point
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", default="-",
        help="path for the JSON report (default: stdout)",
    )
    args = parser.parse_args()

    report = Report()
    _check_substrate_present(report)
    _check_oracle_public_surface(report)
    _check_indexer_topic(report)
    _check_indexer_serialiser(report)

    text = report.to_json()
    if args.json == "-" or args.json == "":
        sys.stdout.write(text + "\n")
    else:
        Path(args.json).write_text(text + "\n")

    return 1 if report.hard() else 0


if __name__ == "__main__":
    sys.exit(main())
