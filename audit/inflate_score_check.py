#!/usr/bin/env python3
"""
audit/inflate_score_check.py — the unified INFLATE LEGITIMATE SCORE
audit gate.

The red-team attack tree's Path 2 (root: "Drain DeFi Protocol
Integrated with Helixor") is "Inflate Legitimate Score" — three
sub-leaves:

  2a. Exploit VULN-06 (baseline overwrite)              [LOW EFFORT]
  2b. Exploit VULN-07 (feature poisoning)               [MEDIUM EFFORT]
  2c. Exploit VULN-03 (Byzantine drift)                 [HIGH EFFORT, LONG TERM]

Each sub-leaf has an EXISTING defence on-chain or at the indexer
boundary; what was missing pre-ILS was an off-chain pre-flight that
catches the residual attack shapes:

  ILS-1  Baseline-rotation cadence + co-attestation     refuses a
                                                       baseline
                                                       rotation that
                                                       arrives faster
                                                       than every 30
                                                       epochs OR is
                                                       attested by
                                                       fewer than the
                                                       agent + 1
                                                       cluster signer.
  ILS-2  Producer-corroboration + record-freshness     refuses an
                                                       agent's
                                                       aggregation
                                                       window if it
                                                       comes from
                                                       fewer than 2
                                                       distinct
                                                       producers, is
                                                       dominated by
                                                       one producer
                                                       (>70%), or
                                                       contains
                                                       records older
                                                       than 24h.
  ILS-3  Cumulative score-drift ceiling                refuses a
                                                       score whose
                                                       cumulative
                                                       drift from the
                                                       agent's
                                                       baseline_score
                                                       exceeds 30%,
                                                       whose per-
                                                       epoch jump
                                                       exceeds 5%, or
                                                       whose
                                                       monotonic
                                                       upward run
                                                       reaches 10
                                                       epochs.

Each is closed by a real module committed into the repo
(`oracle/baseline_rotation_guard.py`,
`oracle/feature_corroboration.py`, `oracle/score_drift_ceiling.py`).
This gate is the mechanical regression alarm: it greps each marker
so a refactor that quietly removes a mitigation lights this red
BEFORE mainnet. It ALSO cross-checks the on-chain and indexer-side
anchors for VULN-06
(`helixor-programs/programs/certificate-issuer/src/instructions/
record_baseline.rs` — `is_authorised_baseline_writer` +
`BaselineRotationTooSoon` + `BaselineEpochNotMonotonic`), VULN-07
(`helixor-indexer/eventbus/consumer.py` — `TrustedProducerSet` +
`verify_record_headers`), and VULN-03
(`helixor-oracle/oracle/cluster/drift_detector.py` —
`VELOCITY_THRESHOLD` + rolling baseline + per-node signed deviation)
so a regression on any existing anchor lights this gate too.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the FHS
gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Finding / Report
# =============================================================================

@dataclass
class Finding:
    """One inflate-score gate finding."""
    ils:      str
    severity: str        # "HARD" — gate fails; "SOFT" — informational
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
# Helpers
# =============================================================================

def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _require(
    report: Report, *, ils: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            ils=ils, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-ILS probes
# =============================================================================

def check_ils1_baseline_rotation_guard(report: Report) -> None:
    """ILS-1 — baseline-rotation cadence + co-attestation guard."""
    report.checked.append(
        "ILS-1 baseline-rotation cadence + co-attestation "
        "(VULN-06 on-chain anchor)"
    )

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle"
        / "baseline_rotation_guard.py"
    )
    _require(
        report, ils="ILS-1",
        rule="baseline-rotation-guard-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/baseline_rotation_guard.py is "
            "missing — the ILS-1 baseline-rotation cadence + "
            "co-attestation guard has been removed; an attacker with "
            "one compromised cluster key can grind any agent's "
            "baseline."
        ),
    )
    if src is None:
        return

    _require(
        report, ils="ILS-1",
        rule="verify-baseline-rotation-defined",
        condition="def verify_baseline_rotation" in src,
        detail=(
            "baseline_rotation_guard.py no longer defines "
            "verify_baseline_rotation."
        ),
    )
    _require(
        report, ils="ILS-1",
        rule="enforce-baseline-rotation-defined",
        condition="def enforce_baseline_rotation" in src,
        detail=(
            "baseline_rotation_guard.py no longer defines "
            "enforce_baseline_rotation — the fail-closed wrapper is "
            "gone."
        ),
    )
    _require(
        report, ils="ILS-1",
        rule="min-epochs-between-baseline-rotations-30",
        condition="MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30" in src,
        detail=(
            "baseline_rotation_guard.py no longer pins "
            "MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS=30 — the "
            "per-agent rotation cadence floor has shifted."
        ),
    )
    _require(
        report, ils="ILS-1",
        rule="min-baseline-cosigners-2",
        condition="MIN_BASELINE_COSIGNERS = 2" in src,
        detail=(
            "baseline_rotation_guard.py no longer pins "
            "MIN_BASELINE_COSIGNERS=2 — a single cluster signer "
            "could now rotate baselines alone."
        ),
    )
    _require(
        report, ils="ILS-1",
        rule="baseline-status-labels-pinned",
        condition=(
            'BASELINE_OK = "OK"' in src
            and 'BASELINE_REFUSED = "REFUSED"' in src
        ),
        detail=(
            "baseline_rotation_guard.py no longer pins the status "
            "labels (OK / REFUSED) — operator dashboards and audit "
            "gates grep these literals."
        ),
    )

    # Cross-check: VULN-06's on-chain anchor must still ship.
    onchain = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "certificate-issuer"
        / "src" / "instructions" / "record_baseline.rs"
    )
    if onchain is not None:
        _require(
            report, ils="ILS-1",
            rule="vuln06-on-chain-anchor-present",
            condition=(
                "is_authorised_baseline_writer" in onchain
                and "BaselineRotationTooSoon" in onchain
                and "BaselineEpochNotMonotonic" in onchain
            ),
            detail=(
                "record_baseline.rs no longer ships the VULN-06 "
                "on-chain anchor (is_authorised_baseline_writer + "
                "BaselineRotationTooSoon + BaselineEpochNotMonotonic) "
                "— ILS-1 is the off-chain pre-flight and cannot "
                "stand alone without the on-chain guards."
            ),
        )
    else:
        report.findings.append(Finding(
            ils="ILS-1", severity="HARD",
            rule="vuln06-record-baseline-module-present",
            detail=(
                "programs/certificate-issuer/src/instructions/"
                "record_baseline.rs is missing — the on-chain "
                "VULN-06 baseline-rotation module has been removed."
            ),
        ))


def check_ils2_feature_corroboration(report: Report) -> None:
    """ILS-2 — producer-corroboration + record-freshness floor."""
    report.checked.append(
        "ILS-2 producer-corroboration + record-freshness "
        "(VULN-07 indexer anchor)"
    )

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "feature_corroboration.py"
    )
    _require(
        report, ils="ILS-2",
        rule="feature-corroboration-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/feature_corroboration.py is "
            "missing — the ILS-2 producer-corroboration gate has "
            "been removed; a single compromised producer key can "
            "solo-poison an agent's aggregation."
        ),
    )
    if src is None:
        return

    _require(
        report, ils="ILS-2",
        rule="verify-feature-corroboration-defined",
        condition="def verify_feature_corroboration" in src,
        detail=(
            "feature_corroboration.py no longer defines "
            "verify_feature_corroboration."
        ),
    )
    _require(
        report, ils="ILS-2",
        rule="enforce-feature-corroboration-defined",
        condition="def enforce_feature_corroboration" in src,
        detail=(
            "feature_corroboration.py no longer defines "
            "enforce_feature_corroboration — the fail-closed "
            "wrapper is gone."
        ),
    )
    _require(
        report, ils="ILS-2",
        rule="min-distinct-producers-per-aggregation-2",
        condition="MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2" in src,
        detail=(
            "feature_corroboration.py no longer pins "
            "MIN_DISTINCT_PRODUCERS_PER_AGGREGATION=2 — a single "
            "producer could now supply all records for an agent."
        ),
    )
    _require(
        report, ils="ILS-2",
        rule="max-producer-dominance-ratio-0.7",
        condition="MAX_PRODUCER_DOMINANCE_RATIO = 0.7" in src,
        detail=(
            "feature_corroboration.py no longer pins "
            "MAX_PRODUCER_DOMINANCE_RATIO=0.7 — one producer could "
            "now dominate the aggregation above the per-producer "
            "cap."
        ),
    )
    _require(
        report, ils="ILS-2",
        rule="max-record-age-24h",
        condition="MAX_RECORD_AGE_SECONDS = 24 * 3600" in src,
        detail=(
            "feature_corroboration.py no longer pins "
            "MAX_RECORD_AGE_SECONDS=24*3600 — backfilled records "
            "from a compromised producer key could re-enter the "
            "aggregation window."
        ),
    )

    # Cross-check: VULN-07's indexer-side anchor must still ship.
    consumer = _read(
        REPO_ROOT / "helixor-indexer" / "eventbus" / "consumer.py"
    )
    if consumer is not None:
        _require(
            report, ils="ILS-2",
            rule="vuln07-consumer-anchor-present",
            condition=(
                "TrustedProducerSet" in consumer
                and "verify_record_headers" in consumer
            ),
            detail=(
                "eventbus/consumer.py no longer references the "
                "TrustedProducerSet + verify_record_headers anchor "
                "— the VULN-07 producer-signing defence is gone and "
                "ILS-2 cannot stand alone."
            ),
        )
    else:
        report.findings.append(Finding(
            ils="ILS-2", severity="HARD",
            rule="vuln07-consumer-module-present",
            detail=(
                "helixor-indexer/eventbus/consumer.py is missing — "
                "the indexer-side VULN-07 producer-signing anchor "
                "has been removed."
            ),
        ))


def check_ils3_score_drift_ceiling(report: Report) -> None:
    """ILS-3 — cumulative score-drift ceiling."""
    report.checked.append(
        "ILS-3 cumulative score-drift ceiling "
        "(VULN-03 cluster anchor)"
    )

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "score_drift_ceiling.py"
    )
    _require(
        report, ils="ILS-3",
        rule="score-drift-ceiling-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/score_drift_ceiling.py is "
            "missing — the ILS-3 cumulative score-drift ceiling has "
            "been removed; an attacker with patience can inflate a "
            "score by 30%+ over many epochs without per-epoch "
            "detectors catching it."
        ),
    )
    if src is None:
        return

    _require(
        report, ils="ILS-3",
        rule="verify-score-drift-ceiling-defined",
        condition="def verify_score_drift_ceiling" in src,
        detail=(
            "score_drift_ceiling.py no longer defines "
            "verify_score_drift_ceiling."
        ),
    )
    _require(
        report, ils="ILS-3",
        rule="enforce-score-drift-ceiling-defined",
        condition="def enforce_score_drift_ceiling" in src,
        detail=(
            "score_drift_ceiling.py no longer defines "
            "enforce_score_drift_ceiling — the fail-closed wrapper "
            "is gone."
        ),
    )
    _require(
        report, ils="ILS-3",
        rule="max-drift-from-baseline-0.30",
        condition="MAX_DRIFT_FROM_BASELINE_RATIO = 0.30" in src,
        detail=(
            "score_drift_ceiling.py no longer pins "
            "MAX_DRIFT_FROM_BASELINE_RATIO=0.30 — the cumulative "
            "drift ceiling has shifted past the audit's "
            "documented 37% inflation attack threshold."
        ),
    )
    _require(
        report, ils="ILS-3",
        rule="max-monotonic-drift-epochs-10",
        condition="MAX_MONOTONIC_DRIFT_EPOCHS = 10" in src,
        detail=(
            "score_drift_ceiling.py no longer pins "
            "MAX_MONOTONIC_DRIFT_EPOCHS=10 — a slow stairstep "
            "drift could now run indefinitely under the per-epoch "
            "ceiling."
        ),
    )
    _require(
        report, ils="ILS-3",
        rule="max-drift-per-epoch-0.05",
        condition="MAX_DRIFT_PER_EPOCH_RATIO = 0.05" in src,
        detail=(
            "score_drift_ceiling.py no longer pins "
            "MAX_DRIFT_PER_EPOCH_RATIO=0.05 — the per-epoch belt-"
            "and-braces ceiling has shifted (the cluster's "
            "drift_detector velocity gate is at 0.20; ILS-3's "
            "0.05 is the absolute hard floor)."
        ),
    )

    # Cross-check: VULN-03's cluster-side detector anchor must still
    # ship.
    detector = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "cluster"
        / "drift_detector.py"
    )
    if detector is not None:
        _require(
            report, ils="ILS-3",
            rule="vuln03-cluster-drift-detector-anchor-present",
            condition=(
                "VELOCITY_THRESHOLD" in detector
                and "DRIFT_REASON_VELOCITY" in detector
            ),
            detail=(
                "drift_detector.py no longer ships the VULN-03 "
                "cluster-side anchor (VELOCITY_THRESHOLD + "
                "DRIFT_REASON_VELOCITY) — ILS-3 is the absolute "
                "ceiling that pairs with the cluster's per-epoch "
                "detectors and cannot stand alone."
            ),
        )
    else:
        report.findings.append(Finding(
            ils="ILS-3", severity="HARD",
            rule="vuln03-drift-detector-module-present",
            detail=(
                "helixor-oracle/oracle/cluster/drift_detector.py "
                "is missing — the VULN-03 cluster-side drift "
                "detector has been removed."
            ),
        ))


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_ils1_baseline_rotation_guard(report)
    check_ils2_feature_corroboration(report)
    check_ils3_score_drift_ceiling(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", default="-",
        help="JSON report destination (default: stdout)",
    )
    args = parser.parse_args(argv)

    report = run()
    body = report.to_json()
    if args.json == "-":
        sys.stdout.write(body + "\n")
    else:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(body + "\n", encoding="utf-8")
        sys.stderr.write(
            f"inflate_score_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nInflate-Legitimate-Score audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.ils}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
