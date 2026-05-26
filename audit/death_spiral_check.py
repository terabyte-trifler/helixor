#!/usr/bin/env python3
"""
audit/death_spiral_check.py — the unified PROTOCOL DEATH SPIRAL audit gate.

The audit's catastrophic Scenario A enumerated a 7-step Protocol Death
Spiral: attacker compromises 2 oracle nodes → runs slow-drift inflation
for 30 epochs → all agent scores reach 900+ → DeFi protocols issue max
loans → attacker triggers mass agent failures → loans default at once →
Helixor's credibility is destroyed.

The mitigations (PDS-1..PDS-3) each close one substrate of the spiral:

  PDS-1  Cluster score-band saturation gate
                                          refuses to sign an epoch where
                                          too many agents migrated into
                                          the HIGH band simultaneously
  PDS-2  SDK-consumer score-velocity      caps per-epoch delta + per-hour
         contract                         velocity for cert pairs the
                                          DeFi consumer reads
  PDS-3  Cross-agent correlated-movement  detects multi-epoch directional
         + mass-failure detector          pressure across the whole agent
                                          universe; produces evidence hash

Each is closed by a real mechanism committed into the repo
(`oracle/cluster/saturation_gate.py`, `oracle/score_velocity.py`,
`oracle/cluster/correlated_inflation.py`). This gate is the mechanical
regression alarm: it greps each marker so a refactor that quietly
removes a mitigation lights this red BEFORE mainnet.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the
centralization gate.
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
    """One death-spiral gate finding."""
    pds:      str
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
    report: Report, *, pds: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            pds=pds, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-PDS probes
# =============================================================================

def check_pds1_saturation_gate(report: Report) -> None:
    """PDS-1 — cluster score-band saturation gate present + thresholds pinned."""
    report.checked.append("PDS-1 cluster saturation gate")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "cluster" / "saturation_gate.py"
    )
    _require(
        report, pds="PDS-1",
        rule="saturation-gate-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/cluster/saturation_gate.py is missing — "
            "the PDS-1 cross-agent saturation gate has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, pds="PDS-1",
        rule="verify-saturation-defined",
        condition="def verify_saturation" in src,
        detail=(
            "saturation_gate.py no longer defines verify_saturation — "
            "the score-band check is gone."
        ),
    )
    _require(
        report, pds="PDS-1",
        rule="enforce-saturation-defined",
        condition="def enforce_saturation" in src,
        detail=(
            "saturation_gate.py no longer defines enforce_saturation — "
            "the fail-closed wrapper used by the cluster pre-issue hook "
            "is gone."
        ),
    )
    _require(
        report, pds="PDS-1",
        rule="high-band-floor-700",
        condition="HIGH_BAND_FLOOR = 700" in src,
        detail=(
            "saturation_gate.py no longer pins HIGH_BAND_FLOOR=700 — the "
            "GREEN-tier boundary the gate operates on has shifted."
        ),
    )
    _require(
        report, pds="PDS-1",
        rule="max-migration-fraction-0.40",
        condition="MAX_HIGH_BAND_MIGRATION_FRACTION = 0.40" in src,
        detail=(
            "saturation_gate.py no longer pins "
            "MAX_HIGH_BAND_MIGRATION_FRACTION=0.40 — the per-epoch "
            "migration burst cap has moved."
        ),
    )
    _require(
        report, pds="PDS-1",
        rule="absolute-high-band-ceiling-0.80",
        condition="ABSOLUTE_HIGH_BAND_CEILING = 0.80" in src,
        detail=(
            "saturation_gate.py no longer pins "
            "ABSOLUTE_HIGH_BAND_CEILING=0.80 — the steady-state HIGH-band "
            "population density ceiling has moved."
        ),
    )
    _require(
        report, pds="PDS-1",
        rule="variance-collapse-threshold-0.50",
        condition="VARIANCE_COLLAPSE_THRESHOLD = 0.50" in src,
        detail=(
            "saturation_gate.py no longer pins "
            "VARIANCE_COLLAPSE_THRESHOLD=0.50 — the variance-collapse "
            "detector has been weakened."
        ),
    )


def check_pds2_score_velocity(report: Report) -> None:
    """PDS-2 — score-velocity contract present + thresholds pinned."""
    report.checked.append("PDS-2 SDK score-velocity contract")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "score_velocity.py"
    )
    _require(
        report, pds="PDS-2",
        rule="score-velocity-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/score_velocity.py is missing — the "
            "PDS-2 score-velocity contract has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, pds="PDS-2",
        rule="verify-score-velocity-defined",
        condition="def verify_score_velocity" in src,
        detail=(
            "score_velocity.py no longer defines verify_score_velocity."
        ),
    )
    _require(
        report, pds="PDS-2",
        rule="enforce-score-velocity-defined",
        condition="def enforce_score_velocity" in src,
        detail=(
            "score_velocity.py no longer defines enforce_score_velocity "
            "— the SDK fail-closed wrapper is gone."
        ),
    )
    _require(
        report, pds="PDS-2",
        rule="max-delta-per-epoch-200",
        condition="MAX_SCORE_DELTA_PER_EPOCH = 200" in src,
        detail=(
            "score_velocity.py no longer pins MAX_SCORE_DELTA_PER_EPOCH=200 "
            "— mirrors scoring._gaming.MAX_SCORE_DELTA; cluster-internal "
            "guard rail and SDK-side guard rail must move in lockstep."
        ),
    )
    _require(
        report, pds="PDS-2",
        rule="max-velocity-per-hour-100",
        condition="MAX_SCORE_VELOCITY_PER_HOUR = 100" in src,
        detail=(
            "score_velocity.py no longer pins MAX_SCORE_VELOCITY_PER_HOUR=100."
        ),
    )
    _require(
        report, pds="PDS-2",
        rule="absurd-velocity-per-hour-500",
        condition="ABSURD_VELOCITY_PER_HOUR = 500" in src,
        detail=(
            "score_velocity.py no longer pins ABSURD_VELOCITY_PER_HOUR=500."
        ),
    )

    # Cross-check: the internal cluster guard rail in scoring/_gaming.py
    # MUST still ship a MAX_SCORE_DELTA = 200 — PDS-2's SDK cap is
    # supposed to mirror it.
    gaming_src = _read(
        REPO_ROOT / "helixor-oracle" / "scoring" / "_gaming.py"
    )
    _require(
        report, pds="PDS-2",
        rule="scoring-gaming-cap-in-lockstep",
        condition=(
            gaming_src is not None
            and "MAX_SCORE_DELTA = 200" in gaming_src
        ),
        detail=(
            "scoring/_gaming.py no longer pins MAX_SCORE_DELTA=200 — the "
            "SDK PDS-2 cap (200) and the internal scoring guard rail are "
            "now out of lockstep, so a cluster-internal change could let "
            "an inflated score pass internal clamp while still failing the "
            "SDK gate (or vice versa)."
        ),
    )


def check_pds3_correlated_inflation(report: Report) -> None:
    """PDS-3 — correlated movement + mass failure detector present."""
    report.checked.append("PDS-3 correlated-inflation detector")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "cluster"
        / "correlated_inflation.py"
    )
    _require(
        report, pds="PDS-3",
        rule="correlated-inflation-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/cluster/correlated_inflation.py is "
            "missing — the PDS-3 multi-epoch correlation detector has "
            "been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, pds="PDS-3",
        rule="verify-correlated-movement-defined",
        condition="def verify_correlated_movement" in src,
        detail=(
            "correlated_inflation.py no longer defines "
            "verify_correlated_movement."
        ),
    )
    _require(
        report, pds="PDS-3",
        rule="verify-mass-failure-defined",
        condition="def verify_mass_failure" in src,
        detail=(
            "correlated_inflation.py no longer defines verify_mass_failure "
            "— the death-spiral terminal-phase detector is gone."
        ),
    )
    _require(
        report, pds="PDS-3",
        rule="max-directional-share-0.85",
        condition="MAX_DIRECTIONAL_SHARE = 0.85" in src,
        detail=(
            "correlated_inflation.py no longer pins "
            "MAX_DIRECTIONAL_SHARE=0.85 — the cross-agent correlation "
            "threshold has shifted."
        ),
    )
    _require(
        report, pds="PDS-3",
        rule="mass-failure-drop-200",
        condition="MASS_FAILURE_DROP = 200" in src,
        detail=(
            "correlated_inflation.py no longer pins MASS_FAILURE_DROP=200 "
            "— the per-agent crash floor has shifted."
        ),
    )
    _require(
        report, pds="PDS-3",
        rule="mass-failure-fraction-0.50",
        condition="MASS_FAILURE_AGENT_FRACTION = 0.50" in src,
        detail=(
            "correlated_inflation.py no longer pins "
            "MASS_FAILURE_AGENT_FRACTION=0.50 — the population-fraction "
            "floor has shifted."
        ),
    )
    _require(
        report, pds="PDS-3",
        rule="correlation-window-5",
        condition="CORRELATION_WINDOW = 5" in src,
        detail=(
            "correlated_inflation.py no longer pins CORRELATION_WINDOW=5 "
            "— the rolling-window length has shifted."
        ),
    )


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_pds1_saturation_gate(report)
    check_pds2_score_velocity(report)
    check_pds3_correlated_inflation(report)
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
            f"death_spiral_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nProtocol Death Spiral audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.pds}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
