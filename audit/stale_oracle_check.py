#!/usr/bin/env python3
"""
audit/stale_oracle_check.py — the unified STALE ORACLE LOCK audit gate.

The audit's catastrophic Scenario C enumerated a 5-step Stale Oracle
Lock: all 5 oracle nodes are disrupted simultaneously -> no new certs
are issued -> DeFi protocols continue to use last-issued certs ->
agents whose behaviour degrades never get updated certs -> mass
defaults with no warning.

The mitigations (SOL-1..SOL-3) each close one substrate of the lock:

  SOL-1  Cluster-liveness signal             refuses cluster-alive when
                                              the cluster has been
                                              quiet past SILENT
                                              threshold or quorum is
                                              broken; visible BEFORE
                                              TA-6's 48h ceiling.
  SOL-2  Per-agent age-based tier            downgrades GREEN -> YELLOW
         degradation                          at 6h, YELLOW -> RED at
                                              12h, refuses at 24h —
                                              so a degrading agent's
                                              stale cert loses weight
                                              progressively, not
                                              cliff-edge.
  SOL-3  Per-operation freshness floors      LOAN_ISSUE 4h, INCREASE
                                              8h, LIQUIDATION 12h,
                                              STATUS_READ 48h (matches
                                              TA-6) — risk-asymmetric
                                              consumer circuit breaker.

Each is closed by a real mechanism committed into the repo
(`oracle/cluster_liveness.py`, `oracle/staleness_escalator.py`,
`oracle/operation_freshness.py`). This gate is the mechanical
regression alarm: it greps each marker so a refactor that quietly
removes a mitigation lights this red BEFORE mainnet.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the NSS
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
    """One stale-oracle gate finding."""
    sol:      str
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
    report: Report, *, sol: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            sol=sol, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-SOL probes
# =============================================================================

def check_sol1_cluster_liveness(report: Report) -> None:
    """SOL-1 — cluster-liveness signal present + thresholds pinned."""
    report.checked.append("SOL-1 cluster-liveness signal")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "cluster_liveness.py"
    )
    _require(
        report, sol="SOL-1",
        rule="cluster-liveness-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/cluster_liveness.py is missing — "
            "the SOL-1 cluster-liveness signal has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, sol="SOL-1",
        rule="verify-cluster-liveness-defined",
        condition="def verify_cluster_liveness" in src,
        detail=(
            "cluster_liveness.py no longer defines verify_cluster_liveness."
        ),
    )
    _require(
        report, sol="SOL-1",
        rule="enforce-cluster-alive-defined",
        condition="def enforce_cluster_alive" in src,
        detail=(
            "cluster_liveness.py no longer defines enforce_cluster_alive "
            "— the fail-closed circuit-breaker is gone."
        ),
    )
    _require(
        report, sol="SOL-1",
        rule="warn-quiet-2h",
        condition="WARN_QUIET_SECONDS = 2 * 3600" in src,
        detail=(
            "cluster_liveness.py no longer pins WARN_QUIET_SECONDS=2*3600 "
            "(2 hours) — the DEGRADED-band threshold has shifted."
        ),
    )
    _require(
        report, sol="SOL-1",
        rule="silent-quiet-4h",
        condition="SILENT_QUIET_SECONDS = 4 * 3600" in src,
        detail=(
            "cluster_liveness.py no longer pins SILENT_QUIET_SECONDS=4*3600 "
            "(4 hours) — the SILENT-band threshold (consumer-side circuit "
            "breaker trigger) has shifted."
        ),
    )
    _require(
        report, sol="SOL-1",
        rule="min-recent-nodes-3",
        condition="MIN_RECENT_NODES_FOR_ALIVE = 3" in src,
        detail=(
            "cluster_liveness.py no longer pins MIN_RECENT_NODES_FOR_ALIVE=3 "
            "— the quorum floor for considering the cluster alive has "
            "shifted; a below-quorum cluster could now appear ALIVE."
        ),
    )
    _require(
        report, sol="SOL-1",
        rule="band-constants-pinned",
        condition=(
            'LIVENESS_ALIVE = "ALIVE"' in src
            and 'LIVENESS_DEGRADED = "DEGRADED"' in src
            and 'LIVENESS_SILENT = "SILENT"' in src
        ),
        detail=(
            "cluster_liveness.py no longer pins the band-label constants "
            "(ALIVE / DEGRADED / SILENT) — the consumer SDK and runbook "
            "greps rely on those literals."
        ),
    )


def check_sol2_staleness_escalator(report: Report) -> None:
    """SOL-2 — per-agent age-based tier degradation escalator."""
    report.checked.append("SOL-2 per-agent staleness escalator")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "staleness_escalator.py"
    )
    _require(
        report, sol="SOL-2",
        rule="staleness-escalator-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/staleness_escalator.py is missing — "
            "the SOL-2 age-based tier escalator has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, sol="SOL-2",
        rule="escalate-for-age-defined",
        condition="def escalate_for_age" in src,
        detail=(
            "staleness_escalator.py no longer defines escalate_for_age."
        ),
    )
    _require(
        report, sol="SOL-2",
        rule="green-to-yellow-6h",
        condition="GREEN_TO_YELLOW_AFTER_SECONDS = 6 * 3600" in src,
        detail=(
            "staleness_escalator.py no longer pins "
            "GREEN_TO_YELLOW_AFTER_SECONDS=6*3600 — the first downgrade "
            "floor has shifted."
        ),
    )
    _require(
        report, sol="SOL-2",
        rule="yellow-to-red-12h",
        condition="YELLOW_TO_RED_AFTER_SECONDS = 12 * 3600" in src,
        detail=(
            "staleness_escalator.py no longer pins "
            "YELLOW_TO_RED_AFTER_SECONDS=12*3600 — the second downgrade "
            "floor has shifted."
        ),
    )
    _require(
        report, sol="SOL-2",
        rule="refuse-24h",
        condition="REFUSE_AFTER_SECONDS = 24 * 3600" in src,
        detail=(
            "staleness_escalator.py no longer pins REFUSE_AFTER_SECONDS=24*3600 "
            "— the outright-refuse floor (the half-life-of-TA-6) has "
            "shifted."
        ),
    )
    _require(
        report, sol="SOL-2",
        rule="tier-constants-pinned",
        condition=(
            'TIER_GREEN = "GREEN"' in src
            and 'TIER_YELLOW = "YELLOW"' in src
            and 'TIER_RED = "RED"' in src
            and 'TIER_REFUSE = "REFUSE"' in src
        ),
        detail=(
            "staleness_escalator.py no longer pins the tier-label "
            "constants (GREEN / YELLOW / RED / REFUSE) — the consumer "
            "SDK and runbook greps rely on those literals."
        ),
    )


def check_sol3_operation_freshness(report: Report) -> None:
    """SOL-3 — per-operation freshness floors."""
    report.checked.append("SOL-3 per-operation freshness floors")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "operation_freshness.py"
    )
    _require(
        report, sol="SOL-3",
        rule="operation-freshness-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/operation_freshness.py is missing — "
            "the SOL-3 per-operation freshness floor has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, sol="SOL-3",
        rule="verify-operation-freshness-defined",
        condition="def verify_operation_freshness" in src,
        detail=(
            "operation_freshness.py no longer defines "
            "verify_operation_freshness."
        ),
    )
    _require(
        report, sol="SOL-3",
        rule="enforce-operation-freshness-defined",
        condition="def enforce_operation_freshness" in src,
        detail=(
            "operation_freshness.py no longer defines "
            "enforce_operation_freshness — the fail-closed circuit "
            "breaker is gone."
        ),
    )
    _require(
        report, sol="SOL-3",
        rule="loan-issue-4h",
        condition="LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600" in src,
        detail=(
            "operation_freshness.py no longer pins "
            "LOAN_ISSUE_MAX_AGE_SECONDS=4*3600 — the high-stakes "
            "operation floor has shifted."
        ),
    )
    _require(
        report, sol="SOL-3",
        rule="loan-increase-8h",
        condition="LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 3600" in src,
        detail=(
            "operation_freshness.py no longer pins "
            "LOAN_INCREASE_MAX_AGE_SECONDS=8*3600."
        ),
    )
    _require(
        report, sol="SOL-3",
        rule="liquidation-check-12h",
        condition="LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 3600" in src,
        detail=(
            "operation_freshness.py no longer pins "
            "LIQUIDATION_CHECK_MAX_AGE_SECONDS=12*3600."
        ),
    )
    _require(
        report, sol="SOL-3",
        rule="status-read-48h-matches-ta6",
        condition="STATUS_READ_MAX_AGE_SECONDS = 48 * 3600" in src,
        detail=(
            "operation_freshness.py no longer pins "
            "STATUS_READ_MAX_AGE_SECONDS=48*3600 — the mirror of TA-6's "
            "MAX_AGE_SECONDS=48h has shifted; SOL-3 and TA-6 must move "
            "in lockstep for the most permissive operation."
        ),
    )
    _require(
        report, sol="SOL-3",
        rule="operation-enum-defined",
        condition=(
            "class Operation" in src
            and 'LOAN_ISSUE = "LOAN_ISSUE"' in src
            and 'LOAN_INCREASE = "LOAN_INCREASE"' in src
            and 'LIQUIDATION_CHECK = "LIQUIDATION_CHECK"' in src
            and 'STATUS_READ = "STATUS_READ"' in src
        ),
        detail=(
            "operation_freshness.py no longer defines the Operation "
            "enum with all four canonical operations — the SDK and "
            "runbook greps rely on the wire labels."
        ),
    )

    # Cross-check: TA-6's on-chain MAX_AGE_SECONDS = 48h must still
    # ship. SOL-3's STATUS_READ floor is supposed to mirror it.
    cert_src = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "certificate-issuer"
        / "src" / "state" / "health_certificate.rs"
    )
    if cert_src is not None:
        _require(
            report, sol="SOL-3",
            rule="ta6-mirror-48h-lockstep",
            condition=(
                "MAX_AGE_SECONDS" in cert_src
                and ("48 * 60 * 60" in cert_src or "172800" in cert_src)
            ),
            detail=(
                "certificate-issuer/state/health_certificate.rs no longer "
                "pins MAX_AGE_SECONDS=48*60*60 — TA-6's on-chain ceiling "
                "(48h) and SOL-3's STATUS_READ floor (48h) are out of "
                "lockstep, so a consumer could refuse for STATUS_READ "
                "while TA-6 accepts the same cert (or vice versa)."
            ),
        )


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_sol1_cluster_liveness(report)
    check_sol2_staleness_escalator(report)
    check_sol3_operation_freshness(report)
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
            f"stale_oracle_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nStale Oracle Lock audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.sol}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
