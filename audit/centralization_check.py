#!/usr/bin/env python3
"""
audit/centralization_check.py — the unified HIDDEN-CENTRALIZATION audit gate.

The audit enumerated four hidden centralization risks (HCR-1..HCR-4)
that survive even after every named SPOF and trust assumption is
closed:

  HCR-1  RPC provider monoculture       — single-provider outage halts
                                          the cluster's commit path
  HCR-2  Single cloud region            — regional outage halts the
                                          whole cluster
  HCR-3  Shared Kafka/Redis SPOF        — bus compromise reaches the
                                          signing path
  HCR-4  Operator key monoculture       — one org meets the threshold
                                          unilaterally

Each is closed by a real mechanism committed into the repo
(`oracle/provider_diversity.py`, `oracle/region_diversity.py`,
`oracle/state_isolation.py`, `oracle/operator_manifest.py`). This gate
is the mechanical regression alarm: it greps each marker so a refactor
that quietly removes a mitigation lights this red BEFORE mainnet.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the
trust-assumption gate.
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
    """One centralization gate finding."""
    hcr:      str
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
    report: Report, *, hcr: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            hcr=hcr, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-HCR probes
# =============================================================================

def check_hcr1_rpc_provider_diversity(report: Report) -> None:
    """HCR-1 — provider_diversity helper + 2-provider floor are present."""
    report.checked.append("HCR-1 rpc-provider diversity")

    src = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle" / "provider_diversity.py"
    )
    _require(
        report, hcr="HCR-1",
        rule="provider-diversity-module-present",
        condition=src is not None,
        detail=(
            "phylanx-oracle/oracle/provider_diversity.py is missing — the "
            "HCR-1 provider-diversity gate has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, hcr="HCR-1",
        rule="verify-provider-diversity-defined",
        condition="def verify_provider_diversity" in src,
        detail=(
            "provider_diversity.py no longer defines "
            "verify_provider_diversity — the construction-time gate is gone."
        ),
    )
    _require(
        report, hcr="HCR-1",
        rule="min-distinct-providers-2",
        condition="MIN_DISTINCT_RPC_PROVIDERS = 2" in src,
        detail=(
            "provider_diversity.py no longer pins "
            "MIN_DISTINCT_RPC_PROVIDERS=2 — a single-provider configuration "
            "may slip through."
        ),
    )
    _require(
        report, hcr="HCR-1",
        rule="known-providers-table-populated",
        condition="helius" in src and "quicknode" in src and "triton" in src,
        detail=(
            "provider_diversity.py's KNOWN_PROVIDERS table has lost coverage "
            "of the major Solana RPC providers — diversity checks will "
            "misclassify."
        ),
    )


def check_hcr2_region_diversity(report: Report) -> None:
    """HCR-2 — region_diversity helper + N-K cap + 2-region floor."""
    report.checked.append("HCR-2 region diversity")

    src = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle" / "region_diversity.py"
    )
    _require(
        report, hcr="HCR-2",
        rule="region-diversity-module-present",
        condition=src is not None,
        detail=(
            "phylanx-oracle/oracle/region_diversity.py is missing — the "
            "HCR-2 cluster-topology gate has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, hcr="HCR-2",
        rule="verify-region-diversity-defined",
        condition="def verify_region_diversity" in src,
        detail=(
            "region_diversity.py no longer defines verify_region_diversity."
        ),
    )
    _require(
        report, hcr="HCR-2",
        rule="min-distinct-regions-2",
        condition="MIN_DISTINCT_REGIONS = 2" in src,
        detail=(
            "region_diversity.py no longer pins MIN_DISTINCT_REGIONS=2 — "
            "a single-region cluster may slip through."
        ),
    )
    _require(
        report, hcr="HCR-2",
        rule="default-cluster-three-of-five",
        condition=(
            "DEFAULT_CLUSTER_SIZE = 5" in src
            and "DEFAULT_CLUSTER_THRESHOLD = 3" in src
        ),
        detail=(
            "region_diversity.py no longer pins the 3-of-5 default cluster "
            "shape — the per-region cap (N - K) becomes unspecified."
        ),
    )


def check_hcr3_state_isolation(report: Report) -> None:
    """HCR-3 — state_isolation helper + signing-path contract present."""
    report.checked.append("HCR-3 state isolation")

    src = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle" / "state_isolation.py"
    )
    _require(
        report, hcr="HCR-3",
        rule="state-isolation-module-present",
        condition=src is not None,
        detail=(
            "phylanx-oracle/oracle/state_isolation.py is missing — the "
            "HCR-3 signing-path isolation gate has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, hcr="HCR-3",
        rule="verify-signing-path-isolation-defined",
        condition="def verify_signing_path_isolation" in src,
        detail=(
            "state_isolation.py no longer defines "
            "verify_signing_path_isolation — the static-import gate is gone."
        ),
    )
    _require(
        report, hcr="HCR-3",
        rule="signing-path-modules-pinned",
        condition=(
            "SIGNING_PATH_MODULES" in src
            and "oracle.cluster.signer" in src
            and "scoring.composite" in src
        ),
        detail=(
            "state_isolation.py no longer pins SIGNING_PATH_MODULES with "
            "the cluster signer + scoring kernel — the gate's scope has "
            "shrunk to where it does not cover the trust path."
        ),
    )
    _require(
        report, hcr="HCR-3",
        rule="forbidden-imports-cover-kafka-redis",
        condition=(
            "SHARED_STATE_FORBIDDEN_IMPORTS" in src
            and "aiokafka" in src and "redis" in src
            and "confluent_kafka" in src
        ),
        detail=(
            "state_isolation.py no longer enumerates aiokafka / redis / "
            "confluent_kafka in SHARED_STATE_FORBIDDEN_IMPORTS."
        ),
    )

    # Cross-check: actually run the live verifier and ensure the
    # signing path is currently isolated. This duplicates the test in
    # test_hcr3_state_isolation.py but having the audit gate run it
    # too means a CI environment without pytest still catches the
    # regression.
    sys.path.insert(0, str(REPO_ROOT / "phylanx-oracle"))
    try:
        from oracle.state_isolation import (  # noqa: E402
            _filesystem_source_lookup,
            verify_signing_path_isolation as _verify,
            SharedStateDependencyError,
        )
        try:
            _verify(_filesystem_source_lookup(REPO_ROOT))
            live_ok = True
            live_detail = ""
        except SharedStateDependencyError as exc:
            live_ok = False
            live_detail = str(exc)
    finally:
        sys.path.pop(0)

    _require(
        report, hcr="HCR-3",
        rule="live-signing-path-isolated",
        condition=live_ok,
        detail=(
            "the live oracle tree has signing-path modules importing "
            "shared-state clients: " + live_detail
        ),
    )


def check_hcr4_operator_diversity(report: Report) -> None:
    """HCR-4 — operator_manifest + diversity floors are present."""
    report.checked.append("HCR-4 operator diversity")

    src = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle" / "operator_manifest.py"
    )
    _require(
        report, hcr="HCR-4",
        rule="operator-manifest-module-present",
        condition=src is not None,
        detail=(
            "phylanx-oracle/oracle/operator_manifest.py is missing — the "
            "HCR-4 operator-diversity gate has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, hcr="HCR-4",
        rule="operator-attestation-defined",
        condition="class OperatorAttestation" in src,
        detail=(
            "operator_manifest.py no longer defines OperatorAttestation — "
            "the per-operator declaration schema is gone."
        ),
    )
    _require(
        report, hcr="HCR-4",
        rule="verify-operator-diversity-defined",
        condition="def verify_operator_diversity" in src,
        detail=(
            "operator_manifest.py no longer defines "
            "verify_operator_diversity — the diversity-floor check is gone."
        ),
    )
    _require(
        report, hcr="HCR-4",
        rule="min-distinct-operators-2",
        condition="MIN_DISTINCT_OPERATORS = 2" in src,
        detail=(
            "operator_manifest.py no longer pins MIN_DISTINCT_OPERATORS=2 — "
            "single-org clusters may slip through."
        ),
    )
    _require(
        report, hcr="HCR-4",
        rule="min-distinct-jurisdictions-2",
        condition="MIN_DISTINCT_JURISDICTIONS = 2" in src,
        detail=(
            "operator_manifest.py no longer pins "
            "MIN_DISTINCT_JURISDICTIONS=2 — single-jurisdiction clusters "
            "may slip through."
        ),
    )


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_hcr1_rpc_provider_diversity(report)
    check_hcr2_region_diversity(report)
    check_hcr3_state_isolation(report)
    check_hcr4_operator_diversity(report)
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
            f"centralization_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nCentralization audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.hcr}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
