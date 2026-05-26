#!/usr/bin/env python3
"""
audit/nation_state_check.py — the unified NATION-STATE SILENT SUBVERSION audit gate.

The audit's catastrophic Scenario B enumerated a 6-step Nation-State
Silent Subversion: nation-state compromises a cloud provider hosting
oracle nodes -> kernel module on the hypervisor exfiltrates Ed25519
private keys -> attacker holds K-of-N cluster keys -> attacker issues
GREEN certs for state-controlled AI agents on fresh wallets -> agents
accumulate large DeFi positions over weeks -> coordinated market action.

The mitigations (NSS-1..NSS-3) each close one substrate of the chain:

  NSS-1  Cluster cloud-provider              refuses to boot a cluster
         diversity gate                       whose nodes concentrate on
                                              one cloud provider — a single
                                              hypervisor compromise can no
                                              longer reach K-of-N keys.
  NSS-2  Mainnet HSM-only signing             refuses to start an oracle
         enforcement                          node on mainnet with an
                                              InProcessSigner (private key
                                              in process memory) — the
                                              kernel-module exfil substrate
                                              is not present.
  NSS-3  Cluster-side agent-registration-     refuses to stamp a GREEN cert
         age floor for GREEN certs            on a wallet that has not
                                              accumulated MIN_AGENT_AGE
                                              wall-clock seconds + epochs
                                              of on-chain history — state-
                                              controlled fresh wallets can
                                              not silently mint collateral-
                                              grade certs.

Each is closed by a real mechanism committed into the repo
(`oracle/cloud_diversity.py`, `oracle/signer_enforcement.py`,
`oracle/agent_age_gate.py`). This gate is the mechanical regression
alarm: it greps each marker so a refactor that quietly removes a
mitigation lights this red BEFORE mainnet.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the PDS gate.
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
    """One nation-state gate finding."""
    nss:      str
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
    report: Report, *, nss: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            nss=nss, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-NSS probes
# =============================================================================

def check_nss1_cloud_diversity(report: Report) -> None:
    """NSS-1 — cluster cloud-provider diversity gate present + floors pinned."""
    report.checked.append("NSS-1 cluster cloud-provider diversity")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "cloud_diversity.py"
    )
    _require(
        report, nss="NSS-1",
        rule="cloud-diversity-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/cloud_diversity.py is missing — the "
            "NSS-1 cluster cloud-provider diversity gate has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, nss="NSS-1",
        rule="classify-cloud-provider-defined",
        condition="def classify_cloud_provider" in src,
        detail=(
            "cloud_diversity.py no longer defines classify_cloud_provider "
            "— the per-node bucketing helper is gone."
        ),
    )
    _require(
        report, nss="NSS-1",
        rule="verify-cloud-diversity-defined",
        condition="def verify_cloud_diversity" in src,
        detail=(
            "cloud_diversity.py no longer defines verify_cloud_diversity "
            "— the cluster-boot enforcement is gone."
        ),
    )
    _require(
        report, nss="NSS-1",
        rule="min-distinct-cloud-providers-2",
        condition="MIN_DISTINCT_CLOUD_PROVIDERS = 2" in src,
        detail=(
            "cloud_diversity.py no longer pins "
            "MIN_DISTINCT_CLOUD_PROVIDERS=2 — the floor on distinct "
            "clouds has shifted; a one-cloud cluster will boot again."
        ),
    )
    _require(
        report, nss="NSS-1",
        rule="default-cluster-size-5",
        condition="DEFAULT_CLUSTER_SIZE = 5" in src,
        detail=(
            "cloud_diversity.py no longer pins DEFAULT_CLUSTER_SIZE=5 — "
            "the canonical cluster size used for the per-cloud cap has "
            "shifted."
        ),
    )
    _require(
        report, nss="NSS-1",
        rule="default-cluster-threshold-3",
        condition="DEFAULT_CLUSTER_THRESHOLD = 3" in src,
        detail=(
            "cloud_diversity.py no longer pins "
            "DEFAULT_CLUSTER_THRESHOLD=3 — the K-of-N threshold (and "
            "therefore the per-cloud cap N-K=2) has shifted."
        ),
    )
    _require(
        report, nss="NSS-1",
        rule="known-cloud-providers-includes-marquee",
        condition=(
            '"aws"' in src and '"gcp"' in src and '"azure"' in src
        ),
        detail=(
            "cloud_diversity.py no longer recognises one of the marquee "
            "providers (aws / gcp / azure) — a node sitting on that "
            "provider now silently buckets as `unknown:<label>` and may "
            "not trigger the per-provider cap correctly."
        ),
    )


def check_nss2_signer_enforcement(report: Report) -> None:
    """NSS-2 — mainnet HSM-only signing enforcement present + classifier pinned."""
    report.checked.append("NSS-2 mainnet HSM-only signing enforcement")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "signer_enforcement.py"
    )
    _require(
        report, nss="NSS-2",
        rule="signer-enforcement-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/signer_enforcement.py is missing — the "
            "NSS-2 mainnet HSM-only signing enforcement has been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, nss="NSS-2",
        rule="classify-signer-defined",
        condition="def classify_signer" in src,
        detail=(
            "signer_enforcement.py no longer defines classify_signer — "
            "the per-signer bucketing helper is gone."
        ),
    )
    _require(
        report, nss="NSS-2",
        rule="verify-production-signer-defined",
        condition="def verify_production_signer" in src,
        detail=(
            "signer_enforcement.py no longer defines "
            "verify_production_signer — the pure verifier is gone."
        ),
    )
    _require(
        report, nss="NSS-2",
        rule="enforce-production-signer-defined",
        condition="def enforce_production_signer" in src,
        detail=(
            "signer_enforcement.py no longer defines "
            "enforce_production_signer — the fail-closed boot wrapper is "
            "gone, so a misconfigured deploy can ship an in-process key "
            "to mainnet again."
        ),
    )
    _require(
        report, nss="NSS-2",
        rule="env-opt-in-name-pinned",
        condition='ENV_INPROCESS_SIGNER_OK = "HELIXOR_INPROCESS_SIGNER_OK"' in src,
        detail=(
            "signer_enforcement.py no longer pins the opt-in env var name "
            "as HELIXOR_INPROCESS_SIGNER_OK — the documented HSM-outage "
            "opt-in path is broken."
        ),
    )
    _require(
        report, nss="NSS-2",
        rule="bucket-constants-pinned",
        condition=(
            'SIGNER_BUCKET_IN_PROCESS = "in-process"' in src
            and 'SIGNER_BUCKET_HSM = "hsm"' in src
            and 'SIGNER_BUCKET_UNKNOWN = "unknown"' in src
        ),
        detail=(
            "signer_enforcement.py no longer pins the bucket label "
            "constants (in-process / hsm / unknown) — the boot log greps "
            "and audit reports rely on those literals."
        ),
    )
    _require(
        report, nss="NSS-2",
        rule="hsm-suffix-rule-present",
        condition='endswith("HSMSigner")' in src,
        detail=(
            "signer_enforcement.py no longer applies the `HSMSigner` "
            "suffix rule — a new YubiHSMSigner subclass would silently "
            "fall through to the `unknown` bucket and be refused on "
            "mainnet."
        ),
    )

    # Cross-check: the VULN-25 signer surface still exists. Without it,
    # the enforcement module has nothing to classify.
    signer_src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "cluster" / "signer.py"
    )
    _require(
        report, nss="NSS-2",
        rule="signer-surface-present",
        condition=(
            signer_src is not None
            and "class InProcessSigner" in signer_src
            and "class HSMSigner" in signer_src
        ),
        detail=(
            "helixor-oracle/oracle/cluster/signer.py no longer defines "
            "both InProcessSigner and HSMSigner — the NSS-2 classifier "
            "has nothing to discriminate."
        ),
    )


def check_nss3_agent_age_gate(report: Report) -> None:
    """NSS-3 — cluster-side agent-registration-age floor for GREEN certs."""
    report.checked.append("NSS-3 cluster-side agent-age floor for GREEN")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "agent_age_gate.py"
    )
    _require(
        report, nss="NSS-3",
        rule="agent-age-gate-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/agent_age_gate.py is missing — the "
            "NSS-3 cluster-side agent-age floor for GREEN certs has been "
            "removed."
        ),
    )
    if src is None:
        return

    _require(
        report, nss="NSS-3",
        rule="verify-agent-age-defined",
        condition="def verify_agent_age_for_tier" in src,
        detail=(
            "agent_age_gate.py no longer defines verify_agent_age_for_tier."
        ),
    )
    _require(
        report, nss="NSS-3",
        rule="enforce-agent-age-defined",
        condition="def enforce_agent_age_for_tier" in src,
        detail=(
            "agent_age_gate.py no longer defines enforce_agent_age_for_tier "
            "— the fail-closed wrapper used by the cluster pre-issue "
            "hook is gone."
        ),
    )
    _require(
        report, nss="NSS-3",
        rule="min-seconds-floor-14-days",
        condition="MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14 * 24 * 3600" in src,
        detail=(
            "agent_age_gate.py no longer pins "
            "MIN_AGENT_AGE_SECONDS_FOR_GREEN=14*24*3600 — the 14-day "
            "wall-clock floor for first-GREEN issuance has shifted; "
            "Scenario B step 4 is operationally re-enabled."
        ),
    )
    _require(
        report, nss="NSS-3",
        rule="min-epochs-floor-168",
        condition="MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168" in src,
        detail=(
            "agent_age_gate.py no longer pins "
            "MIN_AGENT_AGE_EPOCHS_FOR_GREEN=168 — the 168-epoch floor "
            "(14 days at 2h cadence) has shifted; a cluster running "
            "faster than canonical can evade NSS-3."
        ),
    )
    _require(
        report, nss="NSS-3",
        rule="gated-tier-green",
        condition='GATED_TIER_GREEN = "GREEN"' in src,
        detail=(
            "agent_age_gate.py no longer pins GATED_TIER_GREEN=\"GREEN\" "
            "— the tier the gate cares about has shifted."
        ),
    )
    _require(
        report, nss="NSS-3",
        rule="time-travel-reason-defined",
        condition='REASON_TIME_TRAVEL = "AGENT_REGISTERED_IN_FUTURE"' in src,
        detail=(
            "agent_age_gate.py no longer carries the time-travel reason "
            "code — a future-dated registration would now silently fall "
            "through to the seconds-too-young branch and the operator "
            "would lose the structural-failure signal."
        ),
    )

    # Cross-check: the SDK-side VULN-23 consumer freshness gate must
    # still ship. NSS-3 is the cluster-side counterpart and the two are
    # designed to be applied in lockstep — losing the consumer gate
    # turns NSS-3 into a single point of enforcement.
    reader_src = _read(
        REPO_ROOT / "helixor-sdk" / "src" / "lib" / "cert_reader.ts"
    )
    if reader_src is not None:
        # Soft check — VULN-23 lives in another repo subtree, so we only
        # flag a missing constant rather than block the gate. Hard
        # findings are reserved for NSS-3's own substrate.
        if "MIN_HISTORY_REQUIRED" not in reader_src:
            report.findings.append(Finding(
                nss="NSS-3",
                severity="SOFT",
                rule="vuln23-consumer-freshness-present",
                detail=(
                    "helixor-sdk/src/lib/cert_reader.ts no longer "
                    "references MIN_HISTORY_REQUIRED — the consumer-side "
                    "VULN-23 freshness contract that complements NSS-3 "
                    "appears to have shifted. Cluster-side NSS-3 still "
                    "fires, but defence-in-depth is reduced."
                ),
            ))


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_nss1_cloud_diversity(report)
    check_nss2_signer_enforcement(report)
    check_nss3_agent_age_gate(report)
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
            f"nation_state_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nNation-State Silent Subversion audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.nss}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
