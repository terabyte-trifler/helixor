#!/usr/bin/env python3
"""
audit/freeze_cert_check.py — the unified FREEZE-CERT-AT-HIGH-SCORE
audit gate.

The red-team attack tree's Path 3 (root: "Drain DeFi Protocol
Integrated with Phylanx") is "Freeze Cert at High Score" — three
sub-leaves:

  3a. Exploit VULN-05 (commit-reveal block)              [LOW EFFORT]
  3b. Exploit VULN-02 (epoch advancement freeze)         [MEDIUM EFFORT]
  3c. Target DeFi protocol that doesn't check cert
      freshness                                          [LOW EFFORT]

Each sub-leaf has an EXISTING defence on-chain or in the existing
cluster code; what was missing pre-FRP was a CLUSTER-side refusal to
KEEP MINTING new certs against a stalled substrate. The on-chain
checks fail closed only after a long ceiling (TA-6 = 48h); the
cluster needs to fail closed sooner, on its own initiative, in the
gap between attack-start and on-chain ceiling.

  FRP-1  Cluster participation floor                  refuses cert
                                                      issuance when
                                                      the cluster's
                                                      trailing run
                                                      of barely-
                                                      quorate rounds
                                                      exceeds the
                                                      cap (3
                                                      consecutive
                                                      bare-quorum
                                                      rounds).
  FRP-2  Epoch-advance liveness floor                 refuses cert
                                                      issuance when
                                                      the cluster
                                                      hasn't
                                                      advanced its
                                                      epoch in >36h
                                                      (1.5× the 24h
                                                      cycle), well
                                                      before AW-02
                                                      Tier-2
                                                      fallback
                                                      engages at 2×
                                                      duration.
  FRP-3  Cert-reissue cadence floor                   refuses high-
                                                      tier vouching
                                                      when a given
                                                      agent's cert
                                                      hasn't been
                                                      reissued in
                                                      >4h (12× safety
                                                      margin against
                                                      TA-6's 48h
                                                      on-chain
                                                      ceiling) — the
                                                      cluster-side
                                                      promise that
                                                      closes the
                                                      freshness-blind
                                                      DeFi consumer
                                                      residual.

Each is closed by a real module committed into the repo
(`oracle/cluster_participation_floor.py`,
`oracle/epoch_advance_liveness.py`,
`oracle/cert_reissue_cadence.py`). This gate is the mechanical
regression alarm: it greps each marker so a refactor that quietly
removes a mitigation lights this red BEFORE mainnet. It ALSO
cross-checks the existing anchors for VULN-05
(`phylanx-oracle/oracle/cluster/commit_reveal_round.py` —
`submit_reveal` + `non_revealers` + `reveal_deadline` +
`min_reveals`), VULN-02
(`phylanx-programs/programs/health-oracle/src/instructions/
advance_epoch.rs` — `verify_advance_attestations` +
`InsufficientAdvanceAttestations` and
`phylanx-programs/programs/health-oracle/src/state/epoch_state.rs` —
`DEFAULT_DURATION_SECONDS`), and TA-6
(`phylanx-programs/programs/certificate-issuer/src/state/
health_certificate.rs` — `MAX_AGE_SECONDS = 48 * 60 * 60`) so a
regression on any existing anchor lights this gate too.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the ILS
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
    """One freeze-cert gate finding."""
    frp:      str
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
    report: Report, *, frp: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            frp=frp, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-FRP probes
# =============================================================================

def check_frp1_cluster_participation_floor(report: Report) -> None:
    """FRP-1 — cluster participation floor."""
    report.checked.append(
        "FRP-1 cluster participation floor "
        "(VULN-05 commit-reveal anchor)"
    )

    src = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle"
        / "cluster_participation_floor.py"
    )
    _require(
        report, frp="FRP-1",
        rule="cluster-participation-floor-module-present",
        condition=src is not None,
        detail=(
            "phylanx-oracle/oracle/cluster_participation_floor.py is "
            "missing — the FRP-1 cluster-participation floor has been "
            "removed; an attacker who withholds commit-reveal shares "
            "can keep the cluster minting certs at minimum quorum "
            "indefinitely."
        ),
    )
    if src is None:
        return

    _require(
        report, frp="FRP-1",
        rule="verify-cluster-participation-floor-defined",
        condition="def verify_cluster_participation_floor" in src,
        detail=(
            "cluster_participation_floor.py no longer defines "
            "verify_cluster_participation_floor."
        ),
    )
    _require(
        report, frp="FRP-1",
        rule="enforce-cluster-participation-floor-defined",
        condition="def enforce_cluster_participation_floor" in src,
        detail=(
            "cluster_participation_floor.py no longer defines "
            "enforce_cluster_participation_floor — the fail-closed "
            "wrapper is gone."
        ),
    )
    _require(
        report, frp="FRP-1",
        rule="min-healthy-participation-ratio-0.8",
        condition="MIN_HEALTHY_PARTICIPATION_RATIO = 0.8" in src,
        detail=(
            "cluster_participation_floor.py no longer pins "
            "MIN_HEALTHY_PARTICIPATION_RATIO=0.8 — the healthy "
            "participation ratio floor has shifted."
        ),
    )
    _require(
        report, frp="FRP-1",
        rule="max-barely-quorate-rounds-3",
        condition="MAX_BARELY_QUORATE_ROUNDS = 3" in src,
        detail=(
            "cluster_participation_floor.py no longer pins "
            "MAX_BARELY_QUORATE_ROUNDS=3 — the trailing barely-"
            "quorate run cap has shifted; a sustained-withholding "
            "attack would slip past."
        ),
    )
    _require(
        report, frp="FRP-1",
        rule="barely-quorate-margin-1",
        condition="BARELY_QUORATE_MARGIN = 1" in src,
        detail=(
            "cluster_participation_floor.py no longer pins "
            "BARELY_QUORATE_MARGIN=1 — the +1 margin above "
            "quorum_threshold defines what counts as 'barely "
            "quorate' and must not drift silently."
        ),
    )
    _require(
        report, frp="FRP-1",
        rule="participation-status-labels-pinned",
        condition=(
            'PARTICIPATION_OK = "OK"' in src
            and 'PARTICIPATION_REFUSED = "REFUSED"' in src
        ),
        detail=(
            "cluster_participation_floor.py no longer pins the "
            "status labels (OK / REFUSED) — operator dashboards and "
            "audit gates grep these literals."
        ),
    )

    # Cross-check: VULN-05's existing commit-reveal anchor must still
    # ship.
    commit_reveal = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle" / "cluster"
        / "commit_reveal_round.py"
    )
    if commit_reveal is not None:
        _require(
            report, frp="FRP-1",
            rule="vuln05-commit-reveal-anchor-present",
            condition=(
                "submit_reveal" in commit_reveal
                and "non_revealers" in commit_reveal
                and "reveal_deadline" in commit_reveal
                and "min_reveals" in commit_reveal
            ),
            detail=(
                "commit_reveal_round.py no longer ships the VULN-05 "
                "anchor (submit_reveal + non_revealers + "
                "reveal_deadline + min_reveals) — FRP-1 is the "
                "fleet-wide pre-flight and cannot stand alone "
                "without the per-round commit-reveal defence."
            ),
        )
    else:
        report.findings.append(Finding(
            frp="FRP-1", severity="HARD",
            rule="vuln05-commit-reveal-module-present",
            detail=(
                "phylanx-oracle/oracle/cluster/commit_reveal_round.py "
                "is missing — the cluster-side VULN-05 commit-reveal "
                "module has been removed."
            ),
        ))


def check_frp2_epoch_advance_liveness(report: Report) -> None:
    """FRP-2 — epoch-advance liveness floor."""
    report.checked.append(
        "FRP-2 epoch-advance liveness floor "
        "(VULN-02 on-chain anchor)"
    )

    src = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle"
        / "epoch_advance_liveness.py"
    )
    _require(
        report, frp="FRP-2",
        rule="epoch-advance-liveness-module-present",
        condition=src is not None,
        detail=(
            "phylanx-oracle/oracle/epoch_advance_liveness.py is "
            "missing — the FRP-2 epoch-advance liveness floor has "
            "been removed; an attacker who withholds advance "
            "attestations can freeze the cluster's epoch indefinitely "
            "and the cluster will keep minting certs against the "
            "frozen epoch."
        ),
    )
    if src is None:
        return

    _require(
        report, frp="FRP-2",
        rule="verify-epoch-advance-liveness-defined",
        condition="def verify_epoch_advance_liveness" in src,
        detail=(
            "epoch_advance_liveness.py no longer defines "
            "verify_epoch_advance_liveness."
        ),
    )
    _require(
        report, frp="FRP-2",
        rule="enforce-epoch-advance-liveness-defined",
        condition="def enforce_epoch_advance_liveness" in src,
        detail=(
            "epoch_advance_liveness.py no longer defines "
            "enforce_epoch_advance_liveness — the fail-closed "
            "wrapper is gone."
        ),
    )
    _require(
        report, frp="FRP-2",
        rule="max-epoch-advance-stall-36h",
        condition="MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600" in src,
        detail=(
            "epoch_advance_liveness.py no longer pins "
            "MAX_EPOCH_ADVANCE_STALL_SECONDS=36*3600 — the 1.5×-"
            "epoch-duration stall floor has shifted; either the "
            "cluster fires earlier and stresses honest operation or "
            "later and exposes the gap before AW-02 Tier-2 engages."
        ),
    )
    _require(
        report, frp="FRP-2",
        rule="expected-epoch-duration-24h",
        condition="EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600" in src,
        detail=(
            "epoch_advance_liveness.py no longer pins "
            "EXPECTED_EPOCH_DURATION_SECONDS=24*3600 — the cluster's "
            "view of the canonical epoch duration has drifted out of "
            "lockstep with on-chain DEFAULT_DURATION_SECONDS=86_400."
        ),
    )
    _require(
        report, frp="FRP-2",
        rule="epoch-advance-future-tolerance-60s",
        condition=(
            "EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60" in src
        ),
        detail=(
            "epoch_advance_liveness.py no longer pins "
            "EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS=60 — the 60s "
            "clock-skew tolerance has drifted from the rest of the "
            "cluster's timestamp checks."
        ),
    )
    _require(
        report, frp="FRP-2",
        rule="epoch-advance-status-labels-pinned",
        condition=(
            'EPOCH_ADVANCE_OK = "OK"' in src
            and 'EPOCH_ADVANCE_REFUSED = "REFUSED"' in src
        ),
        detail=(
            "epoch_advance_liveness.py no longer pins the status "
            "labels (OK / REFUSED) — operator dashboards and audit "
            "gates grep these literals."
        ),
    )

    # Cross-check: VULN-02's on-chain anchor must still ship.
    advance = _read(
        REPO_ROOT / "phylanx-programs" / "programs" / "health-oracle"
        / "src" / "instructions" / "advance_epoch.rs"
    )
    if advance is not None:
        _require(
            report, frp="FRP-2",
            rule="vuln02-advance-epoch-anchor-present",
            condition=(
                "verify_cluster_threshold" in advance
                and "InsufficientAdvanceAttestations" in advance
                and "consensus_threshold" in advance
            ),
            detail=(
                "advance_epoch.rs no longer ships the VULN-02 "
                "on-chain anchor (verify_cluster_threshold + "
                "consensus_threshold + InsufficientAdvanceAttestations) "
                "— FRP-2 is the off-chain pre-flight and cannot "
                "stand alone without the M-of-N attestation defence."
            ),
        )
    else:
        report.findings.append(Finding(
            frp="FRP-2", severity="HARD",
            rule="vuln02-advance-epoch-module-present",
            detail=(
                "programs/health-oracle/src/instructions/"
                "advance_epoch.rs is missing — the on-chain VULN-02 "
                "advance-attestation module has been removed."
            ),
        ))

    epoch_state = _read(
        REPO_ROOT / "phylanx-programs" / "programs" / "health-oracle"
        / "src" / "state" / "epoch_state.rs"
    )
    if epoch_state is not None:
        _require(
            report, frp="FRP-2",
            rule="vuln02-default-duration-seconds-86400",
            condition=(
                "DEFAULT_DURATION_SECONDS: i64 = 86_400" in epoch_state
            ),
            detail=(
                "epoch_state.rs no longer pins "
                "DEFAULT_DURATION_SECONDS=86_400 — the canonical "
                "on-chain 24h epoch duration has drifted; FRP-2's "
                "EXPECTED_EPOCH_DURATION_SECONDS calibration "
                "story breaks."
            ),
        )
    else:
        report.findings.append(Finding(
            frp="FRP-2", severity="HARD",
            rule="vuln02-epoch-state-module-present",
            detail=(
                "programs/health-oracle/src/state/epoch_state.rs "
                "is missing — the on-chain epoch-state module has "
                "been removed."
            ),
        ))


def check_frp3_cert_reissue_cadence(report: Report) -> None:
    """FRP-3 — cert-reissue cadence floor."""
    report.checked.append(
        "FRP-3 cert-reissue cadence floor "
        "(TA-6 on-chain anchor)"
    )

    src = _read(
        REPO_ROOT / "phylanx-oracle" / "oracle"
        / "cert_reissue_cadence.py"
    )
    _require(
        report, frp="FRP-3",
        rule="cert-reissue-cadence-module-present",
        condition=src is not None,
        detail=(
            "phylanx-oracle/oracle/cert_reissue_cadence.py is "
            "missing — the FRP-3 cert-reissue cadence floor has "
            "been removed; a freshness-blind DeFi consumer could "
            "continue to lend against a frozen cert for up to TA-6's "
            "48h on-chain ceiling."
        ),
    )
    if src is None:
        return

    _require(
        report, frp="FRP-3",
        rule="verify-cert-reissue-cadence-defined",
        condition="def verify_cert_reissue_cadence" in src,
        detail=(
            "cert_reissue_cadence.py no longer defines "
            "verify_cert_reissue_cadence."
        ),
    )
    _require(
        report, frp="FRP-3",
        rule="enforce-cert-reissue-cadence-defined",
        condition="def enforce_cert_reissue_cadence" in src,
        detail=(
            "cert_reissue_cadence.py no longer defines "
            "enforce_cert_reissue_cadence — the fail-closed "
            "wrapper is gone."
        ),
    )
    _require(
        report, frp="FRP-3",
        rule="max-cert-reissue-interval-4h",
        condition="MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600" in src,
        detail=(
            "cert_reissue_cadence.py no longer pins "
            "MAX_CERT_REISSUE_INTERVAL_SECONDS=4*3600 — the "
            "cluster-side reissue cadence floor has drifted from "
            "SOL-3's LOAN_ISSUE 4h freshness floor."
        ),
    )
    _require(
        report, frp="FRP-3",
        rule="cert-reissue-future-tolerance-60s",
        condition=(
            "CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60" in src
        ),
        detail=(
            "cert_reissue_cadence.py no longer pins "
            "CERT_REISSUE_FUTURE_TOLERANCE_SECONDS=60 — the 60s "
            "clock-skew tolerance has drifted."
        ),
    )
    _require(
        report, frp="FRP-3",
        rule="ta6-onchain-mirror-48h",
        condition="TA6_ONCHAIN_MAX_AGE_SECONDS = 48 * 3600" in src,
        detail=(
            "cert_reissue_cadence.py no longer pins "
            "TA6_ONCHAIN_MAX_AGE_SECONDS=48*3600 — the on-chain "
            "TA-6 mirror constant has drifted out of lockstep with "
            "health_certificate.rs::MAX_AGE_SECONDS, breaking the "
            "12× safety-margin calibration."
        ),
    )
    _require(
        report, frp="FRP-3",
        rule="cert-reissue-status-labels-pinned",
        condition=(
            'CERT_REISSUE_OK = "OK"' in src
            and 'CERT_REISSUE_REFUSED = "REFUSED"' in src
        ),
        detail=(
            "cert_reissue_cadence.py no longer pins the status "
            "labels (OK / REFUSED) — operator dashboards and audit "
            "gates grep these literals."
        ),
    )

    # Cross-check: TA-6's on-chain anchor must still ship.
    cert = _read(
        REPO_ROOT / "phylanx-programs" / "programs" / "certificate-issuer"
        / "src" / "state" / "health_certificate.rs"
    )
    if cert is not None:
        _require(
            report, frp="FRP-3",
            rule="ta6-onchain-anchor-present",
            condition=(
                "MAX_AGE_SECONDS: i64 = 48 * 60 * 60" in cert
                and "is_fresh_default" in cert
            ),
            detail=(
                "health_certificate.rs no longer ships the TA-6 "
                "on-chain anchor (MAX_AGE_SECONDS = 48*60*60 + "
                "is_fresh_default) — FRP-3's 12× safety-margin "
                "calibration is broken and the freshness-blind-"
                "consumer residual reopens."
            ),
        )
    else:
        report.findings.append(Finding(
            frp="FRP-3", severity="HARD",
            rule="ta6-health-certificate-module-present",
            detail=(
                "programs/certificate-issuer/src/state/"
                "health_certificate.rs is missing — the on-chain "
                "TA-6 freshness module has been removed."
            ),
        ))


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_frp1_cluster_participation_floor(report)
    check_frp2_epoch_advance_liveness(report)
    check_frp3_cert_reissue_cadence(report)
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
            f"freeze_cert_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nFreeze-Cert-at-High-Score audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.frp}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
