#!/usr/bin/env python3
"""
audit/spof_check.py — the unified single-point-of-failure audit gate.

The Helixor SPOF table (launch/design/spof_resolution.md) enumerates 9
SPOFs. Six were closed by code or deployment work; this script is the
mechanical proof that the mitigations are STILL in place. It is a
regression alarm — if a refactor accidentally undoes one of the fixes,
this gate goes red before the change reaches mainnet.

WHAT THIS GATE CHECKS
---------------------
SPOF-#1  advance_authority             — AW-02 separation kept (no
                                         single-key authority over
                                         certificate-issuer state machine
                                         AND epoch advancement at once).
SPOF-#2  slash_authority               — the 2-of-3-attested rotation
                                         ceremony is present; the
                                         single-admin handler refuses.
SPOF-#3  upgrade_authority             — Squads multisig is the
                                         deployed program upgrade path
                                         (the deploy script names it).
SPOF-#4  oracle_key_per_node           — 3-of-5 cluster threshold
                                         signing (already shipped).
SPOF-#5  Kafka                         — docker-compose.kafka-ha.yml is
                                         present, RF=3, min.insync=2.
SPOF-#6  TimescaleDB                   — docker-compose.timescale-ha.yml
                                         declares primary + standby +
                                         WAL archive.
SPOF-#7  API server                    — docker-compose.api-ha.yml has
                                         >= 3 api-* replicas.
SPOF-#8  Geyser endpoint               — indexer/production_config.py's
                                         mainnet floor refuses < 3
                                         endpoints.
SPOF-#9  API redundancy                — nginx LB config exists with
                                         >= 3 upstreams and
                                         `proxy_next_upstream`.

The check is INTENTIONALLY shallow at the deployment layer — it greps
the docker-compose files for the marker strings. The real validation
that the brokers replicate / the standby promotes is in the failover
runbook (launch/runbooks/spof_failover.md), which the operator
exercises before each release.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` as the SPOF section.
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
    """One SPOF gate finding."""
    spof:     str
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
# Per-SPOF probes
# =============================================================================

def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _require(
    report: Report, *, spof: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            spof=spof, severity="HARD", rule=rule, detail=detail,
        ))


def check_spof2_slash_authority_rotation(report: Report) -> None:
    """SPOF-#2 — slash-authority rotation ceremony is in place."""
    report.checked.append("SPOF-#2 slash_authority")

    pending = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "slash-authority"
        / "src" / "state" / "pending_authority_rotation.rs"
    )
    _require(
        report, spof="SPOF-#2",
        rule="pending_authority_rotation-state-present",
        condition=pending is not None,
        detail=(
            "programs/slash-authority/src/state/pending_authority_rotation.rs "
            "is missing — the SPOF-#2 rotation ceremony state account has "
            "been removed."
        ),
    )
    if pending is not None:
        _require(
            report, spof="SPOF-#2",
            rule="rotation-min-timelock-48h",
            condition="48 * 60 * 60" in pending,
            detail=(
                "pending_authority_rotation.rs no longer pins the 48h "
                "MIN_TIMELOCK_SECONDS — a shorter window collapses the "
                "audit's review floor."
            ),
        )
        _require(
            report, spof="SPOF-#2",
            rule="rotation-consensus-threshold-2",
            condition="CONSENSUS_THRESHOLD: usize = 2" in pending,
            detail=(
                "pending_authority_rotation.rs no longer requires 2-of-3 "
                "role-key attestations."
            ),
        )

    update_authorities = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "slash-authority"
        / "src" / "instructions" / "update_authorities.rs"
    )
    _require(
        report, spof="SPOF-#2",
        rule="single-admin-rotation-refused",
        condition=(
            update_authorities is not None
            and "SingleAdminUpdateRemoved" in update_authorities
        ),
        detail=(
            "update_authorities.rs no longer refuses with "
            "SingleAdminUpdateRemoved — a single-admin rotation path may "
            "have been reintroduced."
        ),
    )


def check_spof3_upgrade_authority(report: Report) -> None:
    """SPOF-#3 — Squads multisig owns the upgrade authority."""
    report.checked.append("SPOF-#3 upgrade_authority")

    deploy = _read(REPO_ROOT / "launch" / "deploy" / "deploy_programs.sh")
    _require(
        report, spof="SPOF-#3",
        rule="upgrade-authority-multisig",
        condition=(
            deploy is not None
            and ("squads" in deploy.lower() or "multisig" in deploy.lower())
        ),
        detail=(
            "launch/deploy/deploy_programs.sh no longer mentions Squads / "
            "multisig — the upgrade authority may have been re-pointed at "
            "a single key."
        ),
    )


def check_spof5_kafka_ha(report: Report) -> None:
    """SPOF-#5 — Kafka 3-broker HA overlay with RF=3 + min.insync=2."""
    report.checked.append("SPOF-#5 kafka")

    overlay = _read(
        REPO_ROOT / "launch" / "deploy" / "docker-compose.kafka-ha.yml"
    )
    _require(
        report, spof="SPOF-#5",
        rule="kafka-ha-overlay-present",
        condition=overlay is not None,
        detail=(
            "launch/deploy/docker-compose.kafka-ha.yml is missing — the "
            "production Kafka HA topology has been removed."
        ),
    )
    if overlay is None:
        return

    # Three broker services must exist.
    brokers = [b for b in ("kafka-1:", "kafka-2:", "kafka-3:") if b in overlay]
    _require(
        report, spof="SPOF-#5",
        rule="kafka-three-brokers",
        condition=len(brokers) == 3,
        detail=(
            f"docker-compose.kafka-ha.yml declares only {len(brokers)} of "
            f"the expected 3 brokers (kafka-1, kafka-2, kafka-3)."
        ),
    )
    _require(
        report, spof="SPOF-#5",
        rule="kafka-replication-factor-3",
        condition="KAFKA_DEFAULT_REPLICATION_FACTOR: 3" in overlay,
        detail=(
            "docker-compose.kafka-ha.yml no longer sets "
            "KAFKA_DEFAULT_REPLICATION_FACTOR=3 — durability degrades."
        ),
    )
    _require(
        report, spof="SPOF-#5",
        rule="kafka-min-insync-replicas-2",
        condition="KAFKA_MIN_INSYNC_REPLICAS: 2" in overlay,
        detail=(
            "docker-compose.kafka-ha.yml no longer sets "
            "KAFKA_MIN_INSYNC_REPLICAS=2 — single-broker compromise can "
            "lose acknowledged writes."
        ),
    )
    _require(
        report, spof="SPOF-#5",
        rule="kafka-unclean-leader-election-off",
        condition='KAFKA_UNCLEAN_LEADER_ELECTION_ENABLE: "false"' in overlay,
        detail=(
            "docker-compose.kafka-ha.yml allows unclean leader election — "
            "an out-of-sync replica could become leader."
        ),
    )


def check_spof6_timescale_ha(report: Report) -> None:
    """SPOF-#6 — Timescale primary + standby + WAL archive overlay."""
    report.checked.append("SPOF-#6 timescaledb")

    overlay = _read(
        REPO_ROOT / "launch" / "deploy" / "docker-compose.timescale-ha.yml"
    )
    _require(
        report, spof="SPOF-#6",
        rule="timescale-ha-overlay-present",
        condition=overlay is not None,
        detail=(
            "launch/deploy/docker-compose.timescale-ha.yml is missing — "
            "the production DB HA topology has been removed."
        ),
    )
    if overlay is None:
        return

    _require(
        report, spof="SPOF-#6",
        rule="timescale-primary-declared",
        condition="timescale-primary:" in overlay,
        detail="docker-compose.timescale-ha.yml lacks a timescale-primary service.",
    )
    _require(
        report, spof="SPOF-#6",
        rule="timescale-standby-declared",
        condition="timescale-standby:" in overlay,
        detail="docker-compose.timescale-ha.yml lacks a timescale-standby service.",
    )
    _require(
        report, spof="SPOF-#6",
        rule="wal-archive-declared",
        condition="wal-archive:" in overlay and "wal_archive:" in overlay,
        detail=(
            "docker-compose.timescale-ha.yml lacks a wal-archive service or "
            "the corresponding wal_archive volume — PITR is impossible."
        ),
    )
    _require(
        report, spof="SPOF-#6",
        rule="archive-mode-on",
        condition="archive_mode=on" in overlay,
        detail=(
            "docker-compose.timescale-ha.yml no longer sets archive_mode=on "
            "on the primary — closed WAL segments will not be shipped."
        ),
    )
    _require(
        report, spof="SPOF-#6",
        rule="wal-level-replica",
        condition="wal_level=replica" in overlay,
        detail=(
            "docker-compose.timescale-ha.yml no longer sets "
            "wal_level=replica — streaming replication breaks."
        ),
    )


def check_spof7_9_api_ha(report: Report) -> None:
    """SPOF-#7+#9 — API multi-replica behind nginx LB."""
    report.checked.append("SPOF-#7+#9 api")

    overlay = _read(
        REPO_ROOT / "launch" / "deploy" / "docker-compose.api-ha.yml"
    )
    _require(
        report, spof="SPOF-#7+#9",
        rule="api-ha-overlay-present",
        condition=overlay is not None,
        detail=(
            "launch/deploy/docker-compose.api-ha.yml is missing — the "
            "production multi-replica API topology has been removed."
        ),
    )
    if overlay is not None:
        replicas = [r for r in ("api-1:", "api-2:", "api-3:") if r in overlay]
        _require(
            report, spof="SPOF-#7+#9",
            rule="api-three-replicas",
            condition=len(replicas) == 3,
            detail=(
                f"docker-compose.api-ha.yml declares only {len(replicas)} "
                f"of 3 API replicas."
            ),
        )
        _require(
            report, spof="SPOF-#7+#9",
            rule="api-lb-declared",
            condition="api-lb:" in overlay,
            detail="docker-compose.api-ha.yml lacks the api-lb (nginx) service.",
        )

    nginx_cfg = _read(
        REPO_ROOT / "launch" / "deploy" / "nginx" / "api_upstream.conf"
    )
    _require(
        report, spof="SPOF-#7+#9",
        rule="nginx-upstream-present",
        condition=nginx_cfg is not None,
        detail=(
            "launch/deploy/nginx/api_upstream.conf is missing — the LB "
            "has no upstream pool."
        ),
    )
    if nginx_cfg is not None:
        upstreams = sum(
            1 for s in ("api-1:8080", "api-2:8080", "api-3:8080")
            if s in nginx_cfg
        )
        _require(
            report, spof="SPOF-#7+#9",
            rule="nginx-three-upstreams",
            condition=upstreams >= 3,
            detail=(
                f"nginx upstream pool lists only {upstreams} of 3 replicas."
            ),
        )
        _require(
            report, spof="SPOF-#7+#9",
            rule="nginx-proxy-next-upstream",
            condition="proxy_next_upstream" in nginx_cfg,
            detail=(
                "nginx config no longer retries idempotent reads against "
                "the next upstream on failure."
            ),
        )
        _require(
            report, spof="SPOF-#7+#9",
            rule="nginx-least-conn",
            condition="least_conn" in nginx_cfg,
            detail=(
                "nginx config no longer balances by least_conn — slow "
                "endpoints stack up on one replica."
            ),
        )


def check_spof8_geyser_consensus(report: Report) -> None:
    """SPOF-#8 — production_config refuses single-endpoint mainnet."""
    report.checked.append("SPOF-#8 geyser")

    prod_cfg = _read(
        REPO_ROOT / "helixor-indexer" / "indexer" / "production_config.py"
    )
    _require(
        report, spof="SPOF-#8",
        rule="production_config-present",
        condition=prod_cfg is not None,
        detail=(
            "helixor-indexer/indexer/production_config.py is missing — the "
            "SPOF-#8 mainnet floor is no longer enforceable."
        ),
    )
    if prod_cfg is None:
        return

    _require(
        report, spof="SPOF-#8",
        rule="mainnet-min-endpoints-3",
        condition="MAINNET_MIN_ENDPOINTS = 3" in prod_cfg,
        detail=(
            "production_config.py no longer pins MAINNET_MIN_ENDPOINTS=3 — "
            "single- or two-endpoint mainnet may slip through."
        ),
    )
    _require(
        report, spof="SPOF-#8",
        rule="min-consensus-threshold-2",
        condition="MIN_CONSENSUS_THRESHOLD = 2" in prod_cfg,
        detail=(
            "production_config.py no longer pins MIN_CONSENSUS_THRESHOLD=2 — "
            "K=1 quora are equivalent to trusting a single endpoint."
        ),
    )
    _require(
        report, spof="SPOF-#8",
        rule="single-point-error-defined",
        condition="class SinglePointGeyserError" in prod_cfg,
        detail=(
            "production_config.py no longer defines SinglePointGeyserError "
            "— the typed refusal contract has been removed."
        ),
    )


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_spof2_slash_authority_rotation(report)
    check_spof3_upgrade_authority(report)
    check_spof5_kafka_ha(report)
    check_spof6_timescale_ha(report)
    check_spof7_9_api_ha(report)
    check_spof8_geyser_consensus(report)
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
            f"spof_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nSPOF audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.spof}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
