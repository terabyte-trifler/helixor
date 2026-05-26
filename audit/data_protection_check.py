#!/usr/bin/env python3
"""
audit/data_protection_check.py — DP-1 data-protection compliance gate.

The substrate is `helixor-oracle/oracle/data_protection_policy.py`,
which declares the `DataCategory × StorageLocation → RetentionPolicy`
table the privacy notice + DSAR handlers consume. This gate is the
mechanical regression alarm: if a refactor quietly drops a category,
weakens the erasability biconditional, or lets the TimescaleDB /
Prometheus retention ceilings drift from the policy declaration,
this lights red BEFORE mainnet.

WHAT IT VERIFIES
----------------
1. The `data_protection_policy` module exists at the expected path.
2. The module exports the audit-pinned public surface: `DataCategory`,
   `LawfulBasis`, `StorageLocation`, `RetentionPolicy`,
   `RETENTION_POLICIES`, plus the helper functions.
3. Every `DataCategory` member has at least one declared policy.
4. The erasability biconditional holds:
     erasure_supported == not is_on_chain(storage_location)
   except for the one explicit carve-out (REFUSAL_LOG, off-chain
   non-erasable, justified by the OFAC-1 transparency invariant).
5. The TimescaleDB migration `0009_timescaledb.sql` still pins
   `INTERVAL '180 days'` for `agent_transactions`, matching
   `TIMESCALE_TRANSACTION_RETENTION_SECONDS`.
6. The docker-compose Prometheus retention still pins `30d`,
   matching `PROMETHEUS_RETENTION_SECONDS`.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` after the cert-refusal gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Audit-pinned values — the canonical retention numbers the substrate
# must match against the actual config files.
# =============================================================================

PINNED_TIMESCALE_TRANSACTION_DAYS = 180
PINNED_PROMETHEUS_RETENTION_FLAG  = "--storage.tsdb.retention.time=30d"
PINNED_PROMETHEUS_RETENTION_DAYS  = 30


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
    """The DP-1 policy module must exist."""
    path = REPO_ROOT / "helixor-oracle" / "oracle" / "data_protection_policy.py"
    report.checked.append(str(path.relative_to(REPO_ROOT)))
    if not path.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.substrate-exists",
            detail=(
                f"missing {path.relative_to(REPO_ROOT)} — DP-1 data-"
                f"protection compliance cannot fire without the substrate"
            ),
        ))


def _check_oracle_public_surface(report: Report) -> None:
    """The policy module must export the audit-pinned symbols."""
    import importlib
    import sys as _sys
    oracle_root = REPO_ROOT / "helixor-oracle"
    if str(oracle_root) not in _sys.path:
        _sys.path.insert(0, str(oracle_root))
    try:
        module = importlib.import_module("oracle.data_protection_policy")
    except Exception as exc:
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.module-importable",
            detail=f"data_protection_policy not importable: {exc!r}",
        ))
        return

    report.checked.append("oracle.data_protection_policy:exports")
    required = {
        "DataCategory", "LawfulBasis", "StorageLocation",
        "RetentionPolicy", "RETENTION_POLICIES",
        "get_policy", "erasable_policies", "non_erasable_policies",
        "is_on_chain",
        "TIMESCALE_TRANSACTION_RETENTION_SECONDS",
        "PROMETHEUS_RETENTION_SECONDS",
        "DataProtectionError",
    }
    missing = sorted(required - set(getattr(module, "__all__", [])))
    if missing:
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.public-surface",
            detail=(
                f"oracle.data_protection_policy.__all__ is missing "
                f"required symbols: {missing}"
            ),
        ))

    # Every DataCategory member must have at least one policy.
    DataCategory = getattr(module, "DataCategory", None)
    StorageLocation = getattr(module, "StorageLocation", None)
    policies = getattr(module, "RETENTION_POLICIES", None)
    if DataCategory is None or StorageLocation is None or policies is None:
        return

    report.checked.append("oracle.data_protection_policy:every-category-covered")
    covered = {p.category for p in policies.values()}
    missing_cats = sorted(set(DataCategory) - covered, key=lambda m: m.value)
    if missing_cats:
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.every-category-covered",
            detail=(
                f"DataCategory members without any declared "
                f"RetentionPolicy: {[m.value for m in missing_cats]}. "
                f"Every category must be wired into RETENTION_POLICIES."
            ),
        ))

    # Erasability biconditional. The only allowed exception is the
    # REFUSAL_LOG carve-out (off-chain, non-erasable, justified by
    # the OFAC-1 transparency invariant).
    report.checked.append("oracle.data_protection_policy:erasability-biconditional")
    is_on_chain = getattr(module, "is_on_chain")
    REFUSAL_LOG = getattr(DataCategory, "REFUSAL_LOG")
    for key, policy in policies.items():
        cat, loc = key
        on_chain = is_on_chain(loc)
        if on_chain and policy.erasure_supported:
            report.findings.append(Finding(
                severity="HARD",
                rule="DP-1.erasability-biconditional",
                detail=(
                    f"{cat.value} on {loc.value} declares "
                    f"erasure_supported=True, but on-chain data is "
                    f"structurally non-erasable"
                ),
            ))
        if (
            not on_chain
            and not policy.erasure_supported
            and cat is not REFUSAL_LOG
        ):
            report.findings.append(Finding(
                severity="HARD",
                rule="DP-1.erasability-biconditional",
                detail=(
                    f"{cat.value} on {loc.value} declares "
                    f"erasure_supported=False, but off-chain data must "
                    f"be erasable unless explicitly carved out. Today "
                    f"only REFUSAL_LOG is carved out."
                ),
            ))


def _check_timescale_retention_matches(report: Report) -> None:
    """The TimescaleDB migration must still pin 180 days for agent_transactions."""
    path = (
        REPO_ROOT / "helixor-oracle" / "db" / "migrations"
        / "0009_timescaledb.sql"
    )
    report.checked.append(str(path.relative_to(REPO_ROOT)))
    if not path.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.timescale-migration-present",
            detail=(
                f"missing {path.relative_to(REPO_ROOT)} — the canonical "
                f"180-day retention pin lives here"
            ),
        ))
        return

    text = path.read_text()
    # Look for "INTERVAL '180 days'" (sql whitespace-flexible).
    pattern = re.compile(
        r"add_retention_policy\s*\(\s*'agent_transactions'\s*,"
        r"\s*INTERVAL\s+'(\d+)\s+days'",
        re.IGNORECASE,
    )
    match = pattern.search(text)
    if match is None:
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.timescale-retention-pinned",
            detail=(
                "0009_timescaledb.sql no longer calls "
                "add_retention_policy('agent_transactions', INTERVAL "
                "'N days', ...). The DP-1 substrate's "
                "TIMESCALE_TRANSACTION_RETENTION_SECONDS would diverge "
                "from the actual hypertable behaviour."
            ),
        ))
        return

    declared_days = int(match.group(1))
    if declared_days != PINNED_TIMESCALE_TRANSACTION_DAYS:
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.timescale-retention-matches-policy",
            detail=(
                f"0009_timescaledb.sql declares "
                f"agent_transactions retention = {declared_days} days, "
                f"but DP-1 substrate pins "
                f"{PINNED_TIMESCALE_TRANSACTION_DAYS} days. The two "
                f"must match or the privacy notice's retention table "
                f"misrepresents reality."
            ),
        ))


def _check_prometheus_retention_matches(report: Report) -> None:
    """The docker-compose Prometheus retention flag must still pin 30d."""
    path = (
        REPO_ROOT / "launch" / "deploy" / "docker-compose.indexer.yml"
    )
    report.checked.append(str(path.relative_to(REPO_ROOT)))
    if not path.is_file():
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.prometheus-compose-present",
            detail=(
                f"missing {path.relative_to(REPO_ROOT)} — the canonical "
                f"30-day Prometheus retention pin lives here"
            ),
        ))
        return

    text = path.read_text()
    if PINNED_PROMETHEUS_RETENTION_FLAG not in text:
        # Try to surface what value IS declared so the finding is
        # actionable rather than just "missing flag".
        m = re.search(
            r"--storage\.tsdb\.retention\.time=(\d+)([dhm])",
            text,
        )
        actual = f"{m.group(1)}{m.group(2)}" if m else "<absent>"
        report.findings.append(Finding(
            severity="HARD",
            rule="DP-1.prometheus-retention-matches-policy",
            detail=(
                f"docker-compose.indexer.yml no longer pins "
                f"{PINNED_PROMETHEUS_RETENTION_FLAG!r}; found "
                f"{actual!r}. DP-1 substrate pins "
                f"{PINNED_PROMETHEUS_RETENTION_DAYS} days."
            ),
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
    _check_timescale_retention_matches(report)
    _check_prometheus_retention_matches(report)

    text = report.to_json()
    if args.json == "-" or args.json == "":
        sys.stdout.write(text + "\n")
    else:
        Path(args.json).write_text(text + "\n")

    return 1 if report.hard() else 0


if __name__ == "__main__":
    sys.exit(main())
