#!/usr/bin/env python3
"""
audit/version_pinning_check.py — VULN-22 hardening sweep.

Statically verifies the scoring-algorithm-version pin remains wired:

  1. **CommitRequest / RevealRequest carry the version pair.** Both
     dataclasses must expose `scoring_algo_version` AND
     `scoring_weights_version` fields. A future refactor that drops
     either is caught here BEFORE it ships — a missing version field
     reopens the upgrade-induced-liveness attack the audit names.

  2. **Round binds version into the commit hash.** `commit_reveal.py`
     must thread an `algo_version=` kwarg into both
     `compute_commit_hash(...)` and `verify_reveal(...)`. If either
     signature loses the kwarg, a revealer can switch versions between
     commit and reveal without hash mismatch.

  3. **Version-mismatched nodes are SILENTLY EXCLUDED, not Byzantine.**
     `byzantine_runner.py` MUST surface `version_excluded_nodes` in its
     `ByzantineEpochReport`. We also assert it never appends the
     version-mismatched set to `epoch_flags` or `byzantine_this_epoch`
     (a textual grep for the antipattern — a future PR that crosses
     these wires fails this gate).

  4. **`VersionMismatch` is a CommitRejected subclass.** Existing
     `except CommitRejected` paths keep working unchanged, so a
     mid-round version drift is handled (silently excluded) without a
     code path needing to be rebuilt.

REPORTING
---------
Emits a JSON report to `--json` (default stdout) and exits non-zero on
any HARD finding so CI fails the gate. The `audit/run_all.sh` harness
calls this script alongside the other Day-29 sweeps.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# =============================================================================
# Targets — the exact files this audit pins
# =============================================================================

MESSAGES_PY            = REPO_ROOT / "helixor-oracle" / "oracle" / "cluster" / "messages.py"
COMMIT_REVEAL_PY       = REPO_ROOT / "helixor-oracle" / "oracle" / "cluster" / "commit_reveal.py"
COMMIT_REVEAL_ROUND_PY = REPO_ROOT / "helixor-oracle" / "oracle" / "cluster" / "commit_reveal_round.py"
BYZANTINE_RUNNER_PY    = REPO_ROOT / "helixor-oracle" / "oracle" / "cluster" / "byzantine_runner.py"
NODE_PY                = REPO_ROOT / "helixor-oracle" / "oracle" / "node.py"


# =============================================================================
# Findings
# =============================================================================

@dataclass
class Finding:
    severity: str       # "HARD"
    rule:     str
    path:     str
    detail:   str


@dataclass
class Report:
    findings:      list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def hard_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HARD")

    def to_dict(self) -> dict:
        return {
            "files_scanned":  self.files_scanned,
            "findings_total": len(self.findings),
            "findings_hard":  self.hard_count,
            "findings": [
                {
                    "severity": f.severity, "rule": f.rule,
                    "path": f.path, "detail": f.detail,
                }
                for f in self.findings
            ],
        }


# =============================================================================
# Scanners
# =============================================================================

def _display(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _check_messages(report: Report) -> None:
    """CommitRequest + RevealRequest must carry both version fields."""
    if not MESSAGES_PY.exists():
        report.add(Finding(
            severity="HARD", rule="missing-file",
            path=_display(MESSAGES_PY), detail="messages.py not found",
        ))
        return
    report.files_scanned += 1
    text = MESSAGES_PY.read_text()

    for cls in ("CommitRequest", "RevealRequest"):
        # crude but sufficient: find the class block and check the two
        # fields appear inside it. dataclasses don't move around.
        match = re.search(
            rf"class {cls}\b.*?(?=^class |\Z)",
            text, flags=re.S | re.M,
        )
        if match is None:
            report.add(Finding(
                severity="HARD", rule="class-missing",
                path=_display(MESSAGES_PY),
                detail=f"class {cls} not found",
            ))
            continue
        block = match.group(0)
        for field_name in ("scoring_algo_version", "scoring_weights_version"):
            if not re.search(rf"\b{field_name}\s*:", block):
                report.add(Finding(
                    severity="HARD", rule="missing-version-field",
                    path=_display(MESSAGES_PY),
                    detail=(
                        f"{cls} is missing field {field_name!r} — VULN-22 "
                        f"requires the (algo, weights) version pair on the wire"
                    ),
                ))


def _check_commit_reveal_kwarg(report: Report) -> None:
    """compute_commit_hash + verify_reveal must accept algo_version=."""
    if not COMMIT_REVEAL_PY.exists():
        report.add(Finding(
            severity="HARD", rule="missing-file",
            path=_display(COMMIT_REVEAL_PY),
            detail="commit_reveal.py not found",
        ))
        return
    report.files_scanned += 1
    text = COMMIT_REVEAL_PY.read_text()

    for fn in ("compute_commit_hash", "verify_reveal"):
        sig = re.search(
            rf"def {fn}\((?P<args>.*?)\)\s*->",
            text, flags=re.S,
        )
        if sig is None:
            report.add(Finding(
                severity="HARD", rule="fn-missing",
                path=_display(COMMIT_REVEAL_PY),
                detail=f"function {fn} not found",
            ))
            continue
        if "algo_version" not in sig.group("args"):
            report.add(Finding(
                severity="HARD", rule="missing-algo-version-kwarg",
                path=_display(COMMIT_REVEAL_PY),
                detail=(
                    f"{fn}() does not accept an algo_version kwarg — "
                    f"VULN-22 requires the version be folded into the hash"
                ),
            ))


def _check_round_pinning(report: Report) -> None:
    """CommitRevealRound must expose pinned_algo_version + VersionMismatch."""
    if not COMMIT_REVEAL_ROUND_PY.exists():
        report.add(Finding(
            severity="HARD", rule="missing-file",
            path=_display(COMMIT_REVEAL_ROUND_PY),
            detail="commit_reveal_round.py not found",
        ))
        return
    report.files_scanned += 1
    text = COMMIT_REVEAL_ROUND_PY.read_text()

    if "class VersionMismatch" not in text:
        report.add(Finding(
            severity="HARD", rule="VersionMismatch-missing",
            path=_display(COMMIT_REVEAL_ROUND_PY),
            detail=(
                "VersionMismatch exception class missing — VULN-22 requires "
                "the round to raise it (subclass of CommitRejected) so "
                "version-mismatched commits are silently excluded"
            ),
        ))
    elif not re.search(
        r"class VersionMismatch\(CommitRejected\)", text,
    ):
        report.add(Finding(
            severity="HARD", rule="VersionMismatch-bad-base",
            path=_display(COMMIT_REVEAL_ROUND_PY),
            detail=(
                "VersionMismatch must subclass CommitRejected so existing "
                "`except CommitRejected` paths keep working"
            ),
        ))

    if "pinned_algo_version" not in text:
        report.add(Finding(
            severity="HARD", rule="pinned-algo-version-missing",
            path=_display(COMMIT_REVEAL_ROUND_PY),
            detail=(
                "CommitRevealRound must accept/expose pinned_algo_version "
                "so the round binds to one (algo, weights) version"
            ),
        ))

    if "version_mismatched_nodes" not in text:
        report.add(Finding(
            severity="HARD", rule="version_mismatched_nodes-missing",
            path=_display(COMMIT_REVEAL_ROUND_PY),
            detail=(
                "CommitRevealRound must expose version_mismatched_nodes() "
                "so the runner can surface excluded nodes in its report"
            ),
        ))


def _check_byzantine_runner_silent_exclude(report: Report) -> None:
    """
    ByzantineEpochReport must carry version_excluded_nodes, and the
    runner must NOT feed version-mismatched node ids into
    EpochByzantineFlag emission.
    """
    if not BYZANTINE_RUNNER_PY.exists():
        report.add(Finding(
            severity="HARD", rule="missing-file",
            path=_display(BYZANTINE_RUNNER_PY),
            detail="byzantine_runner.py not found",
        ))
        return
    report.files_scanned += 1
    text = BYZANTINE_RUNNER_PY.read_text()

    if "version_excluded_nodes" not in text:
        report.add(Finding(
            severity="HARD", rule="report-field-missing",
            path=_display(BYZANTINE_RUNNER_PY),
            detail=(
                "ByzantineEpochReport must carry a version_excluded_nodes "
                "tuple so operators see the upgrade-skew set distinctly "
                "from byzantine_nodes"
            ),
        ))

    if "version_mismatched_nodes" not in text:
        report.add(Finding(
            severity="HARD", rule="runner-does-not-read-mismatches",
            path=_display(BYZANTINE_RUNNER_PY),
            detail=(
                "byzantine_runner.py must read round.version_mismatched_nodes() "
                "to populate the report"
            ),
        ))

    # Antipattern: the version-excluded set must not be merged into
    # byzantine_this_epoch or pushed into epoch_flags. We grep the
    # textual antipattern; a future PR that crosses these wires fails.
    bad_patterns = [
        r"byzantine_this_epoch\s*\|=\s*version_excluded",
        r"byzantine_this_epoch\s*\.update\s*\(\s*version_excluded\s*\)",
        r"EpochByzantineFlag\s*\([^)]*version_excluded",
    ]
    for pat in bad_patterns:
        if re.search(pat, text):
            report.add(Finding(
                severity="HARD", rule="version-excluded-merged-into-byzantine",
                path=_display(BYZANTINE_RUNNER_PY),
                detail=(
                    f"forbidden antipattern matched: {pat!r} — version-"
                    f"excluded nodes MUST NOT be flagged Byzantine"
                ),
            ))


def _check_node_emits_version(report: Report) -> None:
    """OracleNode.local_commit / local_reveal must put the version on the wire."""
    if not NODE_PY.exists():
        report.add(Finding(
            severity="HARD", rule="missing-file",
            path=_display(NODE_PY), detail="node.py not found",
        ))
        return
    report.files_scanned += 1
    text = NODE_PY.read_text()

    if "scoring_algo_version" not in text:
        report.add(Finding(
            severity="HARD", rule="node-no-version-on-wire",
            path=_display(NODE_PY),
            detail=(
                "OracleNode does not reference scoring_algo_version — "
                "VULN-22 requires CommitRequest/RevealRequest emitted by "
                "the node to carry the version pair"
            ),
        ))
    if "algo_version" not in text:
        report.add(Finding(
            severity="HARD", rule="node-no-algo-version-folded",
            path=_display(NODE_PY),
            detail=(
                "OracleNode does not fold algo_version into compute_commit_hash"
            ),
        ))


# =============================================================================
# Driver
# =============================================================================

def scan() -> Report:
    report = Report()
    _check_messages(report)
    _check_commit_reveal_kwarg(report)
    _check_round_pinning(report)
    _check_byzantine_runner_silent_exclude(report)
    _check_node_emits_version(report)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="VULN-22 version-pinning sweep.")
    p.add_argument(
        "--json", type=Path, default=None,
        help="Write the JSON report to this path (default: stdout).",
    )
    args = p.parse_args(argv)

    report = scan()
    blob = json.dumps(report.to_dict(), indent=2)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(blob + "\n")
    else:
        print(blob)

    if report.hard_count:
        print(
            f"\n❌ {report.hard_count} HARD version-pinning findings",
            file=sys.stderr,
        )
        return 1
    print(
        f"✅ version-pinning sweep clean "
        f"({report.files_scanned} files scanned)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
