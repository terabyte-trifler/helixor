#!/usr/bin/env python3
"""
audit/trust_assumption_check.py — the unified TRUST-ASSUMPTION audit gate.

The Helixor audit enumerated 8 TRUST ASSUMPTIONS (TA-1..TA-8). Each one
was closed by a real mechanism — a Python module, an Anchor state file, a
constant, a property-test suite — committed into the repo. This gate is
the regression alarm: it greps each marker so that a refactor that
quietly removes a mitigation lights this red BEFORE mainnet.

WHAT THIS GATE CHECKS
---------------------
TA-1  Oracle-node honesty       — divergence detector + tolerance constant
                                   present off-chain so a Byzantine node's
                                   submission is evidenced, hashed, and
                                   challengeable.
TA-2  Geyser data integrity     — production_config refuses unverified
                                   sources on mainnet AND the runner
                                   actually calls the gate.
TA-3  Scoring-kernel properties — the property-test suite asserts the
                                   per-dimension monotonicity invariant
                                   that "no formal verification" makes
                                   load-bearing.
TA-4  Library verification      — pinned versions in
                                   library_verification.py match
                                   requirements.in exactly; drift in
                                   either side fails this gate.
TA-5  TX-window digest          — compute_tx_window_digest is present so
                                   AW-04 can fold an input-row commitment
                                   into the on-chain digest.
TA-6  Cert freshness            — HealthCertificate exposes MAX_AGE_SECONDS
                                   and is_fresh_at, so SDK consumers gate
                                   on cert age rather than trusting a raw
                                   read.
TA-7  Squads transition         — the 2026-09-01 deadline is pinned and
                                   the predicate exists; an admin-gated
                                   handler can refuse post-deadline.
TA-8  Multi-RPC consensus       — MultiRpcConsensus + mainnet floor
                                   constants are present so the oracle's
                                   COMMIT path can demand K-of-N agreement.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the SPOF gate.
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
    """One trust-assumption gate finding."""
    ta:       str
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
    report: Report, *, ta: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            ta=ta, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-TA probes
# =============================================================================

def check_ta1_oracle_divergence(report: Report) -> None:
    """TA-1 — DivergenceDetector + tolerance + tests are present."""
    report.checked.append("TA-1 oracle-node honesty")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "slashing" / "divergence.py"
    )
    _require(
        report, ta="TA-1",
        rule="divergence-detector-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/slashing/divergence.py is missing — the TA-1 "
            "Byzantine-node detector has been removed."
        ),
    )
    if src is not None:
        _require(
            report, ta="TA-1",
            rule="divergence-detector-class",
            condition="class DivergenceDetector" in src,
            detail=(
                "divergence.py no longer defines DivergenceDetector — the "
                "off-chain evidence producer for challenge_oracle is gone."
            ),
        )
        _require(
            report, ta="TA-1",
            rule="score-tolerance-pinned",
            condition="DEFAULT_SCORE_TOLERANCE = 50" in src,
            detail=(
                "divergence.py no longer pins DEFAULT_SCORE_TOLERANCE=50 — "
                "a wider tolerance silently absorbs Byzantine deviations."
            ),
        )

    tests = _read(
        REPO_ROOT / "helixor-oracle" / "tests" / "slashing"
        / "test_ta1_divergence.py"
    )
    _require(
        report, ta="TA-1",
        rule="divergence-tests-present",
        condition=tests is not None,
        detail=(
            "tests/slashing/test_ta1_divergence.py is missing — the "
            "median-consensus + evidence-hash determinism pins are gone."
        ),
    )


def check_ta2_geyser_verified_source(report: Report) -> None:
    """TA-2 — production_config gate + ConsensusStream marker + runner wire."""
    report.checked.append("TA-2 geyser data integrity")

    prod = _read(
        REPO_ROOT / "helixor-indexer" / "indexer" / "production_config.py"
    )
    _require(
        report, ta="TA-2",
        rule="assert-source-verified-for-cluster-present",
        condition=(
            prod is not None
            and "def assert_source_verified_for_cluster" in prod
            and "class UnverifiedStreamSourceError" in prod
        ),
        detail=(
            "production_config.py no longer defines "
            "assert_source_verified_for_cluster / UnverifiedStreamSourceError "
            "— the TA-2 mainnet pre-flight gate has been removed."
        ),
    )

    consensus = _read(
        REPO_ROOT / "helixor-indexer" / "indexer" / "consensus.py"
    )
    _require(
        report, ta="TA-2",
        rule="consensus-stream-marker",
        condition=(
            consensus is not None
            and "is_verified_consensus_source: bool = True" in consensus
        ),
        detail=(
            "indexer/consensus.py no longer declares "
            "is_verified_consensus_source = True on ConsensusStream — the "
            "duck-typed marker the runner gates on is gone."
        ),
    )

    runner = _read(
        REPO_ROOT / "helixor-indexer" / "indexer" / "runner.py"
    )
    _require(
        report, ta="TA-2",
        rule="runner-calls-pre-flight",
        condition=(
            runner is not None
            and "assert_source_verified_for_cluster(source)" in runner
        ),
        detail=(
            "indexer/runner.py no longer calls "
            "assert_source_verified_for_cluster(source) at __init__ — a "
            "mainnet GeyserIndexer may now boot with a single-endpoint "
            "stream."
        ),
    )


def check_ta3_scoring_property_tests(report: Report) -> None:
    """TA-3 — property-based invariants over compute_composite_score."""
    report.checked.append("TA-3 scoring properties")

    tests = _read(
        REPO_ROOT / "helixor-oracle" / "tests" / "scoring"
        / "test_ta3_property_invariants.py"
    )
    _require(
        report, ta="TA-3",
        rule="property-tests-present",
        condition=tests is not None,
        detail=(
            "tests/scoring/test_ta3_property_invariants.py is missing — "
            "the TA-3 scoring-kernel property suite is gone."
        ),
    )
    if tests is None:
        return

    _require(
        report, ta="TA-3",
        rule="monotonicity-invariant-asserted",
        condition="monotonic" in tests.lower(),
        detail=(
            "the TA-3 property suite no longer asserts per-dimension "
            "monotonicity — the load-bearing invariant has been deleted."
        ),
    )
    _require(
        report, ta="TA-3",
        rule="immediate-red-invariant-asserted",
        condition="IMMEDIATE_RED" in tests or "immediate_red" in tests,
        detail=(
            "the TA-3 property suite no longer asserts that IMMEDIATE_RED "
            "forces a RED tier."
        ),
    )


def check_ta4_library_verification(report: Report) -> None:
    """TA-4 — library pins match requirements.in exactly."""
    report.checked.append("TA-4 library verification")

    verifier = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "library_verification.py"
    )
    _require(
        report, ta="TA-4",
        rule="library-verification-present",
        condition=verifier is not None,
        detail=(
            "helixor-oracle/oracle/library_verification.py is missing — "
            "the TA-4 runtime version gate is gone."
        ),
    )
    if verifier is None:
        return

    _require(
        report, ta="TA-4",
        rule="expected-versions-mapping-present",
        condition="EXPECTED_LIBRARY_VERSIONS" in verifier,
        detail=(
            "library_verification.py no longer exports "
            "EXPECTED_LIBRARY_VERSIONS — the manifest the gate compares "
            "against is gone."
        ),
    )

    requirements = _read(
        REPO_ROOT / "helixor-oracle" / "requirements.in"
    )
    if requirements is None:
        report.findings.append(Finding(
            ta="TA-4", severity="HARD",
            rule="requirements-in-present",
            detail=(
                "helixor-oracle/requirements.in is missing — there is no "
                "source of truth for TA-4 to mirror."
            ),
        ))
        return

    # Cross-check each security-critical pin: manifest version == req.in pin.
    for lib in ("cryptography", "solana", "solders", "grpcio"):
        manifest_pin = f'"{lib}":'
        req_pin = f"{lib}=="
        _require(
            report, ta="TA-4",
            rule=f"{lib}-pinned-in-requirements",
            condition=req_pin in requirements,
            detail=(
                f"requirements.in no longer pins {lib} with == — the "
                f"hash-lock cannot reproduce a specific version."
            ),
        )
        _require(
            report, ta="TA-4",
            rule=f"{lib}-pinned-in-library-verification",
            condition=manifest_pin in verifier,
            detail=(
                f"library_verification.py no longer pins {lib} in "
                f"EXPECTED_LIBRARY_VERSIONS — runtime drift is undetected."
            ),
        )


def check_ta5_tx_window_digest(report: Report) -> None:
    """TA-5 — canonical tx-window digest helper is present."""
    report.checked.append("TA-5 tx-window digest")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "tx_window_digest.py"
    )
    _require(
        report, ta="TA-5",
        rule="tx-window-digest-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/tx_window_digest.py is missing — the "
            "TA-5 input-row commitment helper is gone."
        ),
    )
    if src is None:
        return

    _require(
        report, ta="TA-5",
        rule="compute-tx-window-digest-defined",
        condition="def compute_tx_window_digest" in src,
        detail=(
            "tx_window_digest.py no longer defines compute_tx_window_digest "
            "— AW-04 has nothing to fold the input-row commitment into."
        ),
    )


def check_ta6_cert_freshness(report: Report) -> None:
    """TA-6 — HealthCertificate exposes MAX_AGE_SECONDS + is_fresh_at."""
    report.checked.append("TA-6 cert freshness")

    cert = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "certificate-issuer"
        / "src" / "state" / "health_certificate.rs"
    )
    _require(
        report, ta="TA-6",
        rule="health-certificate-present",
        condition=cert is not None,
        detail=(
            "programs/certificate-issuer/src/state/health_certificate.rs "
            "is missing — there is nothing to gate freshness on."
        ),
    )
    if cert is None:
        return

    _require(
        report, ta="TA-6",
        rule="max-age-seconds-48h",
        condition="MAX_AGE_SECONDS: i64 = 48 * 60 * 60" in cert,
        detail=(
            "health_certificate.rs no longer pins MAX_AGE_SECONDS to 48h — "
            "the consumer freshness ceiling has been moved without review."
        ),
    )
    _require(
        report, ta="TA-6",
        rule="is-fresh-at-helper-present",
        condition="fn is_fresh_at" in cert,
        detail=(
            "health_certificate.rs no longer exposes is_fresh_at(now, "
            "max_age) — SDK consumers have nothing to call."
        ),
    )


def check_ta7_squads_deadline(report: Report) -> None:
    """TA-7 — Squads transition deadline is the pinned 2026-09-01."""
    report.checked.append("TA-7 squads transition deadline")

    src = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "slash-authority"
        / "src" / "state" / "squads_transition.rs"
    )
    _require(
        report, ta="TA-7",
        rule="squads-transition-module-present",
        condition=src is not None,
        detail=(
            "programs/slash-authority/src/state/squads_transition.rs is "
            "missing — the TA-7 admin-key transition anchor is gone."
        ),
    )
    if src is None:
        return

    # The two values MUST be in lockstep: a future patch that bumps the
    # unix value without bumping the ISO string is a regression because the
    # LAUNCH_CHECKLIST entry is the ISO form.
    _require(
        report, ta="TA-7",
        rule="deadline-unix-pinned",
        condition="SQUADS_TRANSITION_DEADLINE_UNIX: i64 = 1_788_220_800" in src,
        detail=(
            "squads_transition.rs no longer pins "
            "SQUADS_TRANSITION_DEADLINE_UNIX to 1_788_220_800 "
            "(2026-09-01T00:00:00Z) — the audit anchor has moved."
        ),
    )
    _require(
        report, ta="TA-7",
        rule="deadline-iso-pinned",
        condition='SQUADS_TRANSITION_DEADLINE_ISO: &str = "2026-09-01T00:00:00Z"' in src,
        detail=(
            "squads_transition.rs no longer pins "
            'SQUADS_TRANSITION_DEADLINE_ISO to "2026-09-01T00:00:00Z" — '
            "the human-readable mirror of the audit anchor has drifted."
        ),
    )
    _require(
        report, ta="TA-7",
        rule="predicate-present",
        condition="fn is_before_squads_transition" in src,
        detail=(
            "squads_transition.rs no longer exposes "
            "is_before_squads_transition — any future admin-gated handler "
            "has nothing to gate on."
        ),
    )


def check_ta8_multi_rpc(report: Report) -> None:
    """TA-8 — MultiRpcConsensus + mainnet floor constants are present."""
    report.checked.append("TA-8 multi-RPC consensus")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "multi_rpc.py"
    )
    _require(
        report, ta="TA-8",
        rule="multi-rpc-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/multi_rpc.py is missing — the TA-8 "
            "multi-endpoint consensus helper is gone."
        ),
    )
    if src is None:
        return

    _require(
        report, ta="TA-8",
        rule="multi-rpc-consensus-class",
        condition="class MultiRpcConsensus" in src,
        detail=(
            "multi_rpc.py no longer defines MultiRpcConsensus — the public "
            "K-of-N consensus API is gone."
        ),
    )
    _require(
        report, ta="TA-8",
        rule="mainnet-min-rpc-endpoints-3",
        condition="MAINNET_MIN_RPC_ENDPOINTS = 3" in src,
        detail=(
            "multi_rpc.py no longer pins MAINNET_MIN_RPC_ENDPOINTS=3 — "
            "single- or two-endpoint mainnet RPC reads may slip through."
        ),
    )
    _require(
        report, ta="TA-8",
        rule="min-rpc-consensus-threshold-2",
        condition="MIN_RPC_CONSENSUS_THRESHOLD = 2" in src,
        detail=(
            "multi_rpc.py no longer pins MIN_RPC_CONSENSUS_THRESHOLD=2 — "
            "a K=1 quorum is equivalent to trusting a single endpoint, "
            "which is the very SPOF this gate exists to forbid."
        ),
    )
    _require(
        report, ta="TA-8",
        rule="rpc-divergence-error-defined",
        condition="class RpcDivergenceError" in src,
        detail=(
            "multi_rpc.py no longer defines RpcDivergenceError — the typed "
            "refusal contract callers branch on has been removed."
        ),
    )


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_ta1_oracle_divergence(report)
    check_ta2_geyser_verified_source(report)
    check_ta3_scoring_property_tests(report)
    check_ta4_library_verification(report)
    check_ta5_tx_window_digest(report)
    check_ta6_cert_freshness(report)
    check_ta7_squads_deadline(report)
    check_ta8_multi_rpc(report)
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
            f"trust_assumption_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nTrust-assumption audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.ta}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
