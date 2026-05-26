#!/usr/bin/env python3
"""
audit/forge_high_score_check.py — the unified FORGE HIGH-SCORE CERT
audit gate.

The red-team attack tree's Path 1 (root: "Drain DeFi Protocol
Integrated with Helixor") is "Forge High-Score Cert" — three sub-leaves:

  1a. Compromise 3 oracle keys [HIGH EFFORT]
  1b. Exploit VULN-01 (signature verification bypass) [MEDIUM EFFORT]
  1c. Exploit VULN-13 (replace all oracle keys) [HIGH EFFORT]

The K-of-N threshold makes 1a hard PER COMPROMISE, NSS-1/NSS-2
already wired close the cloud/HSM substrates, and VULN-01 / VULN-13
ship on-chain defences. What was missing pre-FHS was the time
dimension: a compromised key with permanent validity, a threshold
set with no per-host attestation, and a rotation ceremony that could
wholesale-replace the cluster in one shot.

The mitigations (FHS-1..FHS-3) each close one substrate of Path 1:

  FHS-1  Cluster-key rotation cadence floor   refuses any cluster
                                              key past MAX_KEY_AGE
                                              (90 days); pairs with
                                              FHS-3 to prevent
                                              dwell-time attacks.
  FHS-2  Per-signer provenance attestation    refuses a threshold
                                              set whose K signatures
                                              share a physical host,
                                              exceed the per-region
                                              cap, or are missing
                                              attestations.
  FHS-3  Cluster-key rotation overlap guard   refuses a rotation
                                              proposal that replaces
                                              more than one key per
                                              ceremony (the
                                              wholesale-replacement
                                              attack).

Each is closed by a real mechanism committed into the repo
(`oracle/key_rotation_cadence.py`, `oracle/signer_provenance.py`,
`oracle/rotation_overlap_guard.py`). This gate is the mechanical
regression alarm: it greps each marker so a refactor that quietly
removes a mitigation lights this red BEFORE mainnet. It ALSO
cross-checks the on-chain anchors for VULN-01
(`programs/certificate-issuer/src/signing.rs` —
`verify_threshold_signatures` + `expected_digest` filtering) and
VULN-13 (`programs/health-oracle/src/state/pending_oracle_rotation.rs`
— `MIN_TIMELOCK_SECONDS = 48 * 60 * 60`) so a regression on either
existing anchor lights this gate too.

REPORTING
---------
JSON report to `--json` (default stdout). Exits non-zero on any HARD
finding. Wired into `audit/run_all.sh` immediately after the SOL
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
    """One forge-high-score gate finding."""
    fhs:      str
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
    report: Report, *, fhs: str, rule: str, condition: bool, detail: str,
) -> None:
    if not condition:
        report.findings.append(Finding(
            fhs=fhs, severity="HARD", rule=rule, detail=detail,
        ))


# =============================================================================
# Per-FHS probes
# =============================================================================

def check_fhs1_key_rotation_cadence(report: Report) -> None:
    """FHS-1 — cluster-key rotation cadence floor present + pinned."""
    report.checked.append("FHS-1 cluster-key rotation cadence")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "key_rotation_cadence.py"
    )
    _require(
        report, fhs="FHS-1",
        rule="key-rotation-cadence-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/key_rotation_cadence.py is missing — "
            "the FHS-1 cluster-key rotation cadence floor has been "
            "removed; a compromised key has no expiration."
        ),
    )
    if src is None:
        return

    _require(
        report, fhs="FHS-1",
        rule="verify-key-rotation-cadence-defined",
        condition="def verify_key_rotation_cadence" in src,
        detail=(
            "key_rotation_cadence.py no longer defines "
            "verify_key_rotation_cadence."
        ),
    )
    _require(
        report, fhs="FHS-1",
        rule="enforce-key-rotation-cadence-defined",
        condition="def enforce_key_rotation_cadence" in src,
        detail=(
            "key_rotation_cadence.py no longer defines "
            "enforce_key_rotation_cadence — the fail-closed wrapper "
            "is gone."
        ),
    )
    _require(
        report, fhs="FHS-1",
        rule="max-key-age-90d",
        condition="MAX_KEY_AGE_SECONDS = 90 * 24 * 3600" in src,
        detail=(
            "key_rotation_cadence.py no longer pins "
            "MAX_KEY_AGE_SECONDS=90*24*3600 — the hard rotation "
            "floor has shifted."
        ),
    )
    _require(
        report, fhs="FHS-1",
        rule="warn-key-age-60d",
        condition="WARN_KEY_AGE_SECONDS = 60 * 24 * 3600" in src,
        detail=(
            "key_rotation_cadence.py no longer pins "
            "WARN_KEY_AGE_SECONDS=60*24*3600 — the soft warning "
            "window has shifted."
        ),
    )
    _require(
        report, fhs="FHS-1",
        rule="cadence-status-constants-pinned",
        condition=(
            'CADENCE_OK = "OK"' in src
            and 'CADENCE_WARN = "WARN"' in src
            and 'CADENCE_OVERDUE = "OVERDUE"' in src
        ),
        detail=(
            "key_rotation_cadence.py no longer pins the status labels "
            "(OK / WARN / OVERDUE) — the operator runbook and audit "
            "gate greps rely on those literals."
        ),
    )


def check_fhs2_signer_provenance(report: Report) -> None:
    """FHS-2 — per-signer provenance attestation gate present."""
    report.checked.append("FHS-2 per-signer provenance attestation")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "signer_provenance.py"
    )
    _require(
        report, fhs="FHS-2",
        rule="signer-provenance-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/signer_provenance.py is missing — "
            "the FHS-2 per-signer provenance gate has been removed; "
            "two cluster signatures from the same physical machine "
            "are no longer refused."
        ),
    )
    if src is None:
        return

    _require(
        report, fhs="FHS-2",
        rule="verify-signer-provenance-defined",
        condition="def verify_signer_provenance" in src,
        detail=(
            "signer_provenance.py no longer defines "
            "verify_signer_provenance."
        ),
    )
    _require(
        report, fhs="FHS-2",
        rule="enforce-signer-provenance-defined",
        condition="def enforce_signer_provenance" in src,
        detail=(
            "signer_provenance.py no longer defines "
            "enforce_signer_provenance — the fail-closed wrapper is "
            "gone."
        ),
    )
    _require(
        report, fhs="FHS-2",
        rule="max-signers-per-host-1",
        condition="MAX_SIGNERS_PER_HOST = 1" in src,
        detail=(
            "signer_provenance.py no longer pins MAX_SIGNERS_PER_HOST=1 "
            "— a single physical machine could now host two cluster "
            "signers undetected."
        ),
    )
    _require(
        report, fhs="FHS-2",
        rule="max-signers-per-region-2",
        condition="MAX_SIGNERS_PER_REGION = 2" in src,
        detail=(
            "signer_provenance.py no longer pins "
            "MAX_SIGNERS_PER_REGION=2 — the per-region cap (mirror of "
            "NSS-1 N-K=2) has shifted."
        ),
    )
    _require(
        report, fhs="FHS-2",
        rule="min-distinct-hosts-3",
        condition="MIN_DISTINCT_HOSTS = 3" in src,
        detail=(
            "signer_provenance.py no longer pins MIN_DISTINCT_HOSTS=3 "
            "— the threshold-floor of distinct hosts has shifted."
        ),
    )


def check_fhs3_rotation_overlap_guard(report: Report) -> None:
    """FHS-3 — cluster-key rotation overlap guard present + pinned."""
    report.checked.append("FHS-3 cluster-key rotation overlap")

    src = _read(
        REPO_ROOT / "helixor-oracle" / "oracle" / "rotation_overlap_guard.py"
    )
    _require(
        report, fhs="FHS-3",
        rule="rotation-overlap-module-present",
        condition=src is not None,
        detail=(
            "helixor-oracle/oracle/rotation_overlap_guard.py is missing "
            "— the FHS-3 rotation overlap guard has been removed; a "
            "single ceremony could wholesale-replace the cluster keys."
        ),
    )
    if src is None:
        return

    _require(
        report, fhs="FHS-3",
        rule="verify-rotation-overlap-defined",
        condition="def verify_rotation_overlap" in src,
        detail=(
            "rotation_overlap_guard.py no longer defines "
            "verify_rotation_overlap."
        ),
    )
    _require(
        report, fhs="FHS-3",
        rule="enforce-rotation-overlap-defined",
        condition="def enforce_rotation_overlap" in src,
        detail=(
            "rotation_overlap_guard.py no longer defines "
            "enforce_rotation_overlap — the fail-closed wrapper is "
            "gone."
        ),
    )
    _require(
        report, fhs="FHS-3",
        rule="max-keys-replaced-per-rotation-1",
        condition="MAX_KEYS_REPLACED_PER_ROTATION = 1" in src,
        detail=(
            "rotation_overlap_guard.py no longer pins "
            "MAX_KEYS_REPLACED_PER_ROTATION=1 — a rotation ceremony "
            "could now replace more than one key at a time."
        ),
    )
    _require(
        report, fhs="FHS-3",
        rule="overlap-reasons-pinned",
        condition=(
            'REASON_WHOLESALE_REPLACEMENT = "WHOLESALE_REPLACEMENT"' in src
            and 'REASON_INSUFFICIENT_OVERLAP = "INSUFFICIENT_OVERLAP"' in src
        ),
        detail=(
            "rotation_overlap_guard.py no longer pins the reason "
            "codes (WHOLESALE_REPLACEMENT / INSUFFICIENT_OVERLAP) — "
            "operator runbooks grep these literals."
        ),
    )

    # Cross-check: VULN-13's on-chain 48h timelock floor must still
    # ship — FHS-3 is the OFF-CHAIN pre-flight that pairs with it.
    rotation_src = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "health-oracle"
        / "src" / "state" / "pending_oracle_rotation.rs"
    )
    if rotation_src is not None:
        _require(
            report, fhs="FHS-3",
            rule="vuln13-timelock-48h-anchor",
            condition=(
                "MIN_TIMELOCK_SECONDS" in rotation_src
                and (
                    "48 * 60 * 60" in rotation_src
                    or "172_800" in rotation_src
                    or "172800" in rotation_src
                )
            ),
            detail=(
                "pending_oracle_rotation.rs no longer pins "
                "MIN_TIMELOCK_SECONDS=48*60*60 — VULN-13's on-chain "
                "rotation timelock has shifted; FHS-3 cannot stand "
                "alone without the on-chain timelock floor."
            ),
        )
    else:
        # If the on-chain anchor module is missing entirely, the
        # VULN-13 ceremony has been removed wholesale — that is a
        # HARD finding regardless of FHS-3's local state.
        report.findings.append(Finding(
            fhs="FHS-3", severity="HARD",
            rule="vuln13-rotation-module-present",
            detail=(
                "programs/health-oracle/src/state/pending_oracle_"
                "rotation.rs is missing — the on-chain VULN-13 "
                "rotation ceremony module has been removed."
            ),
        ))


def check_vuln01_signing_anchor(report: Report) -> None:
    """VULN-01 — on-chain signing.rs threshold-verifier anchor."""
    report.checked.append("VULN-01 signing.rs threshold verifier anchor")

    src = _read(
        REPO_ROOT / "helixor-programs" / "programs" / "certificate-issuer"
        / "src" / "signing.rs"
    )
    _require(
        report, fhs="FHS-1b",
        rule="vuln01-signing-module-present",
        condition=src is not None,
        detail=(
            "certificate-issuer/src/signing.rs is missing — the on-"
            "chain threshold-signature verifier (VULN-01 anchor) has "
            "been removed."
        ),
    )
    if src is None:
        return

    _require(
        report, fhs="FHS-1b",
        rule="vuln01-verify-threshold-signatures-defined",
        condition="pub fn verify_threshold_signatures" in src,
        detail=(
            "signing.rs no longer defines verify_threshold_signatures "
            "— the canonical on-chain threshold verifier has been "
            "removed; off-chain FHS-2 cannot stand alone."
        ),
    )
    _require(
        report, fhs="FHS-1b",
        rule="vuln01-expected-digest-filtering",
        condition="expected_digest" in src and "record.message" in src,
        detail=(
            "signing.rs no longer filters Ed25519 precompile records "
            "by expected_digest — the historical-signature replay "
            "defence (VULN-01) is gone."
        ),
    )


# =============================================================================
# CLI
# =============================================================================

def run() -> Report:
    report = Report()
    check_fhs1_key_rotation_cadence(report)
    check_fhs2_signer_provenance(report)
    check_fhs3_rotation_overlap_guard(report)
    check_vuln01_signing_anchor(report)
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
            f"forge_high_score_check: {len(report.checked)} checks, "
            f"{len(report.hard())} hard, "
            f"{len(report.findings) - len(report.hard())} soft -> "
            f"{args.json}\n"
        )

    if report.hard():
        sys.stderr.write("\nForge-High-Score-Cert audit gate FAILED:\n")
        for f in report.hard():
            sys.stderr.write(f"  [{f.fhs}] {f.rule}: {f.detail}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
