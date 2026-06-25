#!/usr/bin/env python3
"""
audit/adversarial_ml_check.py — VULN-24 hardening sweep.

VULN-24 covers adversarial-ML evasion against the anomaly + drift
detectors. An RL-style attacker reads the public oracle output after
each epoch, learns which detectors fired on its last input, and
crafts the next input to evade them. The audit-mandated mitigations
attack that feedback loop in four independent ways:

  1. EVALUATION-WINDOW JITTER — per-(agent, epoch) deterministic
     offsets keyed off an UNPREDICTABLE on-chain seed
     (`EpochState.last_advanced_at`). The attacker cannot precompute
     which sub-window their behaviour will be measured over.

  2. ENSEMBLE-COVERAGE QUORUM — the composite scorer flags
     `ENSEMBLE_INCOMPLETE` when fewer than `MIN_ACTIVE_DETECTORS`
     dimensions actually produced a result. Adversarial features
     designed to silence a specific detector trip the quorum.

  3. PER-DIMENSION VELOCITY GUARD — each dimension's per-epoch
     contribution is clamped to ±`DIM_MAX_SCORE_DELTA`. Catches
     pump-and-offset attacks that whipsaw one dimension while
     another cancels it (so the AGGREGATE delta guard never fires).

  4. PUBLIC FLAG OBFUSCATION — the REST API does not echo the raw
     detection bitmask. Instead it emits an opaque token
     (`flag_set_token`) + popcount (`flag_count`). The on-chain
     bitmask is unchanged; only the public read surface is
     obfuscated. Removes the read-then-craft feedback channel.

This sweep pins every one of those mitigations in source. A future
PR that silently drops one fails the gate.

REPORTING
---------
JSON to `--json` (default stdout), non-zero exit on any HARD finding.
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
# Targets
# =============================================================================

ORACLE_WINDOW_JITTER_PY  = REPO_ROOT / "phylanx-oracle" / "detection" / "window_jitter.py"
ORACLE_GAMING_PY         = REPO_ROOT / "phylanx-oracle" / "scoring" / "_gaming.py"
ORACLE_COMPOSITE_PY      = REPO_ROOT / "phylanx-oracle" / "scoring" / "composite.py"
ORACLE_TYPES_PY          = REPO_ROOT / "phylanx-oracle" / "detection" / "types.py"
API_FLAG_OBFUSCATION_PY  = REPO_ROOT / "phylanx-api" / "api" / "flag_obfuscation.py"
API_SCHEMAS_PY           = REPO_ROOT / "phylanx-api" / "api" / "schemas.py"
API_APP_PY               = REPO_ROOT / "phylanx-api" / "api" / "app.py"


# Audit-mandated numeric values. The scanner refuses to let them be
# silently bumped in only one file.
EXPECTED_MIN_ACTIVE_DETECTORS: int = 3
EXPECTED_DIM_MAX_SCORE_DELTA:  int = 250
EXPECTED_MAX_JITTER_SECONDS:   int = 600


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
# Helpers
# =============================================================================

def _display(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def _require_file(report: Report, p: Path, rule: str) -> str | None:
    if not p.exists():
        report.add(Finding(
            severity="HARD", rule=rule,
            path=_display(p), detail=f"{p.name} not found",
        ))
        return None
    report.files_scanned += 1
    return p.read_text()


# =============================================================================
# Mitigation #1 — window jitter
# =============================================================================

def _check_window_jitter(report: Report) -> None:
    text = _require_file(
        report, ORACLE_WINDOW_JITTER_PY, "missing-window-jitter",
    )
    if text is None:
        return

    if not re.search(r"\bdef\s+compute_window_jitter\s*\(", text):
        report.add(Finding(
            severity="HARD", rule="compute_window_jitter-missing",
            path=_display(ORACLE_WINDOW_JITTER_PY),
            detail=(
                "compute_window_jitter() must exist — VULN-24 mitigation #1: "
                "per-(agent, epoch) evaluation-window jitter"
            ),
        ))

    # The jitter MUST be keyed off an unpredictable per-epoch seed.
    # We pin the parameter name so a refactor that silently drops it
    # is caught.
    if "epoch_advance_seed" not in text:
        report.add(Finding(
            severity="HARD", rule="jitter-seed-missing",
            path=_display(ORACLE_WINDOW_JITTER_PY),
            detail=(
                "compute_window_jitter must accept `epoch_advance_seed` — "
                "without an unpredictable seed an attacker precomputes the "
                "jitter and re-aligns their misbehaviour with the window"
            ),
        ))

    if not re.search(
        rf"MAX_JITTER_SECONDS\s*:?\s*int\s*=\s*{EXPECTED_MAX_JITTER_SECONDS}\b",
        text,
    ):
        report.add(Finding(
            severity="HARD", rule="bad-max-jitter",
            path=_display(ORACLE_WINDOW_JITTER_PY),
            detail=(
                f"MAX_JITTER_SECONDS must equal {EXPECTED_MAX_JITTER_SECONDS}"
            ),
        ))


# =============================================================================
# Mitigation #2 — ensemble-coverage quorum
# =============================================================================

def _check_ensemble_quorum(report: Report) -> None:
    composite_text = _require_file(
        report, ORACLE_COMPOSITE_PY, "missing-composite",
    )
    if composite_text is not None:
        if not re.search(
            rf"MIN_ACTIVE_DETECTORS\s*(?::\s*int\s*)?=\s*"
            rf"{EXPECTED_MIN_ACTIVE_DETECTORS}\b",
            composite_text,
        ):
            report.add(Finding(
                severity="HARD", rule="bad-min-active-detectors",
                path=_display(ORACLE_COMPOSITE_PY),
                detail=(
                    f"MIN_ACTIVE_DETECTORS must equal "
                    f"{EXPECTED_MIN_ACTIVE_DETECTORS} — "
                    f"too low and a single-detector attack passes silently"
                ),
            ))
        if "ENSEMBLE_INCOMPLETE" not in composite_text:
            report.add(Finding(
                severity="HARD", rule="ensemble-flag-not-set",
                path=_display(ORACLE_COMPOSITE_PY),
                detail=(
                    "composite.py never OR-s the ENSEMBLE_INCOMPLETE flag — "
                    "the quorum check is silent without it"
                ),
            ))

    types_text = _require_file(report, ORACLE_TYPES_PY, "missing-detection-types")
    if types_text is not None:
        # The universal flag bits must exist and be pinned at the right
        # positions so the on-chain bitmask layout stays stable.
        if not re.search(r"ENSEMBLE_INCOMPLETE\s*=\s*1\s*<<\s*5", types_text):
            report.add(Finding(
                severity="HARD", rule="ensemble-flag-bit-missing",
                path=_display(ORACLE_TYPES_PY),
                detail=(
                    "FlagBit.ENSEMBLE_INCOMPLETE must be `1 << 5` — bit "
                    "positions are part of the on-chain wire format"
                ),
            ))
        if not re.search(r"DIMENSION_CLAMPED\s*=\s*1\s*<<\s*6", types_text):
            report.add(Finding(
                severity="HARD", rule="dim-clamped-flag-bit-missing",
                path=_display(ORACLE_TYPES_PY),
                detail=(
                    "FlagBit.DIMENSION_CLAMPED must be `1 << 6` — same"
                ),
            ))


# =============================================================================
# Mitigation #3 — per-dimension velocity guard
# =============================================================================

def _check_per_dim_velocity_guard(report: Report) -> None:
    text = _require_file(report, ORACLE_GAMING_PY, "missing-gaming")
    if text is None:
        return

    if not re.search(
        r"\bdef\s+apply_dimension_delta_guard_rail\s*\(", text,
    ):
        report.add(Finding(
            severity="HARD", rule="dim-delta-guard-missing",
            path=_display(ORACLE_GAMING_PY),
            detail=(
                "apply_dimension_delta_guard_rail() must exist — VULN-24 "
                "mitigation #3: per-dimension pump-and-offset guard"
            ),
        ))
    if not re.search(
        rf"DIM_MAX_SCORE_DELTA\s*=\s*{EXPECTED_DIM_MAX_SCORE_DELTA}\b",
        text,
    ):
        report.add(Finding(
            severity="HARD", rule="bad-dim-max-delta",
            path=_display(ORACLE_GAMING_PY),
            detail=(
                f"DIM_MAX_SCORE_DELTA must equal "
                f"{EXPECTED_DIM_MAX_SCORE_DELTA} — too high and pump-and-"
                f"offset attacks pass; too low and legitimate detector "
                f"swings are clamped"
            ),
        ))


# =============================================================================
# Mitigation #4 — public flag obfuscation
# =============================================================================

def _check_flag_obfuscation(report: Report) -> None:
    obfusc_text = _require_file(
        report, API_FLAG_OBFUSCATION_PY, "missing-flag-obfuscation",
    )
    if obfusc_text is not None:
        if not re.search(r"\bdef\s+compute_flag_token\s*\(", obfusc_text):
            report.add(Finding(
                severity="HARD", rule="compute_flag_token-missing",
                path=_display(API_FLAG_OBFUSCATION_PY),
                detail=(
                    "compute_flag_token() must exist — VULN-24 mitigation #4"
                ),
            ))
        if not re.search(r"\bdef\s+popcount\s*\(", obfusc_text):
            report.add(Finding(
                severity="HARD", rule="popcount-missing",
                path=_display(API_FLAG_OBFUSCATION_PY),
                detail=(
                    "popcount() must exist alongside the token helper — "
                    "consumers need the diagnostic count"
                ),
            ))

    schemas_text = _require_file(
        report, API_SCHEMAS_PY, "missing-api-schemas",
    )
    if schemas_text is not None:
        # The raw `flags: int` field MUST NOT appear inside HealthResponse.
        # We scan the HealthResponse block specifically to avoid matching
        # `flags:` inside other unrelated models (e.g. ByzantineRecent).
        m = re.search(
            r"class\s+HealthResponse\b[^\n]*:\s*(?P<body>.*?)(?=\n\nclass\s|\Z)",
            schemas_text, re.DOTALL,
        )
        if m is None:
            report.add(Finding(
                severity="HARD", rule="HealthResponse-missing",
                path=_display(API_SCHEMAS_PY),
                detail="HealthResponse Pydantic model not found",
            ))
        else:
            body = m.group("body")
            if re.search(r"^\s*flags\s*:", body, re.MULTILINE):
                report.add(Finding(
                    severity="HARD", rule="raw-flags-on-wire",
                    path=_display(API_SCHEMAS_PY),
                    detail=(
                        "HealthResponse exposes raw `flags: int` — VULN-24 "
                        "mitigation #4 requires the bitmask be replaced "
                        "with `flag_set_token` + `flag_count`"
                    ),
                ))
            if "flag_set_token" not in body:
                report.add(Finding(
                    severity="HARD", rule="flag_set_token-missing",
                    path=_display(API_SCHEMAS_PY),
                    detail=(
                        "HealthResponse must declare `flag_set_token: str`"
                    ),
                ))
            if "flag_count" not in body:
                report.add(Finding(
                    severity="HARD", rule="flag_count-missing",
                    path=_display(API_SCHEMAS_PY),
                    detail="HealthResponse must declare `flag_count: int`",
                ))

    app_text = _require_file(report, API_APP_PY, "missing-api-app")
    if app_text is not None:
        if "compute_flag_token" not in app_text:
            report.add(Finding(
                severity="HARD", rule="app-not-using-flag-token",
                path=_display(API_APP_PY),
                detail=(
                    "app.py must call compute_flag_token to populate "
                    "HealthResponse — VULN-24 mitigation #4"
                ),
            ))


# =============================================================================
# Driver
# =============================================================================

def scan() -> Report:
    report = Report()
    _check_window_jitter(report)
    _check_ensemble_quorum(report)
    _check_per_dim_velocity_guard(report)
    _check_flag_obfuscation(report)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="VULN-24 adversarial-ML sweep.")
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
            f"\n❌ {report.hard_count} HARD adversarial-ML findings",
            file=sys.stderr,
        )
        return 1
    print(
        f"✅ adversarial-ML sweep clean "
        f"({report.files_scanned} files scanned)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
