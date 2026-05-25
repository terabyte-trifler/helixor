#!/usr/bin/env python3
"""
audit/cert_consumption_check.py — VULN-23 hardening sweep.

VULN-23 covers the flash-loan + score-manipulation + DeFi-drain attack
chain. The audit-mandated mitigations split into two halves:

  - **CHAIN-SIDE** (already addressed elsewhere): VULN-05 / VULN-06 /
    VULN-13 fixes plus the off-chain `apply_delta_guard_rail` per-epoch
    ±200 clamp. Other sweeps and the existing test suites pin those.

  - **CONSUMER-SIDE** (this sweep): the SDK + the read API must expose
    safe-by-default wrappers that refuse stale certs (> 48h old) and
    velocity-pumped scores (> 200 points across the rolling 3-epoch
    window). Without those wrappers, a downstream DeFi protocol that
    naively imports `getScore()` or `GET /agents/{wallet}/health` is
    vulnerable to score-velocity gaming the cluster cannot prevent
    on chain.

This file pins the consumer-side wiring:

  1. **SDK `SafeCertReader` exists**, exports the three constants at the
     audit-mandated values, exposes a `getSafeScore(agent)` method, and
     enumerates the four reject reasons (STALE_CERT, VELOCITY_EXCEEDED,
     INSUFFICIENT_HISTORY, NO_CURRENT_CERT).

  2. **SDK `index.ts` re-exports** the SafeCertReader + its constants —
     a future refactor that hides them breaks every DeFi consumer that
     `import { SafeCertReader } from '@helixor/sdk'`.

  3. **API `compute_safe_score` exists**, exports the same three
     constants AT THE SAME VALUES, and the reject-reason strings match
     the SDK enum values.

  4. **API route `/agents/{wallet}/safe_score`** is wired in `app.py`.

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
# Targets
# =============================================================================

SDK_SAFE_READER_TS = REPO_ROOT / "helixor-sdk" / "src" / "safe_reader.ts"
SDK_INDEX_TS       = REPO_ROOT / "helixor-sdk" / "src" / "index.ts"
API_SAFE_SCORE_PY  = REPO_ROOT / "helixor-api" / "api" / "safe_score.py"
API_APP_PY         = REPO_ROOT / "helixor-api" / "api" / "app.py"
API_SCHEMAS_PY     = REPO_ROOT / "helixor-api" / "api" / "schemas.py"


# Audit-mandated numeric values — both the SDK and the API MUST emit
# these literals. A future PR that bumps either side independently
# trips this gate.

EXPECTED_MAX_AGE_SECONDS:    int = 48 * 60 * 60   # 172_800
EXPECTED_MAX_VELOCITY:       int = 200
EXPECTED_WINDOW_EPOCHS:      int = 3
EXPECTED_MIN_HISTORY:        int = 2

EXPECTED_REJECT_REASONS = (
    "STALE_CERT",
    "VELOCITY_EXCEEDED",
    "INSUFFICIENT_HISTORY",
)


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


def _require_file(report: Report, p: Path, rule: str) -> str | None:
    if not p.exists():
        report.add(Finding(
            severity="HARD", rule=rule,
            path=_display(p), detail=f"{p.name} not found",
        ))
        return None
    report.files_scanned += 1
    return p.read_text()


# ── SDK ───────────────────────────────────────────────────────────────────────

def _check_sdk_safe_reader(report: Report) -> None:
    """The SDK's SafeCertReader must exist, expose the constants at the
    audit-mandated values, and enumerate every reject reason."""
    text = _require_file(report, SDK_SAFE_READER_TS, "missing-sdk-safe-reader")
    if text is None:
        return

    # Class exists.
    if not re.search(r"\bclass\s+SafeCertReader\b", text):
        report.add(Finding(
            severity="HARD", rule="SafeCertReader-class-missing",
            path=_display(SDK_SAFE_READER_TS),
            detail=(
                "SafeCertReader class missing — VULN-23 requires the SDK to "
                "expose a freshness+velocity wrapper for DeFi consumers"
            ),
        ))

    # Method exists.
    if not re.search(r"\bgetSafeScore\s*\(", text):
        report.add(Finding(
            severity="HARD", rule="getSafeScore-missing",
            path=_display(SDK_SAFE_READER_TS),
            detail="SafeCertReader must expose getSafeScore(agent)",
        ))

    # Constants present with the right numeric literals. Tolerate the
    # `48 * 60 * 60` form OR the bare `172800` form (audit cares about
    # the value, not the expression).
    age_re = (
        r"CERT_MAX_AGE_SECONDS\s*=\s*"
        rf"(?:48\s*\*\s*60\s*\*\s*60|{EXPECTED_MAX_AGE_SECONDS})\b"
    )
    if not re.search(age_re, text):
        report.add(Finding(
            severity="HARD", rule="bad-max-age-sdk",
            path=_display(SDK_SAFE_READER_TS),
            detail=(
                f"CERT_MAX_AGE_SECONDS must equal {EXPECTED_MAX_AGE_SECONDS} "
                f"(48h) — audit mandate"
            ),
        ))
    if not re.search(rf"MAX_SCORE_VELOCITY\s*=\s*{EXPECTED_MAX_VELOCITY}\b", text):
        report.add(Finding(
            severity="HARD", rule="bad-max-velocity-sdk",
            path=_display(SDK_SAFE_READER_TS),
            detail=(
                f"MAX_SCORE_VELOCITY must equal {EXPECTED_MAX_VELOCITY} — "
                f"must match the off-chain per-epoch ±200 clamp"
            ),
        ))
    if not re.search(rf"VELOCITY_WINDOW_EPOCHS\s*=\s*{EXPECTED_WINDOW_EPOCHS}\b", text):
        report.add(Finding(
            severity="HARD", rule="bad-window-epochs-sdk",
            path=_display(SDK_SAFE_READER_TS),
            detail=f"VELOCITY_WINDOW_EPOCHS must equal {EXPECTED_WINDOW_EPOCHS}",
        ))
    if not re.search(rf"MIN_HISTORY_REQUIRED\s*=\s*{EXPECTED_MIN_HISTORY}\b", text):
        report.add(Finding(
            severity="HARD", rule="bad-min-history-sdk",
            path=_display(SDK_SAFE_READER_TS),
            detail=f"MIN_HISTORY_REQUIRED must equal {EXPECTED_MIN_HISTORY}",
        ))

    # Reject reason strings present (we don't enforce the NO_CURRENT_CERT
    # name here — that's an SDK-only branch; the wire-stable reasons are
    # the three the API also emits).
    for reason in EXPECTED_REJECT_REASONS:
        if f'"{reason}"' not in text:
            report.add(Finding(
                severity="HARD", rule="missing-reject-reason-sdk",
                path=_display(SDK_SAFE_READER_TS),
                detail=(
                    f"reject reason {reason!r} missing — wire-stable, must "
                    f"appear as a string literal in the RejectReason enum"
                ),
            ))


def _check_sdk_index_exports(report: Report) -> None:
    """A future refactor that hides SafeCertReader breaks every DeFi
    consumer that imports it from `@helixor/sdk` — pin the public export."""
    text = _require_file(report, SDK_INDEX_TS, "missing-sdk-index")
    if text is None:
        return

    required = [
        "SafeCertReader",
        "RejectReason",
        "CERT_MAX_AGE_SECONDS",
        "MAX_SCORE_VELOCITY",
        "VELOCITY_WINDOW_EPOCHS",
        "MIN_HISTORY_REQUIRED",
    ]
    for name in required:
        if name not in text:
            report.add(Finding(
                severity="HARD", rule="sdk-export-missing",
                path=_display(SDK_INDEX_TS),
                detail=(
                    f"{name} is not re-exported from sdk/index.ts — DeFi "
                    f"consumers cannot import it as `from '@helixor/sdk'`"
                ),
            ))


# ── API ───────────────────────────────────────────────────────────────────────

def _check_api_safe_score(report: Report) -> None:
    """The API mirror must exist, expose the same constants AT THE SAME
    VALUES, and emit the wire-stable reject-reason strings."""
    text = _require_file(report, API_SAFE_SCORE_PY, "missing-api-safe-score")
    if text is None:
        return

    if not re.search(r"\bdef\s+compute_safe_score\s*\(", text):
        report.add(Finding(
            severity="HARD", rule="compute_safe_score-missing",
            path=_display(API_SAFE_SCORE_PY),
            detail=(
                "compute_safe_score() must exist — the API mirror of the "
                "SDK SafeCertReader (VULN-23)"
            ),
        ))

    # Same numeric values as the SDK.
    age_re = (
        r"CERT_MAX_AGE_SECONDS\s*:?\s*int\s*=\s*"
        rf"(?:48\s*\*\s*60\s*\*\s*60|{EXPECTED_MAX_AGE_SECONDS})\b"
    )
    if not re.search(age_re, text):
        report.add(Finding(
            severity="HARD", rule="bad-max-age-api",
            path=_display(API_SAFE_SCORE_PY),
            detail=(
                f"CERT_MAX_AGE_SECONDS must equal {EXPECTED_MAX_AGE_SECONDS} "
                f"on the API side — must match the SDK"
            ),
        ))
    if not re.search(
        rf"MAX_SCORE_VELOCITY\s*:?\s*int\s*=\s*{EXPECTED_MAX_VELOCITY}\b", text,
    ):
        report.add(Finding(
            severity="HARD", rule="bad-max-velocity-api",
            path=_display(API_SAFE_SCORE_PY),
            detail=f"MAX_SCORE_VELOCITY must equal {EXPECTED_MAX_VELOCITY}",
        ))
    if not re.search(
        rf"VELOCITY_WINDOW_EPOCHS\s*:?\s*int\s*=\s*{EXPECTED_WINDOW_EPOCHS}\b", text,
    ):
        report.add(Finding(
            severity="HARD", rule="bad-window-epochs-api",
            path=_display(API_SAFE_SCORE_PY),
            detail=f"VELOCITY_WINDOW_EPOCHS must equal {EXPECTED_WINDOW_EPOCHS}",
        ))
    if not re.search(
        rf"MIN_HISTORY_REQUIRED\s*:?\s*int\s*=\s*{EXPECTED_MIN_HISTORY}\b", text,
    ):
        report.add(Finding(
            severity="HARD", rule="bad-min-history-api",
            path=_display(API_SAFE_SCORE_PY),
            detail=f"MIN_HISTORY_REQUIRED must equal {EXPECTED_MIN_HISTORY}",
        ))

    # Wire-stable reason strings.
    for reason in EXPECTED_REJECT_REASONS:
        if f'"{reason}"' not in text:
            report.add(Finding(
                severity="HARD", rule="missing-reject-reason-api",
                path=_display(API_SAFE_SCORE_PY),
                detail=(
                    f"reject reason {reason!r} missing on the API side — "
                    f"wire-stable, must match the SDK enum value"
                ),
            ))


def _check_api_route_wired(report: Report) -> None:
    """The /safe_score route must be registered in app.py."""
    text = _require_file(report, API_APP_PY, "missing-api-app")
    if text is None:
        return

    if "/safe_score" not in text:
        report.add(Finding(
            severity="HARD", rule="safe_score-route-missing",
            path=_display(API_APP_PY),
            detail=(
                "/agents/{wallet}/safe_score not registered in app.py — "
                "REST consumers cannot reach the VULN-23 wrapper"
            ),
        ))
    if "compute_safe_score" not in text:
        report.add(Finding(
            severity="HARD", rule="compute_safe_score-not-called",
            path=_display(API_APP_PY),
            detail=(
                "app.py does not call compute_safe_score — the route must "
                "delegate to the shared helper, not reimplement the check"
            ),
        ))


def _check_api_schema_response(report: Report) -> None:
    """The wire shape for safe_score must exist as a Pydantic model so a
    schema-breaking change to the response is caught at type-check time."""
    text = _require_file(report, API_SCHEMAS_PY, "missing-api-schemas")
    if text is None:
        return

    if "SafeScoreResponse" not in text:
        report.add(Finding(
            severity="HARD", rule="SafeScoreResponse-missing",
            path=_display(API_SCHEMAS_PY),
            detail=(
                "SafeScoreResponse Pydantic model missing — the wire shape "
                "must be pinned so an accidental rename is caught by mypy"
            ),
        ))


# =============================================================================
# Driver
# =============================================================================

def scan() -> Report:
    report = Report()
    _check_sdk_safe_reader(report)
    _check_sdk_index_exports(report)
    _check_api_safe_score(report)
    _check_api_route_wired(report)
    _check_api_schema_response(report)
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="VULN-23 cert-consumption sweep.")
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
            f"\n❌ {report.hard_count} HARD cert-consumption findings",
            file=sys.stderr,
        )
        return 1
    print(
        f"✅ cert-consumption sweep clean "
        f"({report.files_scanned} files scanned)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
