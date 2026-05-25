"""
api/safe_score.py — VULN-23 consumer-side guard rails on the read API.

This module is the HTTP mirror of the SDK's `SafeCertReader`
(helixor-sdk/src/safe_reader.ts). HTTP-only consumers (browsers, the
ElizaOS plugin, off-chain Python tooling) cannot import the TypeScript
SDK; without an equivalent on the API a DeFi integrator that talks REST
loses the freshness + velocity guards that VULN-23 mandates.

THE CONSTANTS MUST MATCH THE SDK
--------------------------------
The numbers below ARE the audit mandate. A drift between the SDK and the
API would silently weaken whichever side is laxer; the static scanner
(audit/cert_consumption_check.py) cross-checks both. Bumping any of them
requires an audit sign-off documented next to the change.

WHY USE LATEST-SCORE EPOCH AS "CURRENT" INSTEAD OF READING THE CHAIN
--------------------------------------------------------------------
The API is a read-side cache over the indexer's database; it deliberately
does NOT hold a Solana RPC connection (so it can sustain 10K req/h
without RPC backpressure). The freshness check on wall-clock `issued_at`
naturally subsumes a "live epoch" check: if the indexer falls behind, or
the cluster stops issuing certs, the latest indexed cert's `issued_at`
ages past CERT_MAX_AGE_SECONDS and the wrapper refuses. An attacker
cannot exploit indexer lag because the wall-clock check is enforced on
top of whatever the indexer has.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

from api.score_repo import ScoreRecord, ScoreRepository


# =============================================================================
# Audit-mandated constants — MUST match helixor-sdk/src/safe_reader.ts
# =============================================================================

CERT_MAX_AGE_SECONDS:    int = 48 * 60 * 60      # 48 hours
MAX_SCORE_VELOCITY:      int = 200               # mirrors apply_delta_guard_rail
VELOCITY_WINDOW_EPOCHS:  int = 3                 # this epoch + 2 prior
MIN_HISTORY_REQUIRED:    int = 2                 # need a pair to claim velocity


# =============================================================================
# Reasons — wire-stable enum strings
# =============================================================================

# These strings are the public wire format. Renaming any of them is a
# breaking change for downstream protocols that switch() on the value.

REASON_STALE_CERT:           str = "STALE_CERT"
REASON_VELOCITY_EXCEEDED:    str = "VELOCITY_EXCEEDED"
REASON_INSUFFICIENT_HISTORY: str = "INSUFFICIENT_HISTORY"


# =============================================================================
# Result types
# =============================================================================

@dataclass(frozen=True, slots=True)
class SafeScoreOk:
    score:            int
    alert_tier:       str            # "GREEN" | "YELLOW" | "RED"
    alert_tier_code:  int            # 0 | 1 | 2
    epoch:            int
    issued_at_unix:   int            # latest cert's issued_at, in unix seconds
    velocity_min:     int            # min score across window
    velocity_max:     int            # max score across window
    window_epochs:    tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SafeScoreRejected:
    reason:  str
    detail:  str


SafeScoreResult = SafeScoreOk | SafeScoreRejected


# =============================================================================
# The check
# =============================================================================

_TIER_LABEL = {0: "GREEN", 1: "YELLOW", 2: "RED"}


def _as_unix(dt: datetime) -> int:
    """The ScoreRecord stores `computed_at` as a tz-aware datetime; we
    treat that as the cert's wall-clock issuance time for freshness."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def compute_safe_score(
    repo:           ScoreRepository,
    wallet:         str,
    *,
    now_unix:       int | None = None,
    max_age_seconds: int       = CERT_MAX_AGE_SECONDS,
    max_velocity:    int       = MAX_SCORE_VELOCITY,
    window_epochs:   int       = VELOCITY_WINDOW_EPOCHS,
) -> SafeScoreResult:
    """
    The VULN-23 wrapper. Returns either a `SafeScoreOk` (the protocol is
    SAFE to act on the contained score) or a `SafeScoreRejected` (the
    protocol MUST refuse the operation).

    NEVER falls through to default-allow on rejection — the whole point
    of this wrapper is to make refusal the safe default.
    """
    if window_epochs < MIN_HISTORY_REQUIRED:
        raise ValueError(
            f"window_epochs ({window_epochs}) must be >= "
            f"{MIN_HISTORY_REQUIRED}"
        )
    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be positive")
    if max_velocity < 0:
        raise ValueError("max_velocity must be non-negative")

    now = now_unix if now_unix is not None else int(time.time())

    latest = repo.latest_score(wallet)
    if latest is None:
        return SafeScoreRejected(
            reason=REASON_INSUFFICIENT_HISTORY,
            detail=(
                f"agent {wallet} has no indexed scores; need >= "
                f"{MIN_HISTORY_REQUIRED} certs in the last "
                f"{window_epochs} epochs"
            ),
        )

    current_epoch = latest.epoch
    from_epoch = max(1, current_epoch - (window_epochs - 1))
    history = repo.score_history(
        wallet,
        from_epoch=from_epoch, to_epoch=current_epoch,
        limit=window_epochs,
    )

    if len(history) < MIN_HISTORY_REQUIRED:
        return SafeScoreRejected(
            reason=REASON_INSUFFICIENT_HISTORY,
            detail=(
                f"agent {wallet} has {len(history)} cert(s) in epochs "
                f"{from_epoch}..{current_epoch}; need >= "
                f"{MIN_HISTORY_REQUIRED} to make a velocity claim"
            ),
        )

    # Freshness on the latest cert.
    issued_at = _as_unix(latest.computed_at)
    age_seconds = now - issued_at
    if age_seconds > max_age_seconds:
        return SafeScoreRejected(
            reason=REASON_STALE_CERT,
            detail=(
                f"latest cert for agent {wallet} epoch {latest.epoch} is "
                f"{age_seconds}s old (issued_at={issued_at}, now={now}); "
                f"max {max_age_seconds}s"
            ),
        )

    # Velocity across the window.
    scores = [r.score for r in history]
    min_score = min(scores)
    max_score = max(scores)
    velocity = max_score - min_score
    if velocity > max_velocity:
        # Sort newest-first for the detail message; repo already returns
        # that order but we don't trust the order here.
        epochs_sorted = sorted({r.epoch for r in history})
        return SafeScoreRejected(
            reason=REASON_VELOCITY_EXCEEDED,
            detail=(
                f"agent {wallet} score swung {velocity} points across "
                f"epochs {epochs_sorted[0]}..{epochs_sorted[-1]} "
                f"(min={min_score}, max={max_score}); max {max_velocity}"
            ),
        )

    return SafeScoreOk(
        score=latest.score,
        alert_tier=_TIER_LABEL.get(latest.alert_tier, f"UNKNOWN({latest.alert_tier})"),
        alert_tier_code=latest.alert_tier,
        epoch=latest.epoch,
        issued_at_unix=issued_at,
        velocity_min=min_score,
        velocity_max=max_score,
        window_epochs=tuple(sorted({r.epoch for r in history})),
    )
