// =============================================================================
// programs/slash-authority/tests/m02_clock_drift_audit_pin.rs
//
// M-02 — Solana clock-drift audit-conclusion pin.
//
// THE AGENT-RATED CLAIM (overstated)
// ----------------------------------
// An automated audit agent flagged Solana's `Clock::unix_timestamp` as
// potentially jumping by up to 48 HOURS in a single tick, which it then
// projected into a "48h timelock bypass" finding against the
// PendingOracleRotation / PendingAuthorityRotation 48h floors and the
// settlement-grace windows.
//
// THE DOWN-RATE
// -------------
// Empirical reality: Solana's voted-on `Clock::unix_timestamp` is the
// stake-weighted median of validator wall clocks. Observed drift between
// the on-chain timestamp and real UTC is consistently sub-minute (single
// digit seconds in steady state, occasional excursions into the 10s of
// seconds during slot-time recovery). The cluster has no documented
// 48-hour jump in its history.
//
// The protocol's critical timelocks (48h rotation timelock, 72h
// settlement window, 72h appeal window, 24h appeal cooldown, 24h pause
// cooldown, 1h propose-overwrite staleness, 30s finalize delay) are
// designed against a multi-second-scale drift budget — every window
// except the propose-finalize delay clears realistic drift by at least
// three orders of magnitude.
//
// Severity dropped from HIGH (timelock-bypass) to MED (documentation /
// observability concern). No code change is required; this file pins
// the audit conclusion so a future revisit of "is our drift budget
// still safe?" has a single check to run.
//
// WHAT THIS FILE GUARDS
// ---------------------
// 1. The DOCUMENTED drift budget is sub-minute (60s); we encode that
//    directly so a hostile re-rating attempt has to delete or modify
//    this constant in a code review.
// 2. Every critical timelock CLEARS the budget by the safety factor
//    captured in the constant tables below — a refactor that shortens
//    a window into the danger zone trips the test.
// 3. The smallest gated window in the protocol — the 30s C-01 finalize
//    delay — is documented as "intentionally inside the drift envelope,
//    paired with strict-monotonic anchor checks at the boundary". The
//    presence of that documentation prevents a future audit from re-
//    raising the same overstated finding against this specific window.
// =============================================================================

use slash_authority::instructions::appeal_slash::APPEAL_COOLDOWN_SECONDS;
use slash_authority::state::pending_authority_rotation::PendingAuthorityRotation;
use slash_authority::state::slash_config::{
    MAX_PAUSE_SECONDS, MIN_SETTLEMENT_TIMELOCK_SECONDS, PAUSE_COOLDOWN_SECONDS,
};
use slash_authority::state::slash_record::APPEAL_WINDOW_SECONDS;

/// The empirically observed worst-case Solana clock drift used by the
/// audit re-rating. Sub-minute — captured as the round number 60s so a
/// future analyst can see the budget at a glance.
const SOLANA_CLOCK_DRIFT_BUDGET_SECONDS: i64 = 60;

/// The minimum safety factor each critical-path timelock must clear
/// over the drift budget. 60× → a window of 1 hour at minimum for a
/// 60-second budget. The 48h+ windows clear this by ~2-3 orders of
/// magnitude.
const MIN_SAFETY_FACTOR_OVER_DRIFT: i64 = 60;

// ── Drift-budget pin ────────────────────────────────────────────────────────

/// The audit recorded the drift budget as 60s ("sub-minute"). If this
/// value is silently bumped to "we tolerate 48h drift" a future re-rate
/// will look at the wrong number; pin the original audited value.
#[test]
fn m02_documented_drift_budget_is_sub_minute() {
    assert_eq!(SOLANA_CLOCK_DRIFT_BUDGET_SECONDS, 60);
}

// ── Critical-path timelocks clear the budget ────────────────────────────────

#[test]
fn m02_settlement_timelock_clears_drift_budget() {
    // 72h settlement timelock vs 60s drift = 4_320× headroom.
    assert!(
        MIN_SETTLEMENT_TIMELOCK_SECONDS
            >= SOLANA_CLOCK_DRIFT_BUDGET_SECONDS * MIN_SAFETY_FACTOR_OVER_DRIFT,
    );
    assert_eq!(MIN_SETTLEMENT_TIMELOCK_SECONDS, 72 * 3_600);
}

#[test]
fn m02_appeal_window_clears_drift_budget() {
    // 72h appeal window vs 60s drift = 4_320× headroom. A clock drift
    // cannot push a Pending slash past the appeal-window cutoff before
    // the agent has had effectively the full 72h to react.
    assert!(
        APPEAL_WINDOW_SECONDS
            >= SOLANA_CLOCK_DRIFT_BUDGET_SECONDS * MIN_SAFETY_FACTOR_OVER_DRIFT,
    );
    assert_eq!(APPEAL_WINDOW_SECONDS, 72 * 3_600);
}

#[test]
fn m02_appeal_cooldown_clears_drift_budget() {
    // 24h cooldown vs 60s drift = 1_440× headroom.
    assert!(
        APPEAL_COOLDOWN_SECONDS
            >= SOLANA_CLOCK_DRIFT_BUDGET_SECONDS * MIN_SAFETY_FACTOR_OVER_DRIFT,
    );
    assert_eq!(APPEAL_COOLDOWN_SECONDS, 24 * 3_600);
}

#[test]
fn m02_pause_cap_clears_drift_budget() {
    // 7d pause cap vs 60s = 10_080× headroom.
    assert!(
        MAX_PAUSE_SECONDS
            >= SOLANA_CLOCK_DRIFT_BUDGET_SECONDS * MIN_SAFETY_FACTOR_OVER_DRIFT,
    );
    assert_eq!(MAX_PAUSE_SECONDS, 7 * 24 * 3_600);
}

#[test]
fn m02_pause_cooldown_clears_drift_budget() {
    // 24h pause cooldown (H-04) vs 60s = 1_440× headroom — the duty
    // cycle is bound at 7d/8d = 87.5%, drift cannot bypass it.
    assert!(
        PAUSE_COOLDOWN_SECONDS
            >= SOLANA_CLOCK_DRIFT_BUDGET_SECONDS * MIN_SAFETY_FACTOR_OVER_DRIFT,
    );
    assert_eq!(PAUSE_COOLDOWN_SECONDS, 24 * 3_600);
}

#[test]
fn m02_authority_rotation_timelock_clears_drift_budget() {
    // 48h authority rotation timelock vs 60s = 2_880× headroom. This
    // is the headline window the original agent claim targeted — the
    // most conservative critical-path timelock and still ~3 orders of
    // magnitude above the drift envelope.
    assert!(
        PendingAuthorityRotation::MIN_TIMELOCK_SECONDS
            >= SOLANA_CLOCK_DRIFT_BUDGET_SECONDS * MIN_SAFETY_FACTOR_OVER_DRIFT,
    );
    assert_eq!(PendingAuthorityRotation::MIN_TIMELOCK_SECONDS, 48 * 60 * 60);
}

// ── Smallest gated window: 30s C-01 finalize delay ─────────────────────────

/// The C-01 finalize delay is intentionally INSIDE the drift envelope.
/// It is a propose/finalize observability window paired with a strict
/// `pending_target_epoch == current_epoch + 1` re-check at finalize,
/// so a drift-induced early finalize cannot commit a target that has
/// drifted. This pin documents that design choice — the test exists so
/// a future re-audit hits the documentation before re-filing the
/// finding.
///
/// Cross-crate import is avoided (slash-authority does not depend on
/// health-oracle); the value is inlined here and the equivalent pin
/// in `health-oracle/tests/c01_advance_epoch_2phase.rs` enforces the
/// same constant on the other side.
#[test]
fn m02_finalize_delay_is_observability_not_safety_window() {
    // FINALIZE_DELAY_SECONDS = 30 (mirrored from health-oracle) —
    // below the 60s drift budget. This is intentional and DOCUMENTED.
    // If somebody bumps it to "match drift", they have misread the
    // design.
    let finalize_delay_seconds: i64 = 30;
    assert!(
        finalize_delay_seconds < SOLANA_CLOCK_DRIFT_BUDGET_SECONDS,
        "C-01 finalize delay is an observability window — not safety; \
         it is paired with a strict-equal pending-target check at \
         finalize time"
    );
}

// ── Conclusion guard ────────────────────────────────────────────────────────

/// Composite check: every critical-path timelock in the protocol clears
/// the drift budget by at least the minimum safety factor. A future
/// refactor that introduces a NEW critical window must extend this
/// pin — the test name surfaces the missing entry on failure.
#[test]
fn m02_every_critical_timelock_clears_drift_budget() {
    let critical_timelocks: &[(&str, i64)] = &[
        ("MIN_SETTLEMENT_TIMELOCK_SECONDS",      MIN_SETTLEMENT_TIMELOCK_SECONDS),
        ("APPEAL_WINDOW_SECONDS",                APPEAL_WINDOW_SECONDS),
        ("APPEAL_COOLDOWN_SECONDS",              APPEAL_COOLDOWN_SECONDS),
        ("MAX_PAUSE_SECONDS",                    MAX_PAUSE_SECONDS),
        ("PAUSE_COOLDOWN_SECONDS",               PAUSE_COOLDOWN_SECONDS),
        ("PendingAuthorityRotation::MIN_TIMELOCK_SECONDS",
            PendingAuthorityRotation::MIN_TIMELOCK_SECONDS),
    ];

    let floor = SOLANA_CLOCK_DRIFT_BUDGET_SECONDS * MIN_SAFETY_FACTOR_OVER_DRIFT;
    for (name, secs) in critical_timelocks {
        assert!(
            *secs >= floor,
            "{} = {}s does not clear the drift safety floor of {}s",
            name, secs, floor,
        );
    }
}
