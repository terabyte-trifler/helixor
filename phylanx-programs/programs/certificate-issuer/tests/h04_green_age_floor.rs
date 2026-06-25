// =============================================================================
// programs/certificate-issuer/tests/h04_green_age_floor.rs
//
// H-4 / NSS-3 — on-chain agent-age floor for a GREEN certificate, plus the
// freshness constants the get_certificate gate uses.
//
// THE AUDIT FINDING
// -----------------
// `issue_certificate` validated only `score >= 700 -> GREEN`. The 14-day /
// 168-epoch agent-age floor that should stop a brand-new wallet from carrying
// a GREEN ("fully trusted") cert lived ONLY in the cluster's off-chain Python,
// so a lending contract reading the raw cert PDA (the recommended path) would
// honour a young-agent GREEN cert — the set-up-and-borrow / score-inflation
// class. `HealthCertificate::is_fresh_at` was also dead code on-chain.
//
// THE FIX
// -------
//   * `green_age_floor_satisfied(first_recorded_at, issued_at)` gates GREEN in
//     `issue_certificate`, anchored on the tamper-proof
//     `BaselineStats.first_recorded_at` Clock timestamp.
//   * `get_certificate` gains an optional `max_age_seconds` freshness gate
//     wired to `is_fresh_at` (covered by the on-chain smoke path + ta6).
//
// WHAT THIS FILE PINS (runtime-free)
// ----------------------------------
// The pure age-floor predicate across the boundary, the legacy/grandfather
// sentinel, fail-closed behaviour for a pathological future timestamp, the
// 14-day constant, and the BaselineStats SIZE invariance (the field was carved
// from reserve, not appended).
// =============================================================================

use certificate_issuer::instructions::issue_certificate::green_age_floor_satisfied;
use certificate_issuer::state::{BaselineStats, HealthCertificate};

const DAY: i64 = 24 * 60 * 60;

#[test]
fn min_green_age_is_14_days() {
    assert_eq!(HealthCertificate::MIN_GREEN_AGE_SECONDS, 14 * DAY);
}

#[test]
fn baseline_stats_size_is_unchanged_field_carved_from_reserve() {
    // first_recorded_at (8 bytes) was carved from _reserved (24 -> 16), so the
    // account size is unchanged — no realloc / migration of existing accounts.
    assert_eq!(BaselineStats::SIZE_WITHOUT_DISCRIMINATOR, 147);
    assert_eq!(BaselineStats::SPACE, 155);
}

#[test]
fn brand_new_agent_cannot_get_green() {
    // first baseline recorded "now"; cert issued the same instant -> age 0.
    let first = 1_000_000_000;
    assert!(!green_age_floor_satisfied(first, first));
    // one second short of the floor -> still rejected.
    assert!(!green_age_floor_satisfied(first, first + 14 * DAY - 1));
    // 13 days old -> rejected.
    assert!(!green_age_floor_satisfied(first, first + 13 * DAY));
}

#[test]
fn agent_at_or_past_the_floor_can_get_green() {
    let first = 1_000_000_000;
    // exactly 14 days -> permitted (>= is inclusive).
    assert!(green_age_floor_satisfied(first, first + 14 * DAY));
    // well past the floor.
    assert!(green_age_floor_satisfied(first, first + 365 * DAY));
}

#[test]
fn legacy_zero_sentinel_is_grandfathered() {
    // A pre-H-4 / zeroed-reserve account (first_recorded_at == 0) is exempt:
    // a fresh post-H-4 agent always gets a real Clock timestamp, so an
    // attacker's new wallet can never present 0.
    assert!(green_age_floor_satisfied(0, 1_000_000_000));
    assert!(green_age_floor_satisfied(0, 0));
}

#[test]
fn future_first_recorded_at_fails_closed() {
    // A pathological first_recorded_at AFTER issued_at must not underflow into
    // a huge age and wave GREEN through — saturating_sub yields age 0.
    let issued = 1_000_000_000;
    assert!(!green_age_floor_satisfied(issued + 5 * DAY, issued));
}
