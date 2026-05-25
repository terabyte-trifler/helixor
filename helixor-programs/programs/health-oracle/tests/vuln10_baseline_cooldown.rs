// =============================================================================
// programs/health-oracle/tests/vuln10_baseline_cooldown.rs
//
// VULN-10 pin tests for the Oracle-path baseline-commit cooldown and the
// helper that backs it. Runtime-level handler behaviour (event emit,
// account writes) is exercised by the TypeScript integration suite; this
// file is the pure-helper isolation layer that monitors hardware against
// regressions to the timing math.
//
// Audit-mandated behaviours pinned here:
//   - the cooldown is 86_400 seconds (one epoch / 24h),
//   - a FIRST commit is unaffected,
//   - an OWNER commit is unaffected (the audit's emergency-reset path),
//   - an ORACLE rotation is blocked before the cooldown elapses,
//   - it releases at exactly `previous + 86_400`,
//   - overflow in the cooldown addition surfaces as a typed error.
// =============================================================================

use anchor_lang::error::Error as AnchorError;
use health_oracle::errors::HelixorError;
use health_oracle::events::CommitterKind;
use health_oracle::instructions::commit_baseline::{
    check_oracle_commit_cooldown, MIN_SECONDS_BETWEEN_ORACLE_COMMITS,
};

// =============================================================================
// Constant pin
// =============================================================================

#[test]
fn cooldown_is_one_epoch() {
    // Audit-mandated: "cannot update baseline more than once per epoch".
    // The protocol's epoch duration is 86_400s (24h).
    assert_eq!(MIN_SECONDS_BETWEEN_ORACLE_COMMITS, 86_400);
}

// =============================================================================
// Error-code helpers
// =============================================================================

fn err_matches(e: AnchorError, code: HelixorError) -> bool {
    match e {
        AnchorError::AnchorError(a) => {
            a.error_code_number
                == code as u32 + anchor_lang::error::ERROR_CODE_OFFSET
        }
        _ => panic!("expected AnchorError, got: {e:?}"),
    }
}

const PREV_COMMIT_AT: i64 = 1_700_000_000;

// =============================================================================
// First commit — cooldown is a no-op
// =============================================================================

#[test]
fn first_commit_oracle_path_always_allowed() {
    // baseline_committed = false ⇒ no cooldown, regardless of timestamps.
    assert!(check_oracle_commit_cooldown(
        false, 0, CommitterKind::Oracle, 0,
    ).is_ok());
    assert!(check_oracle_commit_cooldown(
        false, i64::MAX, CommitterKind::Oracle, i64::MAX,
    ).is_ok());
}

#[test]
fn first_commit_owner_path_always_allowed() {
    assert!(check_oracle_commit_cooldown(
        false, 0, CommitterKind::Owner, 0,
    ).is_ok());
}

// =============================================================================
// Owner path — the emergency reset, never gated
// =============================================================================

#[test]
fn owner_path_bypasses_cooldown_completely() {
    // Even at the same second as the previous commit, the owner can
    // commit. This is intentional — the owner is the response path the
    // audit relies on to undo a malicious Oracle rotation.
    assert!(check_oracle_commit_cooldown(
        true, PREV_COMMIT_AT, CommitterKind::Owner, PREV_COMMIT_AT,
    ).is_ok());
    assert!(check_oracle_commit_cooldown(
        true, PREV_COMMIT_AT, CommitterKind::Owner, PREV_COMMIT_AT + 1,
    ).is_ok());
}

// =============================================================================
// Oracle rotation — gated
// =============================================================================

#[test]
fn oracle_same_second_rotation_blocked() {
    // The textbook attack: a compromised oracle key rotating immediately
    // after a previous commit. Refused.
    let err = check_oracle_commit_cooldown(
        true, PREV_COMMIT_AT, CommitterKind::Oracle, PREV_COMMIT_AT,
    ).expect_err("same-second oracle rotation must be rejected");
    assert!(err_matches(err, HelixorError::OracleCommitCooldownActive));
}

#[test]
fn oracle_one_second_before_release_blocked() {
    let now = PREV_COMMIT_AT + MIN_SECONDS_BETWEEN_ORACLE_COMMITS - 1;
    let err = check_oracle_commit_cooldown(
        true, PREV_COMMIT_AT, CommitterKind::Oracle, now,
    ).expect_err("rotation 1s before cooldown release must be rejected");
    assert!(err_matches(err, HelixorError::OracleCommitCooldownActive));
}

#[test]
fn oracle_rotation_released_at_exact_boundary() {
    let now = PREV_COMMIT_AT + MIN_SECONDS_BETWEEN_ORACLE_COMMITS;
    assert!(check_oracle_commit_cooldown(
        true, PREV_COMMIT_AT, CommitterKind::Oracle, now,
    ).is_ok());
}

#[test]
fn oracle_rotation_far_after_cooldown_allowed() {
    let now = PREV_COMMIT_AT + 30 * 86_400; // 30 days — normal cadence
    assert!(check_oracle_commit_cooldown(
        true, PREV_COMMIT_AT, CommitterKind::Oracle, now,
    ).is_ok());
}

// =============================================================================
// Overflow safety
// =============================================================================

#[test]
fn overflow_in_cooldown_addition_returns_typed_error() {
    // i64::MAX + 86_400 overflows. The helper must surface this as
    // BaselineTimestampOverflow rather than wrapping around to a passing
    // gate (which would silently DISABLE the cooldown).
    let err = check_oracle_commit_cooldown(
        true, i64::MAX, CommitterKind::Oracle, i64::MAX,
    ).expect_err("overflow must error");
    assert!(err_matches(err, HelixorError::BaselineTimestampOverflow));
}

// =============================================================================
// Error-code stability — consumed by off-chain monitor
// =============================================================================

#[test]
fn vuln10_error_codes_are_stable() {
    // The off-chain monitor switches on these codes.
    assert_eq!(HelixorError::OracleCommitCooldownActive as u32, 6023);
    assert_eq!(HelixorError::BaselineTimestampOverflow  as u32, 6024);
}

// =============================================================================
// Defensive sanity: a normal 30-day rotation is never blocked by the floor.
// =============================================================================

#[test]
fn thirty_day_rotation_is_well_inside_the_allowed_window() {
    // The whole point of the floor is "machine-gun rotations are
    // blocked, normal cadence is not". 30 days > 1 day, so a normal
    // baseline cycle clears the floor by a huge margin.
    assert!(MIN_SECONDS_BETWEEN_ORACLE_COMMITS < 30 * 86_400);
}
