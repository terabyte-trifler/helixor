// =============================================================================
// programs/slash-authority/tests/vuln08_settle_timing.rs
//
// Pure unit tests pinning the VULN-08 fix: defence-in-depth timing gates
// on settle_slash that mitigate (1) MEV front-running of an appeal, (2)
// same-block griefing by a compromised executor, and (3) invisible
// settle-spray probing of an appeal's mempool window.
//
// Three gates total on settle_slash now:
//   - APPEAL_WINDOW       (Day 21)       — `now >= appeal_deadline`
//   - SETTLEMENT_TIMELOCK (VULN-04)      — `now >= settlement_unlock_at`
//   - VULN-08 #1 (this)   — `now >= executed_at + 48h` (independent floor)
//   - VULN-08 #2 (this)   — `now >= appeal_deadline + 1h grace`
//
// These tests exercise the pure VULN-08 helper `check_settle_timing` in
// isolation. Runtime-level gating (the handler, the
// `SettleSlashAttempted` event) is exercised by the TypeScript
// integration test.
// =============================================================================

use anchor_lang::error::Error as AnchorError;
use slash_authority::errors::SlashError;
use slash_authority::instructions::settle_slash::{
    check_settle_timing, MIN_EXECUTE_TO_SETTLE_SECONDS,
    SETTLE_GRACE_PERIOD_SECONDS,
};

// =============================================================================
// The two new VULN-08 constants
// =============================================================================

#[test]
fn min_execute_to_settle_is_48h() {
    // The audit requires a minimum 48h floor between execute_slash and
    // settle_slash, regardless of appeal status. Belt-and-braces under
    // the 72h appeal window.
    assert_eq!(MIN_EXECUTE_TO_SETTLE_SECONDS, 48 * 3_600);
}

#[test]
fn settle_grace_period_is_one_hour() {
    // 1h grace after the appeal-window deadline closes — protects
    // appeals that landed in the same slot as the deadline against MEV
    // front-running by settle_slash.
    assert_eq!(SETTLE_GRACE_PERIOD_SECONDS, 60 * 60);
}

#[test]
fn min_execute_to_settle_floor_does_not_block_clean_lifecycle() {
    // SANITY: the 48h floor is intended as DEFENCE IN DEPTH only. It
    // must NEVER be the gate that blocks a clean lifecycle — the appeal
    // window (72h) + grace (1h) = 73h is the natural ceiling. 48 < 73,
    // so a clean, un-appealed slash settled at `appeal_deadline + grace`
    // is past the floor.
    assert!(MIN_EXECUTE_TO_SETTLE_SECONDS < 72 * 3_600 + SETTLE_GRACE_PERIOD_SECONDS);
}

// =============================================================================
// Helpers
// =============================================================================

/// Anchor stamps `error_code_number` as the raw `SlashError` discriminant
/// plus the internal +6000 offset. Canonicalise here so the assertions
/// stay readable.
fn err_matches(e: AnchorError, code: SlashError) -> bool {
    match e {
        AnchorError::AnchorError(a) => {
            a.error_code_number
                == code as u32 + anchor_lang::error::ERROR_CODE_OFFSET
        }
        _ => panic!("expected AnchorError, got: {e:?}"),
    }
}

const EXECUTED_AT:     i64 = 1_700_000_000;
// Standard never-appealed slash: appeal_deadline = executed + 72h.
const APPEAL_DEADLINE: i64 = EXECUTED_AT + 72 * 3_600;

// =============================================================================
// Gate A — the 48h execute->settle floor (VULN-08 #2)
// =============================================================================

#[test]
fn floor_blocks_same_block_settlement() {
    // The textbook griefing case from the audit: execute + settle in the
    // same block. With the floor in place, settle is rejected. (The
    // appeal-window check would also catch this, but the floor is the
    // INDEPENDENT belt-and-braces gate.)
    let err = check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, EXECUTED_AT)
        .expect_err("same-block settle must be rejected");
    assert!(err_matches(err, SlashError::ExecuteToSettleGapTooShort));
}

#[test]
fn floor_blocks_one_second_before_48h() {
    let now = EXECUTED_AT + MIN_EXECUTE_TO_SETTLE_SECONDS - 1;
    let err = check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, now)
        .expect_err("settle 1s before 48h floor must be rejected");
    assert!(err_matches(err, SlashError::ExecuteToSettleGapTooShort));
}

#[test]
fn floor_releases_at_exactly_48h_but_grace_still_blocks() {
    // At exactly executed_at + 48h the floor lets us through, but the
    // appeal-window grace period still holds (we're well inside the 72h
    // appeal window). The error attribution flips from the floor to
    // grace.
    let now = EXECUTED_AT + MIN_EXECUTE_TO_SETTLE_SECONDS;
    let err = check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, now)
        .expect_err("the grace gate should fire once the floor releases");
    assert!(err_matches(err, SlashError::AppealGraceWindowActive));
}

// =============================================================================
// Gate B — the 1h post-appeal grace period (VULN-08 #1)
// =============================================================================

#[test]
fn grace_blocks_exactly_at_appeal_deadline() {
    // At t == appeal_deadline the appeal window just closed; an appeal
    // in the same block could still be landing. The 1h grace blocks
    // settle here. (Floor has been satisfied long ago at 48h.)
    let err = check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, APPEAL_DEADLINE)
        .expect_err("settle at appeal_deadline must be rejected by grace");
    assert!(err_matches(err, SlashError::AppealGraceWindowActive));
}

#[test]
fn grace_blocks_one_second_before_grace_ends() {
    let now = APPEAL_DEADLINE + SETTLE_GRACE_PERIOD_SECONDS - 1;
    let err = check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, now)
        .expect_err("settle 1s before grace ends must be rejected");
    assert!(err_matches(err, SlashError::AppealGraceWindowActive));
}

#[test]
fn grace_releases_at_exactly_appeal_deadline_plus_grace() {
    // Both gates clear at t = appeal_deadline + 1h.
    let now = APPEAL_DEADLINE + SETTLE_GRACE_PERIOD_SECONDS;
    assert!(check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, now).is_ok());
}

// =============================================================================
// Clean lifecycle: gates release exactly when expected, never block legit
// =============================================================================

#[test]
fn clean_never_appealed_lifecycle_settles_at_73h() {
    // The natural settle time for an un-appealed Minor: 72h appeal + 1h
    // grace = 73h post-execute. Floor (48h) is dominated by grace here.
    let now = EXECUTED_AT + 72 * 3_600 + SETTLE_GRACE_PERIOD_SECONDS;
    assert!(check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, now).is_ok());
}

#[test]
fn upheld_appeal_lifecycle_settles_after_timelock() {
    // resolve_appeal(uphold=true) sets appeal_deadline = now_resolve
    // (forces window closed). Suppose the resolver upheld at t = 36h.
    // appeal_deadline = 36h post-execute.
    let upheld_at      = EXECUTED_AT + 36 * 3_600;
    let new_deadline   = upheld_at;
    // The settlement_timelock_seconds (>= 72h) handles the upper bound
    // OUTSIDE this helper. From this helper's perspective the gate is:
    //   (a) 48h floor:  satisfied at 48h post-execute
    //   (b) 1h grace:   satisfied at 37h post-execute (= upheld + 1h)
    // The max of (a) and (b) is 48h post-execute — both gates clear.
    let now = EXECUTED_AT + 48 * 3_600;
    assert!(check_settle_timing(EXECUTED_AT, new_deadline, now).is_ok());
}

// =============================================================================
// Error attribution order — the floor check fires FIRST
// =============================================================================

#[test]
fn floor_fires_before_grace_when_both_are_violated() {
    // The handler reports the FIRST failing gate so monitoring tooling
    // gets stable error codes. The floor (gate A) is checked first.
    // Pick a (now, deadline) where BOTH gates would fail to verify the
    // attribution is deterministic.
    let now = EXECUTED_AT + 1; // both gates violated
    let err = check_settle_timing(EXECUTED_AT, APPEAL_DEADLINE, now)
        .expect_err("expected an error");
    assert!(err_matches(err, SlashError::ExecuteToSettleGapTooShort));
}

// =============================================================================
// Overflow safety
// =============================================================================

#[test]
fn checked_arithmetic_rejects_overflow_in_floor() {
    // i64::MAX + 48h would overflow — must surface as MathOverflow, not
    // wrap-around to a passing gate.
    let err = check_settle_timing(i64::MAX, APPEAL_DEADLINE, i64::MAX)
        .expect_err("overflow must error");
    assert!(err_matches(err, SlashError::MathOverflow));
}

#[test]
fn checked_arithmetic_rejects_overflow_in_grace() {
    // executed_at is fine, but appeal_deadline + 1h overflows.
    // To reach the grace check we must clear the floor first, so set
    // executed_at small.
    let now = i64::MAX;
    let err = check_settle_timing(0, i64::MAX, now)
        .expect_err("overflow in grace must error");
    assert!(err_matches(err, SlashError::MathOverflow));
}

// =============================================================================
// Error code stability — consumed by off-chain tooling
// =============================================================================

#[test]
fn vuln08_error_codes_are_stable() {
    // Stability test — the off-chain monitor switches on these codes.
    assert_eq!(SlashError::ExecuteToSettleGapTooShort as u32, 6070);
    assert_eq!(SlashError::AppealGraceWindowActive    as u32, 6071);
}
