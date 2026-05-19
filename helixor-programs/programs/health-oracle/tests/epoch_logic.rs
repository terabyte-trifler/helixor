// =============================================================================
// programs/health-oracle/tests/epoch_logic.rs
//
// Pure unit tests for the Day-19 EpochState additions. No runtime — these
// exercise the layout constants and the may_advance gate in isolation.
// Full on-chain behaviour (the CPI, epoch-keyed cert PDAs) is exercised by
// the TypeScript integration test.
// =============================================================================

use health_oracle::state::EpochState;

// =============================================================================
// Layout constants
// =============================================================================

#[test]
fn epoch_state_size_is_correct() {
    // 8 discriminator + 8 current_epoch + 8 last_advanced_at
    // + 8 epoch_duration + 32 advance_authority + 1 bump + 32 reserved = 97
    assert_eq!(EpochState::SPACE, 97);
}

#[test]
fn epochs_are_one_indexed() {
    assert_eq!(EpochState::FIRST_EPOCH, 1);
}

#[test]
fn default_duration_is_24h() {
    assert_eq!(EpochState::DEFAULT_DURATION_SECONDS, 86_400);
}

#[test]
fn seed_is_stable() {
    assert_eq!(EpochState::SEED, b"epoch_state");
}

// =============================================================================
// may_advance — the epoch-tick gate
// =============================================================================

fn epoch_at(last_advanced_at: i64) -> EpochState {
    EpochState {
        current_epoch:          1,
        last_advanced_at,
        epoch_duration_seconds: EpochState::DEFAULT_DURATION_SECONDS,
        advance_authority:      Default::default(),
        bump:                   0,
        _reserved:              [0u8; 32],
    }
}

#[test]
fn may_not_advance_before_duration_elapsed() {
    let state = epoch_at(1_000_000);
    // Only 12h elapsed — too early.
    assert!(!state.may_advance(1_000_000 + 43_200));
}

#[test]
fn may_advance_exactly_at_duration() {
    let state = epoch_at(1_000_000);
    // Exactly 24h — the boundary is inclusive.
    assert!(state.may_advance(1_000_000 + 86_400));
}

#[test]
fn may_advance_after_duration() {
    let state = epoch_at(1_000_000);
    // 25h elapsed — well past.
    assert!(state.may_advance(1_000_000 + 90_000));
}

#[test]
fn may_advance_handles_long_gaps() {
    // An oracle that missed several cycles can still advance.
    let state = epoch_at(1_000_000);
    assert!(state.may_advance(1_000_000 + 86_400 * 5));
}
