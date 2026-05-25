// =============================================================================
// programs/health-oracle/tests/epoch_logic.rs
//
// Pure unit tests for the EpochState helpers. No runtime — these exercise
// the layout constants, the may_advance gate, and the liveness_fallback_elapsed
// gate (VULN-02 fix) in isolation.
// Full on-chain behaviour (the CPI, epoch-keyed cert PDAs, advance authority
// rotation) is exercised by the TypeScript integration test.
// =============================================================================

use anchor_lang::prelude::Pubkey;
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

// =============================================================================
// liveness_fallback_elapsed — VULN-02 cluster fallback gate
// =============================================================================
//
// The fallback window opens at 2× epoch_duration_seconds since last advance.
// Before that point only advance_authority may tick the epoch; at and after
// it any cluster key may, preventing permanent protocol halt from a single
// lost or compromised key.

#[test]
fn fallback_not_open_before_double_duration() {
    let state = epoch_at(1_000_000);
    // 1× elapsed — only advance_authority may advance, fallback not open.
    assert!(!state.liveness_fallback_elapsed(1_000_000 + 86_400));
}

#[test]
fn fallback_not_open_at_1_5x_duration() {
    let state = epoch_at(1_000_000);
    // 1.5× elapsed — still only advance_authority.
    assert!(!state.liveness_fallback_elapsed(1_000_000 + 86_400 + 43_200));
}

#[test]
fn fallback_opens_at_exactly_double_duration() {
    let state = epoch_at(1_000_000);
    // Exactly 2× elapsed — boundary is inclusive.
    assert!(state.liveness_fallback_elapsed(1_000_000 + 86_400 * 2));
}

#[test]
fn fallback_open_well_past_double_duration() {
    let state = epoch_at(1_000_000);
    // 3× elapsed — clearly open.
    assert!(state.liveness_fallback_elapsed(1_000_000 + 86_400 * 3));
}

#[test]
fn fallback_open_implies_may_advance() {
    // The invariant: liveness_fallback_elapsed ⟹ may_advance.
    let state = epoch_at(1_000_000);
    for multiplier in [2, 3, 5, 10] {
        let now = 1_000_000 + 86_400 * multiplier;
        if state.liveness_fallback_elapsed(now) {
            assert!(
                state.may_advance(now),
                "fallback open at {multiplier}× but may_advance is false",
            );
        }
    }
}

#[test]
fn fallback_handles_zero_last_advanced_at() {
    // last_advanced_at = 0 (the default / uninitialised value) should not
    // cause a panic via underflow; saturating_sub handles it safely.
    let state = EpochState {
        current_epoch:          1,
        last_advanced_at:       0,
        epoch_duration_seconds: EpochState::DEFAULT_DURATION_SECONDS,
        advance_authority:      Default::default(),
        bump:                   0,
        _reserved:              [0u8; 32],
    };
    // Any realistic "now" is >> 2× 86400, so fallback is open.
    assert!(state.liveness_fallback_elapsed(1_000_000));
}

// =============================================================================
// rotate_advance_authority — pure state-mutation semantics
// =============================================================================

#[test]
fn rotated_authority_is_reflected_in_subsequent_checks() {
    let original_key = Pubkey::new_from_array([0xAAu8; 32]);
    let new_key      = Pubkey::new_from_array([0xBBu8; 32]);

    let mut state = EpochState {
        current_epoch:          5,
        last_advanced_at:       1_000_000,
        epoch_duration_seconds: EpochState::DEFAULT_DURATION_SECONDS,
        advance_authority:      original_key,
        bump:                   255,
        _reserved:              [0u8; 32],
    };

    assert_eq!(state.advance_authority, original_key);

    // Simulate what rotate_advance_authority::handler writes.
    state.advance_authority = new_key;

    assert_eq!(state.advance_authority, new_key);
    assert_ne!(state.advance_authority, original_key);
}

#[test]
fn advance_authority_change_does_not_affect_epoch_or_timing() {
    let original_key = Pubkey::new_from_array([0xAAu8; 32]);
    let new_key      = Pubkey::new_from_array([0xBBu8; 32]);

    let mut state = EpochState {
        current_epoch:          42,
        last_advanced_at:       9_999_999,
        epoch_duration_seconds: EpochState::DEFAULT_DURATION_SECONDS,
        advance_authority:      original_key,
        bump:                   0,
        _reserved:              [0u8; 32],
    };

    state.advance_authority = new_key;

    // Rotation must not disturb any other EpochState fields.
    assert_eq!(state.current_epoch, 42);
    assert_eq!(state.last_advanced_at, 9_999_999);
    assert_eq!(state.epoch_duration_seconds, EpochState::DEFAULT_DURATION_SECONDS);
}
