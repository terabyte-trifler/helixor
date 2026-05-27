// =============================================================================
// programs/health-oracle/tests/epoch_logic.rs
//
// Pure unit tests for the EpochState helpers. No runtime — these exercise
// the layout constants, the may_advance gate, and the liveness_fallback_elapsed
// gate (VULN-02 fix) in isolation.
//
// AW-02 adds digest / domain-separation pinning tests for the M-of-N
// threshold-attested advance path. The Ed25519-precompile parsing and the
// in-handler tier ordering are covered by unit tests inside the
// advance_epoch module itself (cargo test --lib).
// Full on-chain behaviour (the CPI, epoch-keyed cert PDAs, advance authority
// rotation, M-of-N tx assembly) is exercised by the TypeScript integration
// tests.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use health_oracle::instructions::advance_epoch::{
    advance_payload_digest, ADVANCE_EPOCH_DOMAIN_TAG,
};
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

// =============================================================================
// AW-02: advance digest — domain separation and per-tick uniqueness
// =============================================================================
//
// The Tier-1 normal advance path now requires M-of-N cluster Ed25519
// attestations over `advance_payload_digest(current_epoch, target_epoch,
// last_advanced_at)`. These tests pin the digest's anti-replay properties.

#[test]
fn aw02_domain_tag_is_exactly_helixor_epoch_advance() {
    // Pin the literal bytes. A change here is a breaking on-chain protocol
    // change — every queued cluster attestation would be invalidated.
    assert_eq!(ADVANCE_EPOCH_DOMAIN_TAG, b"helixor-epoch-advance");
    assert_eq!(ADVANCE_EPOCH_DOMAIN_TAG.len(), 21);
}

#[test]
fn aw02_domain_tag_is_distinct_from_cert_and_challenge_tags() {
    // The three protocol digests must never collide. Distinct domain tags
    // are the only defence preventing a cert-signing or challenge
    // attestation from being lifted into an epoch-advance attestation.
    assert_ne!(ADVANCE_EPOCH_DOMAIN_TAG, b"helixor-cert-v1");
    assert_ne!(ADVANCE_EPOCH_DOMAIN_TAG, b"helixor-aw01-ext-challenge");
}

#[test]
fn aw02_digest_changes_across_consecutive_ticks() {
    // The crucial defence: a stash of cluster sigs for advance N→N+1 at
    // timestamp T1 cannot be reused to push through advance N→N+1 at a
    // later timestamp T2 (e.g. by an attacker holding sigs in reserve
    // and waiting for an opportune moment). last_advanced_at differs
    // between any two real ticks, so the digests differ.
    let a = advance_payload_digest(7, 8, 1_700_000_000);
    let b = advance_payload_digest(7, 8, 1_700_086_400); // +24h
    assert_ne!(a, b);
}

#[test]
fn aw02_digest_changes_for_different_target_epochs() {
    // Defence against "epoch-skipping" cross-replay: a cluster sig for
    // advancing TO epoch 50 cannot be reused to advance TO epoch 100.
    let a = advance_payload_digest(49, 50, 1_700_000_000);
    let b = advance_payload_digest(49, 100, 1_700_000_000);
    assert_ne!(a, b);
}

#[test]
fn aw02_digest_changes_for_different_current_epochs() {
    // Defence against "epoch-rewind" attacks: a sig issued when the
    // cluster believed current_epoch was 5 cannot be reused when
    // current_epoch is something else, even if target_epoch matches.
    let a = advance_payload_digest(5, 6, 0);
    let b = advance_payload_digest(7, 6, 0);
    assert_ne!(a, b);
}

#[test]
fn aw02_digest_is_deterministic_for_same_inputs() {
    // A cluster member computing the digest off-chain must get the same
    // 32 bytes the on-chain verifier computes — full bit-for-bit match.
    let a = advance_payload_digest(123, 124, 1_777_000_000);
    let b = advance_payload_digest(123, 124, 1_777_000_000);
    assert_eq!(a, b);
}

// =============================================================================
// C-01: submit_score vs advance_epoch boundary-race witness
// =============================================================================
//
// The audit raised C-01 as a putative race between submit_score (reads
// EpochState.current_epoch) and advance_epoch (writes it). The verification
// chain that closes C-01 to fail-closed is:
//
//   (a) Solana's runtime serialises writers against readers on the same
//       account, so advance_epoch and submit_score CANNOT interleave on
//       EpochState — ordering is total within any slot.
//   (b) submit_score enforces `epoch == epoch_state.current_epoch`, so a
//       caller cannot smuggle a stale `epoch` past the on-chain counter.
//   (c) cert_payload_digest folds `epoch` into the bytes the cluster
//       signs over (see certificate-issuer/tests/threshold_logic.rs
//       `digest_changes_with_epoch`). If a caller mutates `epoch` to
//       match a post-tick counter, the rebuilt digest no longer matches
//       any cluster sig → ed25519 verification fails → the CPI reverts
//       atomically with submit_score.
//
// Steps (a) and (b) are Solana/handler invariants tested at runtime; this
// test pins step (c)'s health-oracle-side witness: the advance digest
// itself separates per-tick so even attestations cannot be carried across
// the boundary the race would have exploited.
#[test]
fn c01_advance_digest_separates_pre_and_post_tick_attestations() {
    // Pre-tick state: cluster believes current_epoch = N, target = N+1,
    // last advance happened at T0.
    let pre_tick = advance_payload_digest(5, 6, 1_700_000_000);

    // Post-tick state, in the same slot the race posits: current_epoch
    // has moved to N+1, target to N+2, last_advanced_at to the tick time.
    let post_tick = advance_payload_digest(6, 7, 1_700_086_400);

    // The two digests MUST differ. If they collided, a sig for one tick
    // would carry across to the next — the exact replay vector C-01
    // would have created if epoch were not bound. Pinning this
    // separation prevents a future refactor from accidentally
    // weakening the advance-side binding.
    assert_ne!(pre_tick, post_tick);
}
