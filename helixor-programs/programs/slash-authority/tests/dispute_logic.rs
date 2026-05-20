// =============================================================================
// programs/slash-authority/tests/dispute_logic.rs
//
// Pure unit tests for the Day-21 dispute logic — no runtime. Exercises the
// SlashStatus / ProofType / ChallengeStatus codecs, the appeal-window math,
// the updated layout sizes, and the lifecycle-transition rules. Full
// on-chain behaviour (appeal, resolve, settle, challenge) is exercised by
// the TypeScript integration test.
// =============================================================================

use slash_authority::state::{
    ChallengeCounter, ChallengeStatus, OracleChallenge, ProofType,
    SlashRecord, SlashStatus, APPEAL_WINDOW_SECONDS,
};
use slash_authority::instructions::appeal_slash::APPEAL_COOLDOWN_SECONDS;

// =============================================================================
// Updated layout sizes
// =============================================================================

#[test]
fn slash_record_grew_for_the_lifecycle_fields() {
    // Day 20: 182. Day 21 spends most of the reserve + adds 14 -> 196.
    assert_eq!(SlashRecord::SIZE_WITHOUT_DISCRIMINATOR, 196);
    assert_eq!(SlashRecord::SPACE, 204);
}

#[test]
fn oracle_challenge_size_is_correct() {
    //   32+32+8+1+1+32+32+8+8+8+1+1 = 164  + 32 reserve = 196
    assert_eq!(OracleChallenge::SIZE_WITHOUT_DISCRIMINATOR, 196);
    assert_eq!(OracleChallenge::SPACE, 204);
}

#[test]
fn challenge_counter_size_is_correct() {
    assert_eq!(ChallengeCounter::SPACE, 8 + 32 + 8 + 1);
}

#[test]
fn day21_seed_prefixes_are_stable() {
    assert_eq!(OracleChallenge::SEED_PREFIX, b"challenge");
    assert_eq!(ChallengeCounter::SEED_PREFIX, b"challenge_counter");
}

// =============================================================================
// SlashStatus codec + lifecycle
// =============================================================================

#[test]
fn slash_status_round_trips() {
    for s in [
        SlashStatus::Pending, SlashStatus::Appealed,
        SlashStatus::Overturned, SlashStatus::Settled,
    ] {
        assert_eq!(SlashStatus::from_u8(s.as_u8()), Some(s));
    }
}

#[test]
fn slash_status_codes_are_stable() {
    assert_eq!(SlashStatus::Pending.as_u8(), 0);
    assert_eq!(SlashStatus::Appealed.as_u8(), 1);
    assert_eq!(SlashStatus::Overturned.as_u8(), 2);
    assert_eq!(SlashStatus::Settled.as_u8(), 3);
}

#[test]
fn slash_status_rejects_invalid_code() {
    assert_eq!(SlashStatus::from_u8(4), None);
    assert_eq!(SlashStatus::from_u8(255), None);
}

#[test]
fn overturned_and_settled_are_terminal() {
    assert!(SlashStatus::Overturned.is_terminal());
    assert!(SlashStatus::Settled.is_terminal());
}

#[test]
fn pending_and_appealed_are_not_terminal() {
    // A Pending or Appealed slash can still transition — not terminal.
    assert!(!SlashStatus::Pending.is_terminal());
    assert!(!SlashStatus::Appealed.is_terminal());
}

// =============================================================================
// Appeal window math
// =============================================================================

fn record_with_deadline(deadline: i64) -> SlashRecord {
    SlashRecord {
        agent_wallet:     Default::default(),
        index:            0,
        offense_tier:     0,
        slashed_lamports: 0,
        destination:      0,
        evidence_hash:    [0u8; 32],
        stake_before:     0,
        stake_after:      0,
        executed_at:      0,
        executor:         Default::default(),
        bump:             0,
        layout_version:   1,
        status:           SlashStatus::Pending.as_u8(),
        appeal_deadline:  deadline,
        appeal_hash:      [0u8; 32],
        appealed_at:      0,
        _reserved:        [0u8; 7],
    }
}

#[test]
fn appeal_window_open_before_deadline() {
    let r = record_with_deadline(1_000_000);
    assert!(r.appeal_window_open(999_999));
}

#[test]
fn appeal_window_closed_at_deadline() {
    let r = record_with_deadline(1_000_000);
    // At exactly the deadline the window is CLOSED — settlement may proceed.
    assert!(!r.appeal_window_open(1_000_000));
}

#[test]
fn appeal_window_closed_after_deadline() {
    let r = record_with_deadline(1_000_000);
    assert!(!r.appeal_window_open(1_000_100));
}

#[test]
fn appeal_window_is_72_hours() {
    assert_eq!(APPEAL_WINDOW_SECONDS, 72 * 3_600);
}

#[test]
fn appeal_cooldown_is_24_hours() {
    assert_eq!(APPEAL_COOLDOWN_SECONDS, 24 * 3_600);
}

// =============================================================================
// ProofType codec + on-chain verifiability
// =============================================================================

#[test]
fn proof_type_round_trips() {
    for p in [
        ProofType::ConflictingScores, ProofType::PhantomAgent,
        ProofType::EvidenceHash,
    ] {
        assert_eq!(ProofType::from_u8(p.as_u8()), Some(p));
    }
}

#[test]
fn proof_type_rejects_invalid_code() {
    assert_eq!(ProofType::from_u8(3), None);
}

#[test]
fn conflicting_scores_and_phantom_agent_are_onchain_verifiable() {
    assert!(ProofType::ConflictingScores.is_onchain_verifiable());
    assert!(ProofType::PhantomAgent.is_onchain_verifiable());
}

#[test]
fn evidence_hash_is_not_onchain_verifiable() {
    // Honest scope: an off-chain claim cannot be auto-verified on chain.
    assert!(!ProofType::EvidenceHash.is_onchain_verifiable());
}

// =============================================================================
// ChallengeStatus codec
// =============================================================================

#[test]
fn challenge_status_round_trips() {
    for s in [
        ChallengeStatus::Pending, ChallengeStatus::Verified,
        ChallengeStatus::Dismissed,
    ] {
        assert_eq!(ChallengeStatus::from_u8(s.as_u8()), Some(s));
    }
}

#[test]
fn challenge_status_codes_are_stable() {
    assert_eq!(ChallengeStatus::Pending.as_u8(), 0);
    assert_eq!(ChallengeStatus::Verified.as_u8(), 1);
    assert_eq!(ChallengeStatus::Dismissed.as_u8(), 2);
}
