// =============================================================================
// programs/slash-authority/tests/spof02_authority_rotation.rs
//
// Pure unit tests pinning the SPOF-#2 mitigation: time-locked, 2-of-3-
// attested authority rotation. These cover the pure helpers on
// PendingAuthorityRotation; runtime-level enforcement of the handler
// gates (`NotRotationProposer`, `NotRoleKeyAttester`,
// `RotationTimelockNotElapsed`, `InsufficientAuthorityAttestations`,
// `DuplicateAuthorityAttestation`, `NoopAuthorityRotation`,
// `RotationTimelockTooShort`, `SingleAdminUpdateRemoved`) is covered by
// the TypeScript integration test.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::state::PendingAuthorityRotation;

// ----------------------------------------------------------------------------
// PendingAuthorityRotation: constants
// ----------------------------------------------------------------------------

#[test]
fn min_timelock_is_48_hours() {
    // The audit's review-window floor for any privileged rotation.
    assert_eq!(
        PendingAuthorityRotation::MIN_TIMELOCK_SECONDS,
        48 * 60 * 60,
    );
}

#[test]
fn role_key_count_is_three() {
    // Slash-authority has exactly three role keys: executor, resolver,
    // pauser. Distinct by validate_authority_separation.
    assert_eq!(PendingAuthorityRotation::ROLE_KEY_COUNT, 3);
}

#[test]
fn consensus_threshold_is_two_of_three() {
    // Strict majority of 3 = floor(3/2) + 1 = 2. Two of the three role
    // keys must attest before enactment.
    assert_eq!(PendingAuthorityRotation::CONSENSUS_THRESHOLD, 2);
}

#[test]
fn pda_seed_is_pending_authority_rotation() {
    // Singleton: a second propose fails until the open proposal is
    // enacted or cancelled. The exact byte sequence is part of the
    // wire contract for off-chain indexers.
    assert_eq!(
        PendingAuthorityRotation::SEED,
        b"pending_authority_rotation",
    );
}

#[test]
fn account_space_includes_three_attestation_slots() {
    // SIZE breakdown:
    //   8  discriminator
    // + 32 proposer
    // + 32 * 4 (new_slash_executor, new_appeal_resolver,
    //          new_pause_authority, new_treasury)         = 128
    // + 8  new_settlement_timelock_seconds
    // + 8  enact_after
    // + 4  attestations length prefix
    // + 32 * 3 (reserved attestation slots)               =  96
    // + 8  proposed_at
    // + 1  bump
    //   = 8 + 32 + 128 + 8 + 8 + 4 + 96 + 8 + 1 = 293
    assert_eq!(PendingAuthorityRotation::SPACE, 293);
}

// ----------------------------------------------------------------------------
// PendingAuthorityRotation: is_enactable gating
// ----------------------------------------------------------------------------

fn fresh_with_attestations(n: usize, enact_after: i64) -> PendingAuthorityRotation {
    let mut p = PendingAuthorityRotation {
        enact_after,
        ..Default::default()
    };
    for i in 0..n {
        let mut bytes = [0u8; 32];
        bytes[0] = (i as u8) + 1;
        p.attestations.push(Pubkey::new_from_array(bytes));
    }
    p
}

#[test]
fn enactable_false_before_timelock_even_with_full_attestations() {
    // Defence: a fully-attested proposal still cannot enact until the
    // 48h review window elapses. This is the half of the gate that
    // gives honest cluster members time to detect + cancel a hostile
    // proposal.
    let p = fresh_with_attestations(3, /* enact_after = */ 1_000);
    assert!(!p.is_enactable(999));
    assert!(p.is_enactable(1_000));
    assert!(p.is_enactable(2_000));
}

#[test]
fn enactable_false_with_one_attestation_even_after_timelock() {
    // The other half: timelock elapsed but only 1 of 3 attested.
    // 1 < CONSENSUS_THRESHOLD = 2, so enactment is blocked.
    let p = fresh_with_attestations(1, /* enact_after = */ 100);
    assert!(!p.is_enactable(200));
}

#[test]
fn enactable_true_at_threshold() {
    // Exactly the threshold (2 of 3) AND timelock elapsed: enactable.
    let p = fresh_with_attestations(2, /* enact_after = */ 100);
    assert!(p.is_enactable(200));
}

#[test]
fn enactable_true_above_threshold() {
    // Above the threshold (3 of 3): trivially enactable.
    let p = fresh_with_attestations(3, /* enact_after = */ 100);
    assert!(p.is_enactable(200));
}

// ----------------------------------------------------------------------------
// PendingAuthorityRotation: attestations_remaining
// ----------------------------------------------------------------------------

#[test]
fn remaining_counts_down_to_zero() {
    let mut p = fresh_with_attestations(0, 0);
    assert_eq!(p.attestations_remaining(), 2);

    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    p.attestations.push(Pubkey::new_from_array(bytes));
    assert_eq!(p.attestations_remaining(), 1);

    bytes[0] = 2;
    p.attestations.push(Pubkey::new_from_array(bytes));
    assert_eq!(p.attestations_remaining(), 0);

    // Above threshold: saturates at 0.
    bytes[0] = 3;
    p.attestations.push(Pubkey::new_from_array(bytes));
    assert_eq!(p.attestations_remaining(), 0);
}

// ----------------------------------------------------------------------------
// PendingAuthorityRotation: has_attestation set semantics
// ----------------------------------------------------------------------------

#[test]
fn has_attestation_is_set_membership() {
    let k1 = Pubkey::new_unique();
    let k2 = Pubkey::new_unique();
    let mut p = fresh_with_attestations(0, 0);
    assert!(!p.has_attestation(&k1));
    assert!(!p.has_attestation(&k2));
    p.attestations.push(k1);
    assert!(p.has_attestation(&k1));
    assert!(!p.has_attestation(&k2));
}
