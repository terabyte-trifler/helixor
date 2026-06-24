// =============================================================================
// programs/certificate-issuer/tests/m06_certificate_invalidation.rs
//
// M-6 — authority-gated certificate invalidation (the on-chain recovery path
// for a bad-score cert). The cert PDA is write-once, so a wrong score could
// never be corrected on chain; invalidate_certificate flips challenge_state to
// `Invalidated` (a repudiated state) without mutating the signed content.
//
// This file pins the ChallengeState semantics the on-chain handler relies on;
// the full instruction (authority gate, idempotency, event) is exercised by
// the on-chain smoke test.
// =============================================================================

use certificate_issuer::state::ChallengeState;

#[test]
fn invalidated_is_variant_three() {
    assert_eq!(ChallengeState::Invalidated.as_u8(), 3);
    assert_eq!(ChallengeState::from_u8(3), Some(ChallengeState::Invalidated));
}

#[test]
fn from_u8_round_trips_all_states() {
    for s in [
        ChallengeState::None,
        ChallengeState::Upheld,
        ChallengeState::Rejected,
        ChallengeState::Invalidated,
    ] {
        assert_eq!(ChallengeState::from_u8(s.as_u8()), Some(s));
    }
    assert_eq!(ChallengeState::from_u8(4), None);
}

#[test]
fn invalidated_and_upheld_are_repudiated_none_and_rejected_are_not() {
    // Downstream consumers must treat BOTH an upheld slot-anchor challenge and
    // an authority invalidation as repudiated; None/Rejected are not.
    assert!(ChallengeState::Invalidated.is_repudiated());
    assert!(ChallengeState::Upheld.is_repudiated());
    assert!(!ChallengeState::None.is_repudiated());
    assert!(!ChallengeState::Rejected.is_repudiated());
}
