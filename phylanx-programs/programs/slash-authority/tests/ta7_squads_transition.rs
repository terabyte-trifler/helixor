// =============================================================================
// programs/slash-authority/tests/ta7_squads_transition.rs
//
// TA-7: admin-key → Squads-multisig transition deadline.
//
// Pure tests pinning:
//   * SQUADS_TRANSITION_DEADLINE_UNIX is 2026-09-01T00:00:00Z
//   * SQUADS_TRANSITION_DEADLINE_ISO matches the unix value
//   * is_before_squads_transition / is_after_squads_transition are
//     each other's exact inverse
//   * the boundary is the exact second — a regression that ±1's the
//     comparison fails loud
// =============================================================================

use slash_authority::state::{
    is_after_squads_transition, is_before_squads_transition,
    SQUADS_TRANSITION_DEADLINE_ISO, SQUADS_TRANSITION_DEADLINE_UNIX,
};

#[test]
fn deadline_is_pinned_to_2026_09_01_utc() {
    // 2026-09-01T00:00:00Z = 1_788_220_800. Pinned in the source; the
    // test exists so the constant cannot be moved without a code review.
    assert_eq!(SQUADS_TRANSITION_DEADLINE_UNIX, 1_788_220_800);
    assert_eq!(SQUADS_TRANSITION_DEADLINE_ISO, "2026-09-01T00:00:00Z");
}

#[test]
fn before_predicate_true_strictly_before_deadline() {
    assert!(is_before_squads_transition(SQUADS_TRANSITION_DEADLINE_UNIX - 1));
    assert!(is_before_squads_transition(0));
    assert!(is_before_squads_transition(i64::MIN));
}

#[test]
fn before_predicate_false_at_deadline_and_after() {
    // At the exact second: NOT before. The handler that gates on this
    // predicate refuses on-chain calls at second == deadline. Pinned
    // explicitly so a future refactor does not accidentally turn `<`
    // into `<=`.
    assert!(!is_before_squads_transition(SQUADS_TRANSITION_DEADLINE_UNIX));
    assert!(!is_before_squads_transition(SQUADS_TRANSITION_DEADLINE_UNIX + 1));
    assert!(!is_before_squads_transition(i64::MAX));
}

#[test]
fn after_predicate_is_exact_inverse_of_before() {
    for t in [
        i64::MIN, -1, 0,
        SQUADS_TRANSITION_DEADLINE_UNIX - 1,
        SQUADS_TRANSITION_DEADLINE_UNIX,
        SQUADS_TRANSITION_DEADLINE_UNIX + 1,
        i64::MAX,
    ] {
        assert_eq!(
            is_after_squads_transition(t),
            !is_before_squads_transition(t),
            "predicates disagreed at t = {t}",
        );
    }
}

#[test]
fn deadline_is_in_the_future_at_authoring_time() {
    // 2026-05-26 (audit re-test) = 1_779_753_600 < deadline. Sanity check
    // that the deadline is meaningful — a constant in the past would
    // brick admin paths immediately.
    let audit_authoring_unix = 1_779_753_600_i64;
    assert!(audit_authoring_unix < SQUADS_TRANSITION_DEADLINE_UNIX);
}
