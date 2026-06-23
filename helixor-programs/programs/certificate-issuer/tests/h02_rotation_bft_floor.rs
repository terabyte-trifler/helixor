// =============================================================================
// programs/certificate-issuer/tests/h02_rotation_bft_floor.rs
//
// H-2 — rotate_cluster_keys must not COLLAPSE a BFT cluster to a single key.
//
// THE AUDIT FINDING
// -----------------
// `rotate_cluster_keys` validated the new cluster with the same shape rules as
// `initialize_config` (size in {1, 3..=5}, strict-majority threshold). Those
// rules still permit rotating a 3-of-5 quorum down to a SINGLE key (size 1,
// threshold 1), and the M-06 proof-of-possession is trivially satisfied by the
// attacker's own key. A compromised issuer `authority` could therefore rotate
// to 1-of-1 and forge every certificate with one signature.
//
// THE FIX
// -------
// `IssuerConfig::rotation_preserves_bft_floor(current_len, new_len)` is the
// single source of truth for the no-downgrade rule, enforced in
// `rotate_cluster_keys` with `ClusterBftFloorViolation`. Once a cluster is BFT
// (>= MIN_BFT_CLUSTER_KEYS), rotation must keep it BFT. A degenerate
// single-issuer cluster (size 1) may still rotate in place or promote.
//
// WHAT THIS FILE PINS
// -------------------
//   * The exact exploit (5 -> 1, 3 -> 1) is rejected.
//   * Legitimate BFT rotations (3->3, 5->3, 3->5) are allowed.
//   * A single-issuer bootstrap (size 1) may rotate in place (1->1) or
//     promote (1->3/4/5).
//   * The floor constant is 3.
// =============================================================================

use certificate_issuer::state::IssuerConfig;

#[test]
fn bft_floor_constant_is_three() {
    assert_eq!(IssuerConfig::MIN_BFT_CLUSTER_KEYS, 3);
}

#[test]
fn bft_cluster_cannot_collapse_to_a_single_key() {
    // The headline exploit: 3-of-5 (or 2-of-3) rotated to 1-of-1.
    assert!(!IssuerConfig::rotation_preserves_bft_floor(5, 1));
    assert!(!IssuerConfig::rotation_preserves_bft_floor(4, 1));
    assert!(!IssuerConfig::rotation_preserves_bft_floor(3, 1));
    // And cannot drop to the (separately-rejected) size 2 either.
    assert!(!IssuerConfig::rotation_preserves_bft_floor(5, 2));
    assert!(!IssuerConfig::rotation_preserves_bft_floor(3, 2));
}

#[test]
fn bft_to_bft_rotation_is_allowed() {
    // Key rotation in place.
    assert!(IssuerConfig::rotation_preserves_bft_floor(3, 3));
    assert!(IssuerConfig::rotation_preserves_bft_floor(5, 5));
    // Legitimate decommissioning WITHIN the BFT range.
    assert!(IssuerConfig::rotation_preserves_bft_floor(5, 3));
    assert!(IssuerConfig::rotation_preserves_bft_floor(4, 3));
    // Growth.
    assert!(IssuerConfig::rotation_preserves_bft_floor(3, 5));
}

#[test]
fn single_issuer_bootstrap_may_rotate_in_place_or_promote() {
    // A degenerate single-issuer cluster (size 1, threshold 1) was never BFT,
    // so the no-downgrade rule does not apply to it.
    assert!(IssuerConfig::rotation_preserves_bft_floor(1, 1)); // 1->1 key swap
    assert!(IssuerConfig::rotation_preserves_bft_floor(1, 3)); // promote to BFT
    assert!(IssuerConfig::rotation_preserves_bft_floor(1, 5));
}

#[test]
fn property_a_bft_source_forces_a_bft_target() {
    // For every (current, new) over the permitted size domain, a BFT current
    // size implies the rule passes IFF the new size is also BFT.
    for current in [1usize, 3, 4, 5] {
        for new in [1usize, 3, 4, 5] {
            let allowed = IssuerConfig::rotation_preserves_bft_floor(current, new);
            if current >= IssuerConfig::MIN_BFT_CLUSTER_KEYS {
                assert_eq!(
                    allowed,
                    new >= IssuerConfig::MIN_BFT_CLUSTER_KEYS,
                    "BFT current={current} must allow new={new} only when new is BFT",
                );
            } else {
                assert!(allowed, "sub-BFT current={current} must allow any new={new}");
            }
        }
    }
}
