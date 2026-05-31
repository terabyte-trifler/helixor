// =============================================================================
// programs/certificate-issuer/tests/h01_strict_majority_threshold.rs
//
// H-01 — strict-majority threshold ENFORCED at config-write time.
//
// THE AUDIT FINDING
// -----------------
// `IssuerConfig.threshold` controls how many cluster-key Ed25519
// signatures a cert write must carry. A sub-majority threshold (e.g.
// 2 of 5) is a quorum-safety break: two compromised cluster nodes can
// issue a valid cert against the wishes of the other three. The init
// + rotate paths inlined a strict-majority check, but a future write
// path could silently allow a sub-majority value to be persisted.
//
// THE FIX
// -------
// `IssuerConfig::is_strict_majority_threshold(threshold, cluster_size)`
// is the SINGLE source of truth. Both `initialize_config` and
// `rotate_cluster_keys` defer to it, AND
// `verify_threshold_signatures` calls it at runtime as defence-in-depth.
//
// WHAT THIS FILE PINS
// -------------------
//   * The helper's truth table across the full permitted cluster-size
//     range (1, 3, 4, 5) — every valid + invalid threshold combination.
//   * Edge cases the helper MUST reject: cluster_size == 0 (no cluster),
//     cluster_size == 2 (the InvalidClusterSize size — strict-majority
//     would be threshold == 2 == n which is unanimity, not majority).
//   * The classical canonical strict-majority test cases
//     (3-of-5, 2-of-3) accept; (1-of-3, 2-of-5) reject.
// =============================================================================

use certificate_issuer::state::IssuerConfig;

// -----------------------------------------------------------------------------
// Single-node (degenerate)
// -----------------------------------------------------------------------------

#[test]
fn single_node_cluster_requires_threshold_one() {
    // The degenerate "single issuer" pre-Phase-4 deployment.
    assert!(IssuerConfig::is_strict_majority_threshold(1, 1));
    // Threshold 0 is not allowed.
    assert!(!IssuerConfig::is_strict_majority_threshold(0, 1));
    // Threshold 2 of 1 is structurally impossible.
    assert!(!IssuerConfig::is_strict_majority_threshold(2, 1));
}

// -----------------------------------------------------------------------------
// 2-node — STRUCTURALLY rejected upstream; helper returns false uniformly
// -----------------------------------------------------------------------------

#[test]
fn two_node_cluster_is_uniformly_rejected_by_helper() {
    // The init + rotate paths reject cluster_size == 2 with
    // `InvalidClusterSize`. The helper additionally returns false for
    // ANY threshold on a 2-node cluster, so a defence-in-depth caller
    // that received a 2-node config still bails.
    for t in 0u8..=3u8 {
        assert!(
            !IssuerConfig::is_strict_majority_threshold(t, 2),
            "helper accepted threshold {} on a 2-node cluster — \
             this is the InvalidClusterSize size and the helper must \
             reject every value defensively",
            t,
        );
    }
}

// -----------------------------------------------------------------------------
// 3-node — strict majority = 2 of 3
// -----------------------------------------------------------------------------

#[test]
fn three_node_cluster_requires_at_least_two_signers() {
    // 0 of 3 — no quorum.
    assert!(!IssuerConfig::is_strict_majority_threshold(0, 3));
    // 1 of 3 — NOT a strict majority (1 < 3/2 + 1 = 2).
    assert!(!IssuerConfig::is_strict_majority_threshold(1, 3));
    // 2 of 3 — strict majority. Canonical 3-of-1 fault-tolerance.
    assert!(IssuerConfig::is_strict_majority_threshold(2, 3));
    // 3 of 3 — unanimity, also strict majority. Permitted.
    assert!(IssuerConfig::is_strict_majority_threshold(3, 3));
    // 4 of 3 — structurally impossible.
    assert!(!IssuerConfig::is_strict_majority_threshold(4, 3));
}

// -----------------------------------------------------------------------------
// 4-node — strict majority = 3 of 4
// -----------------------------------------------------------------------------

#[test]
fn four_node_cluster_requires_at_least_three_signers() {
    for t in 0u8..=2u8 {
        assert!(!IssuerConfig::is_strict_majority_threshold(t, 4));
    }
    assert!(IssuerConfig::is_strict_majority_threshold(3, 4));
    assert!(IssuerConfig::is_strict_majority_threshold(4, 4));
    assert!(!IssuerConfig::is_strict_majority_threshold(5, 4));
}

// -----------------------------------------------------------------------------
// 5-node — strict majority = 3 of 5. THE CANONICAL DEPLOYMENT.
// -----------------------------------------------------------------------------

#[test]
fn five_node_cluster_requires_at_least_three_signers() {
    for t in 0u8..=2u8 {
        // 2 of 5 is the classical "sub-majority quorum break" — two
        // compromised nodes should NOT be able to issue a cert.
        assert!(
            !IssuerConfig::is_strict_majority_threshold(t, 5),
            "helper accepted sub-majority threshold {} on a 5-node cluster",
            t,
        );
    }
    assert!(IssuerConfig::is_strict_majority_threshold(3, 5));
    assert!(IssuerConfig::is_strict_majority_threshold(4, 5));
    assert!(IssuerConfig::is_strict_majority_threshold(5, 5));
    assert!(!IssuerConfig::is_strict_majority_threshold(6, 5));
}

// -----------------------------------------------------------------------------
// Zero / pathological edges
// -----------------------------------------------------------------------------

#[test]
fn zero_cluster_size_is_rejected() {
    // An uninitialised config that somehow reached the helper.
    for t in 0u8..=5u8 {
        assert!(!IssuerConfig::is_strict_majority_threshold(t, 0));
    }
}

// -----------------------------------------------------------------------------
// Property: for every cluster size in {1, 3..=5}, there exists EXACTLY
// one minimum strict-majority threshold.
// -----------------------------------------------------------------------------

#[test]
fn minimum_strict_majority_threshold_matches_floor_n_over_2_plus_1() {
    let cases: &[(usize, u8)] = &[
        (1, 1),  // single-node
        (3, 2),  // 2-of-3
        (4, 3),  // 3-of-4
        (5, 3),  // 3-of-5 (canonical)
    ];
    for &(n, expected_min) in cases {
        // The expected-minimum threshold passes.
        assert!(
            IssuerConfig::is_strict_majority_threshold(expected_min, n),
            "expected minimum threshold {} for n={} did NOT pass — \
             the strict-majority formula has drifted from `n/2 + 1`",
            expected_min, n,
        );
        // Any threshold one below MUST fail.
        if expected_min > 0 {
            assert!(
                !IssuerConfig::is_strict_majority_threshold(
                    expected_min - 1, n,
                ),
                "helper accepted threshold {} for n={} — \
                 the strict-majority floor relaxed by one",
                expected_min - 1, n,
            );
        }
    }
}
