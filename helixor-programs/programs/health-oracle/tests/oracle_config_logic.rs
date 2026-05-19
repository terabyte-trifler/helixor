// =============================================================================
// programs/health-oracle/tests/oracle_config_logic.rs
//
// Pure unit tests for the Day-23 OracleConfig cluster extensions. No
// runtime — these exercise the layout constant, the membership check, and
// the BFT consensus-threshold math. Full on-chain behaviour
// (initialize_oracle_config validation) is exercised by the TypeScript
// integration test.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use health_oracle::state::OracleConfig;

fn config_with(keys: Vec<Pubkey>) -> OracleConfig {
    OracleConfig {
        authority:      Pubkey::default(),
        oracle_node:    keys.first().copied().unwrap_or_default(),
        oracle_keys:    keys,
        min_confidence: 600,
        bump:           0,
    }
}

// =============================================================================
// Layout
// =============================================================================

#[test]
fn space_reserves_room_for_the_max_cluster() {
    //   8 disc + 32 authority + 32 oracle_node
    // + 4 Vec prefix + 32*5 reserved slots + 2 min_confidence + 1 bump
    let expected = 8 + 32 + 32 + 4 + (32 * 5) + 2 + 1;
    assert_eq!(OracleConfig::SPACE, expected);
    assert_eq!(OracleConfig::SPACE, 239);
}

#[test]
fn cluster_size_constants() {
    assert_eq!(OracleConfig::MAX_ORACLE_KEYS, 5);
    assert_eq!(OracleConfig::MIN_BFT_CLUSTER, 3);
}

#[test]
fn seed_is_stable() {
    assert_eq!(OracleConfig::SEED, b"oracle_config");
}

// =============================================================================
// Cluster membership
// =============================================================================

#[test]
fn cluster_member_is_recognised() {
    let k0 = Pubkey::new_unique();
    let k1 = Pubkey::new_unique();
    let k2 = Pubkey::new_unique();
    let config = config_with(vec![k0, k1, k2]);
    assert!(config.is_cluster_member(&k0));
    assert!(config.is_cluster_member(&k1));
    assert!(config.is_cluster_member(&k2));
}

#[test]
fn non_member_is_rejected() {
    let config = config_with(vec![Pubkey::new_unique(), Pubkey::new_unique()]);
    assert!(!config.is_cluster_member(&Pubkey::new_unique()));
}

// =============================================================================
// BFT consensus threshold — strict majority
// =============================================================================

#[test]
fn single_node_threshold_is_one() {
    let config = config_with(vec![Pubkey::new_unique()]);
    assert_eq!(config.consensus_threshold(), 1);
}

#[test]
fn three_node_threshold_is_two() {
    // 3 nodes -> 2-of-3, tolerating one fault.
    let config = config_with(vec![
        Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(),
    ]);
    assert_eq!(config.consensus_threshold(), 2);
}

#[test]
fn five_node_threshold_is_three() {
    // 5 nodes -> 3-of-5, tolerating two faults.
    let config = config_with((0..5).map(|_| Pubkey::new_unique()).collect());
    assert_eq!(config.consensus_threshold(), 3);
}

#[test]
fn threshold_is_always_a_strict_majority() {
    for n in 1..=5 {
        let config = config_with((0..n).map(|_| Pubkey::new_unique()).collect());
        let t = config.consensus_threshold();
        // A strict majority: 2*t > n, and t is the smallest such value.
        assert!(2 * t > n, "threshold {t} is not a majority of {n}");
        assert!(2 * (t - 1) <= n, "threshold {t} is not minimal for {n}");
    }
}

#[test]
fn min_confidence_is_stored() {
    let config = config_with(vec![Pubkey::new_unique()]);
    assert_eq!(config.min_confidence, 600);
}
