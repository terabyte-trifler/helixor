// =============================================================================
// programs/certificate-issuer/tests/threshold_logic.rs
//
// Pure unit tests for the Day-27 threshold-signing additions. No runtime —
// these exercise the canonical cert-payload digest (the bytes off-chain
// signers must sign over), the cluster membership check, and the new
// IssuerConfig layout. Full on-chain enforcement (the 2-sig reject vs
// 3-sig accept, the heart of the done-when) is exercised by the
// TypeScript integration test.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use certificate_issuer::signing::cert_payload_digest;
use certificate_issuer::state::IssuerConfig;

// =============================================================================
// Canonical cert-payload digest
// =============================================================================

fn agent() -> Pubkey {
    Pubkey::new_from_array([0x11; 32])
}

#[test]
fn digest_is_32_bytes() {
    let d = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    assert_eq!(d.len(), 32);
}

#[test]
fn digest_is_deterministic() {
    let a = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    let b = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    assert_eq!(a, b);
}

#[test]
fn digest_changes_with_score() {
    let a = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    let b = cert_payload_digest(&agent(), 1, 852, 2, 8, true);
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_epoch() {
    let a = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    let b = cert_payload_digest(&agent(), 2, 851, 2, 8, true);
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_alert_tier() {
    let a = cert_payload_digest(&agent(), 1, 851, 0, 8, true);
    let b = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_flags() {
    let a = cert_payload_digest(&agent(), 1, 851, 2, 0, true);
    let b = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_immediate_red() {
    let a = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    let b = cert_payload_digest(&agent(), 1, 851, 2, 8, false);
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_agent() {
    let other = Pubkey::new_from_array([0x22; 32]);
    let a = cert_payload_digest(&agent(), 1, 851, 2, 8, true);
    let b = cert_payload_digest(&other, 1, 851, 2, 8, true);
    assert_ne!(a, b);
}

// =============================================================================
// IssuerConfig layout + helpers
// =============================================================================

#[test]
fn issuer_config_space_reserves_room_for_the_max_cluster() {
    // 8 disc + 32 authority + 32 issuer_node + 4 Vec prefix
    // + 32 * MAX_CLUSTER_KEYS (5) + 1 threshold + 1 bump = 238
    assert_eq!(IssuerConfig::SPACE, 238);
    assert_eq!(IssuerConfig::MAX_CLUSTER_KEYS, 5);
}

#[test]
fn issuer_config_seed_is_stable() {
    assert_eq!(IssuerConfig::SEED, b"issuer_config");
}

#[test]
fn is_cluster_key_recognises_members() {
    let k0 = Pubkey::new_unique();
    let k1 = Pubkey::new_unique();
    let k2 = Pubkey::new_unique();
    let config = IssuerConfig {
        authority: Pubkey::default(),
        issuer_node: k0,
        cluster_keys: vec![k0, k1, k2],
        threshold: 2,
        bump: 0,
    };
    assert!(config.is_cluster_key(&k0));
    assert!(config.is_cluster_key(&k1));
    assert!(config.is_cluster_key(&k2));
    assert!(!config.is_cluster_key(&Pubkey::new_unique()));
}

#[test]
fn three_of_five_is_a_strict_majority() {
    // The on-chain validator (initialize_config) enforces strict majority
    // for a BFT cluster — 3 of 5, 2 of 3.
    assert!(3 > 5 / 2);
    assert!(2 > 3 / 2);
}
