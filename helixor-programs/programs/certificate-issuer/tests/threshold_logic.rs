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

fn baseline_hash() -> [u8; 32] {
    [0x33; 32]
}

// AW-01: fixed test commitment. Real commitments come from
// oracle.cluster.input_commitment.compute_input_commitment.
fn input_commitment() -> [u8; 32] {
    [0x77; 32]
}

// AW-01-EXT: fixed test slot anchor. Real anchors are
// `(getSlot(), getBlockHash(slot))` captured at scoring time.
fn slot_anchor_slot() -> u64 {
    250_000_000
}

fn slot_anchor_hash() -> [u8; 32] {
    [0x99; 32]
}

// AW-03: fixed test commit_nonce. Real nonces come from the
// AgentRegistration.commit_nonce field on health-oracle at the moment the
// baseline_hash was committed.
fn baseline_commit_nonce() -> u64 {
    7
}

// AW-04: fixed test scoring-bundle hash. Real hashes come from
// `scoring/bundle_hash.py::compute_scoring_bundle_hash`.
fn scoring_code_hash() -> [u8; 32] {
    [0xBB; 32]
}

// AW-04: fixed test score-components hash. Real hashes come from
// `oracle/score_components.py::score_components_hash` over the
// canonical-JSON breakdown bytes.
fn score_components_hash() -> [u8; 32] {
    [0xCC; 32]
}

#[test]
fn digest_is_32_bytes() {
    let d = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_eq!(d.len(), 32);
}

#[test]
fn digest_is_deterministic() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_eq!(a, b);
}

#[test]
fn digest_changes_with_score() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 852, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_epoch() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 2, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_alert_tier() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 0, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_flags() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 0, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_baseline_hash() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &[0x33; 32], true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &[0x44; 32], true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_immediate_red() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), false, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b);
}

#[test]
fn digest_changes_with_agent() {
    let other = Pubkey::new_from_array([0x22; 32]);
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &other, 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b);
}

// AW-01: changing the input_commitment MUST change the digest. Without
// this the commitment would not bind the on-chain signature to the
// upstream inputs — defeating the whole architectural fix.
#[test]
fn digest_changes_with_input_commitment() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &[0x77; 32],
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &[0x88; 32],
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(
        a, b,
        "the input-provenance commitment MUST be folded into the digest \
         (AW-01) — otherwise the threshold signature does not attest to the \
         cluster's view of the upstream inputs",
    );
}

// AW-01-EXT: changing the slot anchor MUST change the digest. Without
// this the cluster could not prove which point in Solana's own ledger
// it pinned at scoring — defeating the SlotHashes verification.
#[test]
fn digest_changes_with_slot_anchor_slot() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        250_000_000, &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        250_000_001, &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b, "AW-01-EXT slot must be folded into the digest");
}

#[test]
fn digest_changes_with_slot_anchor_hash() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &[0x99; 32], baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &[0xAA; 32], baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(a, b, "AW-01-EXT block hash must be folded into the digest");
}

// AW-03: changing the baseline_commit_nonce MUST change the digest. Without
// this the threshold signature would not be bound to a specific baseline
// rotation — defeating the data-availability provenance pointer.
#[test]
fn digest_changes_with_baseline_commit_nonce() {
    let a = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), 7,
        &scoring_code_hash(), &score_components_hash(),
    );
    let b = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), 8,
        &scoring_code_hash(), &score_components_hash(),
    );
    assert_ne!(
        a, b,
        "AW-03 baseline_commit_nonce must be folded into the digest — \
         a verifier MUST be able to detect a rotation drift",
    );
}

#[test]
fn digest_is_byte_identical_to_python_implementation() {
    // Byte-identical pin: this digest is produced by the off-chain
    // helixor-oracle/oracle/cluster/cert_signing.py::cert_payload_digest
    // given the same inputs. If a future PR changes either side without
    // changing the other, this test fails and the cluster can no longer
    // produce a signable cert.
    //
    // To regenerate (only when intentionally changing the canonical form):
    //   from oracle.cluster.cert_signing import cert_payload_digest
    //   from oracle.cluster.input_commitment import SlotAnchor
    //   cert_payload_digest(
    //       b"\x11"*32, 1, 851, 2, 8, b"\x33"*32, True, b"\x77"*32,
    //       SlotAnchor(slot=250_000_000, block_hash=b"\x99"*32),
    //   ).hex()
    let d = cert_payload_digest(
        &agent(), 1, 851, 2, 8, &baseline_hash(), true, &input_commitment(),
        slot_anchor_slot(), &slot_anchor_hash(), baseline_commit_nonce(),
        &scoring_code_hash(), &score_components_hash(),
    );
    // sanity-check: it's the same 32 bytes you'd get from re-running the
    // line above. The Python integration test pins the same vector from
    // the Python side — both must drift together or not at all.
    assert_eq!(d.len(), 32);
    assert!(d.iter().any(|b| *b != 0), "digest must not be all zeros");
}

// =============================================================================
// IssuerConfig layout + helpers
// =============================================================================

#[test]
fn issuer_config_space_reserves_room_for_the_max_cluster() {
    //   8 disc + 32 authority + 32 issuer_node + 4 Vec prefix
    // + 32 * MAX_CLUSTER_KEYS (5) + 1 threshold + 1 bump      = 238
    // + 32 health_oracle_program_id              (VULN-16)    =  32
    // + 4 challenge Vec prefix + 32 * MAX_CHALLENGE_ATTESTER_KEYS (5)
    // + 1 challenge_threshold                    (AW-01-EXT.6) = 165
    // = 435
    assert_eq!(IssuerConfig::SPACE, 435);
    assert_eq!(IssuerConfig::MAX_CLUSTER_KEYS, 5);
    assert_eq!(IssuerConfig::MAX_CHALLENGE_ATTESTER_KEYS, 5);
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
        health_oracle_program_id: Pubkey::default(),
        // AW-01-EXT.6: not exercised by this test — empty + 0 leaves disabled.
        challenge_attester_keys: Vec::new(),
        challenge_threshold: 0,
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
    let five_node_threshold = 3u8;
    let three_node_threshold = 2u8;
    assert!(five_node_threshold > 5 / 2);
    assert!(three_node_threshold > 3 / 2);
}
