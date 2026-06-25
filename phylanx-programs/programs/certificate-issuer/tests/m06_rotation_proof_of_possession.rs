// =============================================================================
// programs/certificate-issuer/tests/m06_rotation_proof_of_possession.rs
//
// M-06 — Cluster-key rotation with on-chain proof-of-possession.
//
// Pure unit-test pins on the canonical rotation digest + the public
// `rotation` module surface. Full on-chain enforcement (the Anchor handler
// reading the Instructions sysvar and rejecting a rotation tx that misses
// a per-key PoP signature) is exercised by the TypeScript integration test.
//
// These pins enforce the cryptographic core: a rotation digest produced
// under any DIFFERENT (program_id, old_version, new_version, threshold,
// keys) cannot collide with the digest a verifier recomputes — so a
// signature captured for one rotation is provably useless for another.
// That property is the M-06 fix.
//
// Error-code pins guard the on-chain message contract: a future refactor
// renaming or renumbering the M-06 errors fails this file, which forces
// the TypeScript SDK + integration tests to be updated in lockstep.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use certificate_issuer::errors::CertificateError;
use certificate_issuer::rotation::{rotation_digest, ROTATION_DOMAIN_TAG};

// -----------------------------------------------------------------------------
// Test fixtures
// -----------------------------------------------------------------------------

fn program_id() -> Pubkey {
    Pubkey::new_from_array([0xAA; 32])
}

fn five_keys() -> Vec<Pubkey> {
    (0u8..5).map(|i| Pubkey::new_from_array([i + 1; 32])).collect()
}

// -----------------------------------------------------------------------------
// Digest stability + binding pins
// -----------------------------------------------------------------------------

#[test]
fn rotation_digest_is_deterministic() {
    let a = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    let b = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    assert_eq!(a, b, "rotation_digest must be a pure function of its inputs");
}

#[test]
fn rotation_digest_is_32_bytes_and_nonzero() {
    let d = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    assert_eq!(d.len(), 32);
    assert!(d.iter().any(|b| *b != 0), "digest must not be all zeros");
}

#[test]
fn rotation_digest_binds_program_id() {
    // A signature captured under one program's rotation MUST NOT verify
    // under another program's rotation, even if every other input is
    // identical. This pins the cross-program replay defence.
    let a = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    let b = rotation_digest(
        &Pubkey::new_from_array([0xBB; 32]),
        1, 2, 3, &five_keys(),
    );
    assert_ne!(a, b);
}

#[test]
fn rotation_digest_binds_old_config_version() {
    // The (old_version -> new_version) transition is part of the signed
    // bytes, so a sig captured for rotation N->N+1 cannot be replayed as
    // a sig for rotation M->N+1 (M != N).
    let a = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    let b = rotation_digest(&program_id(), 7, 2, 3, &five_keys());
    assert_ne!(a, b);
}

#[test]
fn rotation_digest_binds_new_config_version() {
    let a = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    let b = rotation_digest(&program_id(), 1, 3, 3, &five_keys());
    assert_ne!(a, b);
}

#[test]
fn rotation_digest_binds_new_threshold() {
    // A new cluster size of 5 with threshold 3 vs 4 has the same key set
    // but a materially different security boundary — the digest must
    // distinguish them.
    let a = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    let b = rotation_digest(&program_id(), 1, 2, 4, &five_keys());
    assert_ne!(a, b);
}

#[test]
fn rotation_digest_binds_each_new_key() {
    // Mutating any single key in the new cluster set must change the
    // digest — this is what proves the signed bytes commit to the full
    // post-rotation key set, not just to a count or a hash with a
    // truncation bug.
    let base = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    for i in 0..five_keys().len() {
        let mut mutated = five_keys();
        mutated[i] = Pubkey::new_from_array([0xFF; 32]);
        let d = rotation_digest(&program_id(), 1, 2, 3, &mutated);
        assert_ne!(
            base, d,
            "mutating key index {i} of the new cluster set must change the digest",
        );
    }
}

#[test]
fn rotation_digest_binds_key_order() {
    // Swapping any two new-key positions must change the digest. The
    // protocol records and iterates `cluster_keys` in insertion order,
    // so a verifier MUST see exactly the same order the signer pinned.
    let a = rotation_digest(&program_id(), 1, 2, 3, &five_keys());
    let mut swapped = five_keys();
    swapped.swap(0, 4);
    let b = rotation_digest(&program_id(), 1, 2, 3, &swapped);
    assert_ne!(a, b);
}

#[test]
fn rotation_digest_distinguishes_cluster_sizes() {
    // A 1-key and a 3-key rotation under otherwise-matching inputs must
    // produce different bytes — the length prefix the digest reserves
    // for the keys list is the canonical anti-truncation primitive.
    let one_key = vec![Pubkey::new_from_array([0x01; 32])];
    let three_keys: Vec<Pubkey> =
        (0u8..3).map(|i| Pubkey::new_from_array([i + 1; 32])).collect();
    let a = rotation_digest(&program_id(), 1, 2, 1, &one_key);
    let b = rotation_digest(&program_id(), 1, 2, 1, &three_keys);
    assert_ne!(a, b);
}

#[test]
fn rotation_domain_tag_is_pinned_and_distinct() {
    // The 28-byte domain tag is the first input to the digest, so it
    // permanently separates rotation signatures from cert-payload
    // signatures and challenge signatures.
    assert_eq!(ROTATION_DOMAIN_TAG, b"phylanx-m06-cluster-rotation");
    assert_eq!(ROTATION_DOMAIN_TAG.len(), 28);
}

// -----------------------------------------------------------------------------
// Error-code pins — protect the on-chain contract from silent re-numbering
// -----------------------------------------------------------------------------

#[test]
fn rotation_error_codes_are_stable() {
    // Anchor maps these to fixed numeric codes. The TypeScript SDK +
    // integration tests dispatch on the codes, so a silent renumber
    // would break callers without breaking the build.
    assert_eq!(CertificateError::MissingRotationProofOfPossession as u32, 6120);
    assert_eq!(CertificateError::RotationConfigVersionOverflow as u32, 6121);
    assert_eq!(CertificateError::RotationNoOpRejected as u32, 6122);
}
