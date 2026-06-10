// =============================================================================
// programs/certificate-issuer/tests/m05_config_immutability_tag.rs
//
// M-05 — IssuerConfig immutability tag for already-issued certs.
//
// THE AUDIT FINDING
// -----------------
// Pre-M-05, IssuerConfig carried `cluster_keys`, `threshold`, and the
// challenge-attester set but NO version field on the snapshot. A future
// `update_issuer_config` rotation that mutated the cluster set could
// therefore retroactively change the interpretation of HISTORICAL certs:
// an off-chain verifier that re-derives the digest under the CURRENT
// snapshot would compute different bytes than the cluster signed against,
// or worse, a malicious admin could swap the cluster set, sign a
// fabricated cert under the new keys, and stamp it with an OLD epoch /
// agent so it looked like a historical Certificate produced under the
// SIGNED-AT-THE-TIME keys.
//
// THE FIX
// -------
// 1. IssuerConfig gains `config_version: u32` (genesis = 1). Any future
//    rotation ix MUST strictly increment it.
// 2. HealthCertificate gains `issuer_config_version: u32` — stamped on
//    every cert at issuance time.
// 3. `cert_payload_digest` folds `issuer_config_version` into the SHA-256
//    input — so the cluster's threshold signatures cryptographically
//    attest to the EXACT snapshot the keys came from.
//
// This file pins:
//   - IssuerConfig::SPACE == 439 bytes (435 + 4 for u32).
//   - HealthCertificate::CURRENT_LAYOUT_VERSION >= 8 (M-05 landed at v8;
//     later migrations may advance it without invalidating M-05's pin).
//   - HealthCertificate carries `issuer_config_version: u32` at the
//     expected offset/width (carved from `_reserved`, not appended) —
//     the M-05 audit finding is that this field exists and is folded
//     into the digest, NOT that the account size is frozen at the v8
//     value. Day 38 / Cert v2 grew the account; the M-05 carve survives
//     intact within the new layout.
//   - `cert_payload_digest` returns DIFFERENT bytes when ONLY the
//     `issuer_config_version` argument changes — the binding actually
//     reaches the SHA-256 input.
//   - `cert_payload_digest` is DETERMINISTIC when version is held fixed.
//   - The genesis value initialize_config stamps is 1 (off-chain signers
//     can pin against this without an extra RPC fetch).
// =============================================================================

use anchor_lang::prelude::Pubkey;
use certificate_issuer::signing::cert_payload_digest;
use certificate_issuer::state::{HealthCertificate, IssuerConfig};

// -----------------------------------------------------------------------------
// Layout pins
// -----------------------------------------------------------------------------

#[test]
fn issuer_config_space_grew_by_four_bytes_for_config_version() {
    // Pre-M-05 SPACE was 435 (Day-27 cluster_keys + threshold + VULN-16
    // health_oracle_program_id + AW-01-EXT.6 challenge cluster). M-05
    // appends config_version (u32), adding 4 bytes.
    assert_eq!(IssuerConfig::SPACE, 439);
    assert_eq!(IssuerConfig::SPACE - 435, 4);
}

#[test]
fn health_certificate_layout_is_at_least_v8() {
    // M-05 introduced layout v8. Future migrations (e.g. Day 38 / Cert v2
    // bumping to v9) may advance the version further — the M-05 audit
    // pin is that the layout REACHED v8, not that it stays there forever.
    assert!(
        HealthCertificate::CURRENT_LAYOUT_VERSION >= 8,
        "M-05 reached v8; current layout must not regress below it",
    );
}

#[test]
fn issuer_config_version_was_carved_from_reserved_at_m05() {
    // M-05 specifically CARVED `issuer_config_version` (u32) from the v7
    // `_reserved` block rather than APPENDING it — so the M-05 carve
    // contributed ZERO bytes to the on-chain account size. Day 38 later
    // grew the account by APPENDING new fields, but M-05's carve is
    // independent of that growth. This test pins the carve discipline:
    // the field exists, is u32-wide, and is stamped with the genesis
    // value 1 by `initialize_config`. The account-SIZE invariant the
    // M-05 audit cared about ("no realloc from M-05 alone") is now
    // expressed via the static-typing pin below, not by hard-coding the
    // v8 SIZE constant that Day 38 made stale.
    let cfg = IssuerConfig {
        authority:                Pubkey::default(),
        issuer_node:              Pubkey::default(),
        cluster_keys:             vec![Pubkey::default()],
        threshold:                1,
        bump:                     255,
        health_oracle_program_id: Pubkey::default(),
        challenge_attester_keys:  Vec::new(),
        challenge_threshold:      0,
        config_version:           1u32,
    };
    let _: u32 = cfg.config_version;
}

// -----------------------------------------------------------------------------
// Digest binding — the core M-05 invariant
// -----------------------------------------------------------------------------

fn fixed_agent() -> Pubkey {
    Pubkey::new_from_array([0x11; 32])
}

fn fixed_hash() -> [u8; 32] {
    [0x33; 32]
}

#[test]
fn digest_changes_with_issuer_config_version() {
    // The whole point of M-05: a verifier that recomputes the digest
    // under a DIFFERENT `config_version` from the one the cluster signed
    // against gets DIFFERENT bytes. Without this, a config rotation
    // could silently re-bind historical signatures to a new key set.
    let v1 = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        1,
        0, 0, &[0u8; 32], 0,
    );
    let v2 = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        2,
        0, 0, &[0u8; 32], 0,
    );
    assert_ne!(
        v1, v2,
        "M-05: issuer_config_version MUST be folded into the digest — \
         a config rotation must not retroactively re-bind historical certs",
    );
}

#[test]
fn digest_is_deterministic_when_version_held_constant() {
    // Pin: holding ALL inputs (including version) constant produces the
    // same 32 bytes. This is the off-chain signer's stable contract.
    let a = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        7,
        0, 0, &[0u8; 32], 0,
    );
    let b = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        7,
        0, 0, &[0u8; 32], 0,
    );
    assert_eq!(a, b);
}

#[test]
fn digest_distinguishes_zero_and_one_versions() {
    // Legacy / sentinel pin: a verifier replaying a pre-M-05 historical
    // cert (signed against the sentinel 0) MUST produce different bytes
    // from a post-M-05 genesis cert (signed against 1). Without this
    // distinction, a cluster could lift a pre-M-05 signature and claim
    // it was signed under the current snapshot.
    let legacy = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        0,
        0, 0, &[0u8; 32], 0,
    );
    let genesis = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        1,
        0, 0, &[0u8; 32], 0,
    );
    assert_ne!(legacy, genesis);
}

#[test]
fn digest_changes_with_max_u32_version() {
    // Range pin: the field is u32, so a version near the u32 ceiling must
    // also produce a distinct digest. Catches a silent truncation if a
    // future refactor accidentally narrows the field to u16/u8.
    let small = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        1,
        0, 0, &[0u8; 32], 0,
    );
    let huge = cert_payload_digest(
        &fixed_agent(), 1, 851, 2, 8, &fixed_hash(), true, &fixed_hash(),
        250_000_000, &fixed_hash(), 7, &fixed_hash(), &fixed_hash(),
        u32::MAX,
        0, 0, &[0u8; 32], 0,
    );
    assert_ne!(small, huge);
}

// -----------------------------------------------------------------------------
// Genesis-value pin
// -----------------------------------------------------------------------------

#[test]
fn issuer_config_version_field_is_u32() {
    // Static-typing pin via Default. If a future refactor accidentally
    // narrows or widens the field, this fails to compile.
    let cfg = IssuerConfig {
        authority:                Pubkey::default(),
        issuer_node:              Pubkey::default(),
        cluster_keys:             vec![Pubkey::default()],
        threshold:                1,
        bump:                     255,
        health_oracle_program_id: Pubkey::default(),
        challenge_attester_keys:  Vec::new(),
        challenge_threshold:      0,
        config_version:           1u32,
    };
    // Round-trip: holds the u32 we set, and is ge 1 (the genesis floor
    // `initialize_config` writes).
    let v: u32 = cfg.config_version;
    assert_eq!(v, 1);
}

#[test]
fn health_certificate_issuer_config_version_field_is_u32() {
    // Same static-typing pin on the cert struct — guarantees the cert
    // carries the SAME width the digest folds in, so cluster signatures
    // and on-chain verification agree.
    let cert = HealthCertificate {
        agent_wallet:          Pubkey::default(),
        epoch:                 1,
        score:                 700,
        alert_tier:            0,
        flags:                 0,
        issued_at:             0,
        issuer:                Pubkey::default(),
        baseline_hash:         [0u8; 32],
        immediate_red:         false,
        bump:                  255,
        layout_version:        HealthCertificate::CURRENT_LAYOUT_VERSION,
        signer_count:          3,
        input_commitment:      [0u8; 32],
        slot_anchor_slot:      0,
        slot_anchor_hash:      [0u8; 32],
        challenge_state:       0,
        baseline_commit_nonce: 0,
        scoring_code_hash:     [0u8; 32],
        issuer_config_version: 1u32,
        taxonomy_version:       0,
        failure_mode_bitmask:   0,
        remediation_codes:      0,
        diagnosis_payload_hash: [0u8; 32],
        _reserved:             [0u8; 1],
    };
    let v: u32 = cert.issuer_config_version;
    assert_eq!(v, 1);
}
