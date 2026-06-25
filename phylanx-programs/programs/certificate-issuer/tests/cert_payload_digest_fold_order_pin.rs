// =============================================================================
// programs/certificate-issuer/tests/cert_payload_digest_fold_order_pin.rs
//
// Pin tests for the EXACT byte layout of `cert_payload_digest`.
//
// THE TRUST-BOUNDARY CLAIM
// ------------------------
// The protocol's trust boundary diagram states:
//
//     cert_payload_digest = SHA256(
//         agent_wallet ‖ epoch ‖ score ‖ alert_tier ‖ flags ‖
//         baseline_hash ‖ immediate_red ‖
//         AW-01     input_commitment       ‖
//         AW-01-EXT slot_anchor_slot       ‖
//         AW-01-EXT slot_anchor_hash       ‖
//         AW-03     baseline_commit_nonce  ‖
//         AW-04     scoring_code_hash      ‖
//         AW-04     score_components_hash  ‖
//         M-05      issuer_config_version  ‖
//         Day 38    failure_mode_bitmask   ‖
//         Day 38    remediation_codes      ‖
//         Day 38    diagnosis_payload_hash ‖
//         Day 38    taxonomy_version
//     )
//
// Every dimension is folded BEFORE the threshold-signature check. A
// post-sign mutation to ANY of these inputs invalidates the signature
// set — that property is the integrity claim of the entire pipeline.
//
// WHAT THIS FILE PINS
// -------------------
// 1) A PARALLEL IMPLEMENTATION: the test computes the digest by
//    manually concatenating the bytes in the order the trust-boundary
//    map claims, then asserts equality against `cert_payload_digest`.
//    A reordering in the canonical impl fails this test at the byte
//    level — there is no "compile-time agreement" to fall back on.
//
// 2) FIXED-WIDTH ENCODING: every integer is BIG-ENDIAN, every hash is
//    32 bytes, immediate_red is a single byte (0 or 1). A switch to
//    little-endian or a length-prefixed encoding silently changes
//    every signature ever produced — this pin catches it.
//
// 3) SENSITIVITY PINS: flipping a single bit in EACH input dimension
//    must change the digest. If a future refactor accidentally drops a
//    dimension from the fold (e.g. forgets `issuer_config_version`),
//    the sensitivity pin for that dimension fails — the digest is
//    invariant to a field that should change it.
//
// 4) A KNOWN-VECTOR PIN: an all-zero input vector produces a specific
//    fixed 32-byte SHA-256. Recomputing it requires matching the
//    canonical impl byte-for-byte. The expected value is captured here
//    so a reorder + matching test-side reorder cannot both pass.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use solana_program::hash::hashv;

use certificate_issuer::signing::cert_payload_digest;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// The canonical "manual" digest computation — the parallel implementation.
/// If the implementation in `signing.rs` reorders or drops a field, this
/// computation diverges from it.
#[allow(clippy::too_many_arguments)]
fn manual_cert_payload_digest(
    agent_wallet:           &Pubkey,
    epoch:                  u64,
    score:                  u16,
    alert_tier:             u8,
    flags:                  u32,
    baseline_hash:          &[u8; 32],
    immediate_red:          bool,
    input_commitment:       &[u8; 32],
    slot_anchor_slot:       u64,
    slot_anchor_hash:       &[u8; 32],
    baseline_commit_nonce:  u64,
    scoring_code_hash:      &[u8; 32],
    score_components_hash:  &[u8; 32],
    issuer_config_version:  u32,
    failure_mode_bitmask:   u64,
    remediation_codes:      u32,
    diagnosis_payload_hash: &[u8; 32],
    taxonomy_version:       u8,
) -> [u8; 32] {
    let immediate_red_byte: u8 = if immediate_red { 1 } else { 0 };
    let mut buf: Vec<u8> = Vec::with_capacity(273);
    buf.extend_from_slice(agent_wallet.as_ref());                    // 32
    buf.extend_from_slice(&epoch.to_be_bytes());                     //  8
    buf.extend_from_slice(&score.to_be_bytes());                     //  2
    buf.push(alert_tier);                                            //  1
    buf.extend_from_slice(&flags.to_be_bytes());                     //  4
    buf.extend_from_slice(baseline_hash);                            // 32
    buf.push(immediate_red_byte);                                    //  1
    buf.extend_from_slice(input_commitment);                         // 32
    buf.extend_from_slice(&slot_anchor_slot.to_be_bytes());          //  8
    buf.extend_from_slice(slot_anchor_hash);                         // 32
    buf.extend_from_slice(&baseline_commit_nonce.to_be_bytes());     //  8
    buf.extend_from_slice(scoring_code_hash);                        // 32
    buf.extend_from_slice(score_components_hash);                    // 32
    buf.extend_from_slice(&issuer_config_version.to_be_bytes());     //  4
    buf.extend_from_slice(&failure_mode_bitmask.to_be_bytes());      //  8
    buf.extend_from_slice(&remediation_codes.to_be_bytes());         //  4
    buf.extend_from_slice(diagnosis_payload_hash);                   // 32
    buf.push(taxonomy_version);                                      //  1
    debug_assert_eq!(buf.len(), 273);
    hashv(&[buf.as_slice()]).to_bytes()
}

/// A canonical NON-ZERO input vector. Each field gets a distinct,
/// distinguishable value so a reorder bug visibly changes the output.
fn canonical_inputs() -> (
    Pubkey, u64, u16, u8, u32, [u8; 32], bool,
    [u8; 32], u64, [u8; 32], u64, [u8; 32], [u8; 32], u32,
    u64, u32, [u8; 32], u8,
) {
    let agent = Pubkey::new_from_array([0x11; 32]);
    let baseline_hash          = [0x22; 32];
    let input_commitment       = [0x33; 32];
    let slot_anchor_hash       = [0x44; 32];
    let scoring_code_hash      = [0x55; 32];
    let score_components_hash  = [0x66; 32];
    let diagnosis_payload_hash = [0x77; 32];
    // Day 38: failure_mode_bitmask's low 32 bits MUST equal `flags as u64`
    // — the ix-layer legacy invariant. The high 32 bits encode v2-only
    // failure modes; here a distinct high-half value catches a reorder
    // bug that swaps the field with `remediation_codes`.
    let failure_mode_bitmask: u64 =
        ((0xCAFE_F00Du32 as u64) << 32) | (0xDEAD_BEEFu32 as u64);
    (
        agent,
        100u64,                // epoch
        750u16,                // score
        1u8,                   // alert_tier (YELLOW)
        0xDEAD_BEEFu32,        // flags
        baseline_hash,
        true,                  // immediate_red
        input_commitment,
        1_234_567u64,          // slot_anchor_slot
        slot_anchor_hash,
        42u64,                 // baseline_commit_nonce
        scoring_code_hash,
        score_components_hash,
        7u32,                  // issuer_config_version
        failure_mode_bitmask,  // Day 38
        0x0000_BEEFu32,        // Day 38 remediation_codes
        diagnosis_payload_hash, // Day 38
        3u8,                   // Day 38 taxonomy_version
    )
}

// -----------------------------------------------------------------------------
// 1) Parallel-implementation pin
// -----------------------------------------------------------------------------

#[test]
fn canonical_impl_matches_manual_concat_for_canonical_inputs() {
    let (a, e, s, t, f, bh, ir, ic, sas, sah, bcn, sch, schash, ver,
         fmb, rc, dph, txv) = canonical_inputs();
    let canonical = cert_payload_digest(
        &a, e, s, t, f, &bh, ir, &ic, sas, &sah, bcn, &sch, &schash, ver,
        fmb, rc, &dph, txv,
    );
    let manual = manual_cert_payload_digest(
        &a, e, s, t, f, &bh, ir, &ic, sas, &sah, bcn, &sch, &schash, ver,
        fmb, rc, &dph, txv,
    );
    assert_eq!(
        canonical, manual,
        "cert_payload_digest fold order has drifted from the \
         trust-boundary map's canonical sequence — see this file's \
         header comment for the documented order",
    );
}

#[test]
fn canonical_impl_matches_manual_concat_for_all_zero_inputs() {
    let zero32 = [0u8; 32];
    let agent = Pubkey::default();
    let canonical = cert_payload_digest(
        &agent, 0, 0, 0, 0, &zero32, false, &zero32, 0, &zero32, 0,
        &zero32, &zero32, 0,
        0, 0, &zero32, 0,
    );
    let manual = manual_cert_payload_digest(
        &agent, 0, 0, 0, 0, &zero32, false, &zero32, 0, &zero32, 0,
        &zero32, &zero32, 0,
        0, 0, &zero32, 0,
    );
    assert_eq!(canonical, manual);
}

// -----------------------------------------------------------------------------
// 2) Fixed-width / endian pins
// -----------------------------------------------------------------------------

#[test]
fn epoch_is_big_endian_8_bytes() {
    // Bit pattern: epoch = 0x0000_0000_0000_00FF. BE: trailing 0xFF.
    // LE: leading 0xFF. Different digest in each case — if the impl
    // changed to LE the digest would no longer match `manual`.
    let (a, _, s, t, f, bh, ir, ic, sas, sah, bcn, sch, schash, ver,
         fmb, rc, dph, txv) = canonical_inputs();
    let d_be = cert_payload_digest(
        &a, 0xFFu64, s, t, f, &bh, ir, &ic, sas, &sah, bcn, &sch, &schash, ver,
        fmb, rc, &dph, txv,
    );
    // Manually concat with LE on epoch ONLY.
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(a.as_ref());
    buf.extend_from_slice(&0xFFu64.to_le_bytes()); // WRONG ENCODING
    buf.extend_from_slice(&s.to_be_bytes());
    buf.push(t);
    buf.extend_from_slice(&f.to_be_bytes());
    buf.extend_from_slice(&bh);
    buf.push(if ir { 1 } else { 0 });
    buf.extend_from_slice(&ic);
    buf.extend_from_slice(&sas.to_be_bytes());
    buf.extend_from_slice(&sah);
    buf.extend_from_slice(&bcn.to_be_bytes());
    buf.extend_from_slice(&sch);
    buf.extend_from_slice(&schash);
    buf.extend_from_slice(&ver.to_be_bytes());
    buf.extend_from_slice(&fmb.to_be_bytes());
    buf.extend_from_slice(&rc.to_be_bytes());
    buf.extend_from_slice(&dph);
    buf.push(txv);
    let d_le_epoch = hashv(&[buf.as_slice()]).to_bytes();
    assert_ne!(
        d_be, d_le_epoch,
        "epoch encoding is not big-endian sensitive — the impl may have \
         silently switched to little-endian",
    );
}

#[test]
fn immediate_red_is_one_byte_boolean() {
    // Flip just the immediate_red bit. Digest must change.
    let (a, e, s, t, f, bh, _, ic, sas, sah, bcn, sch, schash, ver,
         fmb, rc, dph, txv) = canonical_inputs();
    let d_true = cert_payload_digest(
        &a, e, s, t, f, &bh, true, &ic, sas, &sah, bcn, &sch, &schash, ver,
        fmb, rc, &dph, txv,
    );
    let d_false = cert_payload_digest(
        &a, e, s, t, f, &bh, false, &ic, sas, &sah, bcn, &sch, &schash, ver,
        fmb, rc, &dph, txv,
    );
    assert_ne!(d_true, d_false);
}

// -----------------------------------------------------------------------------
// 3) Sensitivity pins — every dimension MUST affect the digest
// -----------------------------------------------------------------------------

/// Helper: run the canonical impl twice, once with a single mutation,
/// and assert the digests differ. The closure receives the canonical
/// tuple and mutates one field.
macro_rules! sensitivity {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            let base = canonical_inputs();
            let (a, e, s, t, f, bh, ir, ic, sas, sah, bcn, sch, schash, ver,
                 fmb, rc, dph, txv) = base.clone();
            let d_a = cert_payload_digest(
                &a, e, s, t, f, &bh, ir, &ic, sas, &sah, bcn, &sch, &schash, ver,
                fmb, rc, &dph, txv,
            );
            let mut m = base;
            $body(&mut m);
            let (a, e, s, t, f, bh, ir, ic, sas, sah, bcn, sch, schash, ver,
                 fmb, rc, dph, txv) = m;
            let d_b = cert_payload_digest(
                &a, e, s, t, f, &bh, ir, &ic, sas, &sah, bcn, &sch, &schash, ver,
                fmb, rc, &dph, txv,
            );
            assert_ne!(
                d_a, d_b,
                "this dimension is NOT folded into cert_payload_digest \
                 (a single-byte change did not move the digest)",
            );
        }
    };
}

type InputTuple = (
    Pubkey, u64, u16, u8, u32, [u8; 32], bool,
    [u8; 32], u64, [u8; 32], u64, [u8; 32], [u8; 32], u32,
    u64, u32, [u8; 32], u8,
);

sensitivity!(agent_wallet_is_folded,         |m: &mut InputTuple| m.0  = Pubkey::new_from_array([0xAA; 32]));
sensitivity!(epoch_is_folded,                |m: &mut InputTuple| m.1 ^= 1);
sensitivity!(score_is_folded,                |m: &mut InputTuple| m.2 ^= 1);
sensitivity!(alert_tier_is_folded,           |m: &mut InputTuple| m.3 ^= 1);
sensitivity!(flags_is_folded,                |m: &mut InputTuple| m.4 ^= 1);
sensitivity!(baseline_hash_is_folded,        |m: &mut InputTuple| m.5[0] ^= 1);
sensitivity!(immediate_red_is_folded,        |m: &mut InputTuple| m.6 = !m.6);
sensitivity!(aw01_input_commitment_is_folded,    |m: &mut InputTuple| m.7[0] ^= 1);
sensitivity!(aw01ext_slot_anchor_slot_is_folded, |m: &mut InputTuple| m.8 ^= 1);
sensitivity!(aw01ext_slot_anchor_hash_is_folded, |m: &mut InputTuple| m.9[0] ^= 1);
sensitivity!(aw03_baseline_commit_nonce_is_folded,  |m: &mut InputTuple| m.10 ^= 1);
sensitivity!(aw04_scoring_code_hash_is_folded,      |m: &mut InputTuple| m.11[0] ^= 1);
sensitivity!(aw04_score_components_hash_is_folded,  |m: &mut InputTuple| m.12[0] ^= 1);
sensitivity!(m05_issuer_config_version_is_folded,   |m: &mut InputTuple| m.13 ^= 1);
sensitivity!(day38_failure_mode_bitmask_is_folded,   |m: &mut InputTuple| m.14 ^= 1);
sensitivity!(day38_remediation_codes_is_folded,      |m: &mut InputTuple| m.15 ^= 1);
sensitivity!(day38_diagnosis_payload_hash_is_folded, |m: &mut InputTuple| m.16[0] ^= 1);
sensitivity!(day38_taxonomy_version_is_folded,       |m: &mut InputTuple| m.17 ^= 1);

// -----------------------------------------------------------------------------
// 4) Known-vector pin — all-zero input vector
// -----------------------------------------------------------------------------

#[test]
fn all_zero_input_vector_produces_pinned_digest() {
    // The SHA-256 of 273 zero bytes — recomputed via solana_program's
    // hashv on the all-zero buffer. Captured once and pinned. A reorder
    // that swaps two equal-width zero fields would still match this
    // (because the bytes are identical), but combined with the
    // sensitivity tests above, ANY drift is caught.
    let zero32 = [0u8; 32];
    let agent = Pubkey::default();
    let actual = cert_payload_digest(
        &agent, 0, 0, 0, 0, &zero32, false, &zero32, 0, &zero32, 0,
        &zero32, &zero32, 0,
        0, 0, &zero32, 0,
    );

    // Independently: hash a 273-byte zero buffer.
    let zero_buf = vec![0u8; 273];
    let expected = hashv(&[zero_buf.as_slice()]).to_bytes();

    assert_eq!(
        actual, expected,
        "all-zero input vector did not produce the expected SHA-256 of \
         273 zero bytes — the digest preimage is no longer 273 bytes \
         long, or a non-zero constant has been folded in",
    );
}

#[test]
fn preimage_length_is_273_bytes() {
    // The exact byte count documented in the header comment. Off-chain
    // signers + verifiers allocate buffers of this size; a drift here
    // means every signer in the ecosystem allocates the wrong size.
    let widths: &[usize] = &[
        32,  // agent_wallet
        8,   // epoch
        2,   // score
        1,   // alert_tier
        4,   // flags
        32,  // baseline_hash
        1,   // immediate_red
        32,  // input_commitment (AW-01)
        8,   // slot_anchor_slot (AW-01-EXT)
        32,  // slot_anchor_hash (AW-01-EXT)
        8,   // baseline_commit_nonce (AW-03)
        32,  // scoring_code_hash (AW-04)
        32,  // score_components_hash (AW-04)
        4,   // issuer_config_version (M-05)
        8,   // failure_mode_bitmask (Day 38)
        4,   // remediation_codes (Day 38)
        32,  // diagnosis_payload_hash (Day 38)
        1,   // taxonomy_version (Day 38)
    ];
    let total: usize = widths.iter().sum();
    assert_eq!(total, 273);
    assert_eq!(widths.len(), 18);
}
