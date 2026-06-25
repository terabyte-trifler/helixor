// =============================================================================
// programs/certificate-issuer/src/rotation.rs
//
// M-06 — Cluster-key rotation with PROOF-OF-POSSESSION (PoP).
//
// THE AUDIT FINDING
// -----------------
// A naive rotation handler — "admin authority signs the tx, new cluster_keys
// land in IssuerConfig" — admits a class of latent attacks:
//
//   1. TYPO / FAT-FINGER. An admin pastes a slightly-wrong pubkey; the
//      cluster set now contains a key NOBODY controls. The threshold
//      then degrades silently (a 3-of-5 with one un-owned key is
//      effectively 3-of-4 from the operators' POV; from the protocol's
//      POV the threshold check still demands 3 but only 4 of the
//      installed keys can sign — a hidden liveness reduction).
//
//   2. HOSTILE ADMIN. A compromised admin key inserts a public key
//      whose privkey is held by the attacker — instant cluster takeover
//      under the next rotation.
//
//   3. ROTATION-DIGEST REPLAY. Without binding (program_id, old_version,
//      new_version, final cluster set) into a signed digest, a signature
//      captured for one rotation could in principle be lifted into a
//      different rotation. Domain-separating the digest closes that.
//
// THE FIX
// -------
// Every rotation MUST carry an Ed25519 precompile signature from EVERY
// new cluster key over a canonical "rotation digest" that pins:
//
//   - a fixed DOMAIN TAG ("phylanx-m06-cluster-rotation"), so the digest
//     cannot collide with `cert_payload_digest` or `challenge_payload_digest`.
//   - the certificate-issuer PROGRAM ID, so a signature for one program
//     cannot be replayed into a different program with the same layout.
//   - the OLD `config_version` (the snapshot being retired) and the NEW
//     `config_version` (= old + 1), so a sig captured for one rotation
//     cannot be lifted into a different rotation transition.
//   - the NEW THRESHOLD and the NEW CLUSTER KEYS (in order), so a sig
//     captured for one cluster shape cannot be lifted onto another.
//
// We require sigs from EVERY new key (not just newly-added ones). This is
// strictly stronger than "PoP for new keys only": legacy keys re-prove
// possession (harmless) AND the cluster collectively re-attests to the
// rotation as a unit. It also means the on-chain check is uniform — no
// "diff old vs new" set arithmetic — which keeps the handler trivially
// auditable.
// =============================================================================

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_instruction_at_checked, ID as INSTRUCTIONS_ID};
use solana_program::{hash::hashv, instruction::Instruction};
use solana_sdk_ids::ed25519_program;

use crate::errors::CertificateError;

/// Domain-separation tag for the cluster-rotation digest. Distinct from
/// `cert_payload_digest` (no tag) and `challenge_payload_digest`
/// (`b"phylanx-aw01-ext-challenge"`) so an attacker cannot lift a cert
/// signature or a challenge signature and reuse it as a rotation
/// signature, or vice versa.
pub const ROTATION_DOMAIN_TAG: &[u8] = b"phylanx-m06-cluster-rotation";

/// Compute the 32-byte canonical rotation digest. The off-chain rotation
/// tooling computes the identical bytes; mismatch = unsignable rotation.
///
/// The byte layout is FIXED and PUBLIC. Field order is deliberately the
/// same as the on-chain check below so a reader sees one canonical
/// recipe.
pub fn rotation_digest(
    program_id:         &Pubkey,
    old_config_version: u32,
    new_config_version: u32,
    new_threshold:      u8,
    new_cluster_keys:   &[Pubkey],
) -> [u8; 32] {
    // The Vec is serialised as `len_u32_be || key_0 || key_1 || ...` so
    // the digest CANNOT collide between a 2-key set and a 1-key set
    // whose single element happens to share a prefix. The length prefix
    // is the canonical anti-ambiguity primitive.
    let len_be = (new_cluster_keys.len() as u32).to_be_bytes();
    let keys_bytes: Vec<u8> = new_cluster_keys
        .iter()
        .flat_map(|k| k.to_bytes())
        .collect();
    let h = hashv(&[
        ROTATION_DOMAIN_TAG,                    // 28 bytes
        program_id.as_ref(),                    // 32 bytes
        &old_config_version.to_be_bytes(),      //  4 bytes
        &new_config_version.to_be_bytes(),      //  4 bytes
        &[new_threshold],                       //  1 byte
        &len_be,                                //  4 bytes
        &keys_bytes,                            // 32 * N bytes
    ]);
    h.to_bytes()
}

// -----------------------------------------------------------------------------
// Ed25519 precompile instruction layout (mirrors signing.rs)
// -----------------------------------------------------------------------------
//
// We re-use the same single-signature layout the cert-signing path assumes.
// The off-chain rotation builder emits one Ed25519 precompile ix per new
// cluster key, each carrying that key's signature over `rotation_digest`.

const ED25519_NUM_SIGNATURES_OFFSET: usize = 0;
const ED25519_HEADER_LEN: usize            = 16;
const ED25519_PUBKEY_LEN: usize            = 32;
const ED25519_SIGNATURE_LEN: usize         = 64;
const ED25519_MESSAGE_LEN: usize           = 32;

#[derive(Debug, Clone, Copy)]
struct PrecompileRecord {
    pubkey:  [u8; 32],
    message: [u8; 32],
}

fn parse_ed25519_ix(ix: &Instruction) -> Result<PrecompileRecord> {
    require!(
        ix.data.len() >= ED25519_HEADER_LEN.saturating_add(ED25519_PUBKEY_LEN)
                       .saturating_add(ED25519_SIGNATURE_LEN).saturating_add(ED25519_MESSAGE_LEN),
        CertificateError::MalformedEd25519Instruction,
    );
    require!(
        ix.data[ED25519_NUM_SIGNATURES_OFFSET] == 1,
        CertificateError::MalformedEd25519Instruction,
    );

    let sig_offset    = u16::from_le_bytes([ix.data[2],  ix.data[3]])  as usize;
    let sig_ix_idx    = u16::from_le_bytes([ix.data[4],  ix.data[5]]);
    let pk_offset     = u16::from_le_bytes([ix.data[6],  ix.data[7]])  as usize;
    let pk_ix_idx     = u16::from_le_bytes([ix.data[8],  ix.data[9]]);
    let msg_offset    = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
    let msg_size      = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;
    let msg_ix_idx    = u16::from_le_bytes([ix.data[14], ix.data[15]]);

    const THIS_IX: u16 = u16::MAX;
    require!(
        sig_ix_idx == THIS_IX && pk_ix_idx == THIS_IX && msg_ix_idx == THIS_IX,
        CertificateError::CrossInstructionReference,
    );
    require!(
        msg_size == ED25519_MESSAGE_LEN,
        CertificateError::WrongDigestLength,
    );
    require!(
        pk_offset.saturating_add(ED25519_PUBKEY_LEN) <= ix.data.len()
            && sig_offset.saturating_add(ED25519_SIGNATURE_LEN) <= ix.data.len()
            && msg_offset.saturating_add(msg_size) <= ix.data.len(),
        CertificateError::MalformedEd25519Instruction,
    );

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&ix.data[pk_offset .. pk_offset + ED25519_PUBKEY_LEN]);
    let mut message = [0u8; 32];
    message.copy_from_slice(&ix.data[msg_offset .. msg_offset + msg_size]);

    Ok(PrecompileRecord { pubkey, message })
}

/// Decide whether `ix` is a valid PoP signature for `expected_digest` from
/// a key in `required_keys`, and if so push that key onto `signers`
/// (distinct only).
///
/// Foreign keys, wrong-message records, malformed precompile ixs, and
/// repeats are all silently dropped (no contribution to the tally). The
/// FINAL threshold check at the end of `verify_rotation_pop` catches any
/// deficit — keeping per-ix parsing fault-tolerant.
fn maybe_tally_rotation_ix(
    ix:              &Instruction,
    expected_digest: &[u8; 32],
    required_keys:   &[Pubkey],
    signers:         &mut Vec<Pubkey>,
) -> Result<()> {
    if ix.program_id != ed25519_program::id() {
        return Ok(());
    }
    let record = match parse_ed25519_ix(ix) {
        Ok(r)  => r,
        Err(_) => return Ok(()),
    };
    if record.message != *expected_digest {
        return Ok(());
    }
    let signer = Pubkey::new_from_array(record.pubkey);
    if !required_keys.contains(&signer) {
        return Ok(());
    }
    if signers.contains(&signer) {
        return Ok(());
    }
    signers.push(signer);
    Ok(())
}

/// Verify that the current transaction carries one valid Ed25519
/// precompile signature over `expected_digest` from EVERY key in
/// `required_keys`. Anything short of full coverage is rejected with
/// `MissingRotationProofOfPossession`.
///
/// `instructions_sysvar` must be the instructions sysvar AccountInfo.
pub fn verify_rotation_pop(
    expected_digest:     &[u8; 32],
    required_keys:       &[Pubkey],
    instructions_sysvar: &AccountInfo,
) -> Result<()> {
    require!(
        instructions_sysvar.key == &INSTRUCTIONS_ID,
        CertificateError::WrongInstructionsSysvar,
    );

    let mut signers: Vec<Pubkey> = Vec::with_capacity(required_keys.len());
    let mut ix_index: usize = 0;
    while let Ok(ix) = load_instruction_at_checked(ix_index, instructions_sysvar) {
        ix_index += 1;
        if ix.program_id != ed25519_program::id() {
            continue;
        }
        maybe_tally_rotation_ix(&ix, expected_digest, required_keys, &mut signers)?;
    }

    // Strict: every required key must appear EXACTLY once. The dedup in
    // `maybe_tally_rotation_ix` guarantees each key contributes at most
    // once; here we demand it contributes at least once.
    require!(
        signers.len() == required_keys.len(),
        CertificateError::MissingRotationProofOfPossession,
    );

    msg!(
        "rotation PoP verified: {} of {} new cluster keys signed the rotation digest",
        signers.len(), required_keys.len(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── digest layout pins ──────────────────────────────────────────────────

    fn pid_a() -> Pubkey { Pubkey::new_from_array([0xAA; 32]) }
    fn pid_b() -> Pubkey { Pubkey::new_from_array([0xBB; 32]) }

    fn three_keys() -> Vec<Pubkey> {
        vec![
            Pubkey::new_from_array([0x01; 32]),
            Pubkey::new_from_array([0x02; 32]),
            Pubkey::new_from_array([0x03; 32]),
        ]
    }

    #[test]
    fn digest_is_32_bytes_and_deterministic() {
        let a = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        let b = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        assert_eq!(a.len(), 32);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_changes_with_program_id() {
        let a = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        let b = rotation_digest(&pid_b(), 1, 2, 2, &three_keys());
        assert_ne!(a, b, "program_id binding must survive into the digest");
    }

    #[test]
    fn digest_changes_with_old_version() {
        let a = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        let b = rotation_digest(&pid_a(), 5, 2, 2, &three_keys());
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_with_new_version() {
        let a = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        let b = rotation_digest(&pid_a(), 1, 3, 2, &three_keys());
        assert_ne!(a, b, "new_config_version binding must survive into the digest");
    }

    #[test]
    fn digest_changes_with_threshold() {
        let a = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        let b = rotation_digest(&pid_a(), 1, 2, 3, &three_keys());
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_with_keys() {
        let mut other = three_keys();
        other[1] = Pubkey::new_from_array([0x99; 32]);
        let a = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        let b = rotation_digest(&pid_a(), 1, 2, 2, &other);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_changes_with_key_order() {
        // Order matters: a re-ordered cluster is a different cluster
        // (different `is_cluster_key` iteration order in the verifier,
        // different on-chain storage order, different audit-log order).
        let a = rotation_digest(&pid_a(), 1, 2, 2, &three_keys());
        let mut reordered = three_keys();
        reordered.swap(0, 2);
        let b = rotation_digest(&pid_a(), 1, 2, 2, &reordered);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_uses_distinct_domain_tag() {
        // The first 28 bytes the digest sees are the domain tag — so a
        // signature captured for cert-issuance or challenge-filing cannot
        // be lifted into a rotation. Sanity-pin the tag bytes.
        assert_eq!(ROTATION_DOMAIN_TAG, b"phylanx-m06-cluster-rotation");
        assert_ne!(ROTATION_DOMAIN_TAG, b"phylanx-aw01-ext-challenge");
    }

    // ── tally semantics ─────────────────────────────────────────────────────

    fn ed25519_ix(pubkey: Pubkey, message: [u8; 32]) -> Instruction {
        let mut data = Vec::with_capacity(
            ED25519_HEADER_LEN + ED25519_PUBKEY_LEN + ED25519_SIGNATURE_LEN + ED25519_MESSAGE_LEN,
        );
        let pk_offset:  u16 = ED25519_HEADER_LEN as u16;
        let sig_offset: u16 = pk_offset + ED25519_PUBKEY_LEN as u16;
        let msg_offset: u16 = sig_offset + ED25519_SIGNATURE_LEN as u16;
        let this_ix = u16::MAX.to_le_bytes();

        data.push(1);
        data.push(0);
        data.extend_from_slice(&sig_offset.to_le_bytes());
        data.extend_from_slice(&this_ix);
        data.extend_from_slice(&pk_offset.to_le_bytes());
        data.extend_from_slice(&this_ix);
        data.extend_from_slice(&msg_offset.to_le_bytes());
        data.extend_from_slice(&(ED25519_MESSAGE_LEN as u16).to_le_bytes());
        data.extend_from_slice(&this_ix);
        data.extend_from_slice(pubkey.as_ref());
        data.extend_from_slice(&[7u8; ED25519_SIGNATURE_LEN]);
        data.extend_from_slice(&message);

        Instruction {
            program_id: ed25519_program::id(),
            accounts: Vec::new(),
            data,
        }
    }

    #[test]
    fn pop_full_coverage_is_counted() {
        let keys = three_keys();
        let digest = [0xCD; 32];
        let mut signers = Vec::new();
        for k in &keys {
            let ix = ed25519_ix(*k, digest);
            maybe_tally_rotation_ix(&ix, &digest, &keys, &mut signers).unwrap();
        }
        assert_eq!(signers.len(), 3);
    }

    #[test]
    fn pop_missing_one_key_yields_partial_count() {
        let keys = three_keys();
        let digest = [0xCD; 32];
        let mut signers = Vec::new();
        // Only two of three keys sign.
        for k in keys.iter().take(2) {
            let ix = ed25519_ix(*k, digest);
            maybe_tally_rotation_ix(&ix, &digest, &keys, &mut signers).unwrap();
        }
        assert_eq!(signers.len(), 2);
    }

    #[test]
    fn pop_duplicate_signer_counted_once() {
        let keys = three_keys();
        let digest = [0xCD; 32];
        let mut signers = Vec::new();
        let ix = ed25519_ix(keys[0], digest);
        maybe_tally_rotation_ix(&ix, &digest, &keys, &mut signers).unwrap();
        maybe_tally_rotation_ix(&ix, &digest, &keys, &mut signers).unwrap();
        assert_eq!(signers.len(), 1);
    }

    #[test]
    fn pop_foreign_key_is_dropped() {
        let keys = three_keys();
        let digest = [0xCD; 32];
        let mut signers = Vec::new();
        let foreign = Pubkey::new_from_array([0xEE; 32]);
        let ix = ed25519_ix(foreign, digest);
        maybe_tally_rotation_ix(&ix, &digest, &keys, &mut signers).unwrap();
        assert!(signers.is_empty());
    }

    #[test]
    fn pop_wrong_digest_is_dropped() {
        let keys = three_keys();
        let expected = [0xCD; 32];
        let wrong    = [0xDC; 32];
        let mut signers = Vec::new();
        for k in &keys {
            let ix = ed25519_ix(*k, wrong);
            maybe_tally_rotation_ix(&ix, &expected, &keys, &mut signers).unwrap();
        }
        assert!(
            signers.is_empty(),
            "signatures over a wrong digest must not satisfy PoP — \
             this is the rotation-replay defence",
        );
    }
}
