// =============================================================================
// programs/certificate-issuer/src/signing.rs
//
// Day 27 — 3-of-5 threshold signature verification for certificate writes.
//
// THE DESIGN — TWO HONEST CHOICES
// -------------------------------
// The spec invited either Squads Protocol v4 or a threshold-signature
// scheme, and asked the choice be documented. The cert-issuer uses a
// THRESHOLD SIGNATURE SCHEME, not Squads v4. Why:
//
//   1. SELF-CONTAINED. The threshold is checked here in our own program,
//      with no external program ID, IDL version, or vault PDA to depend
//      on. The spec says: "`certificate_issuer` gains an Anchor constraint:
//      reject any cert write not carrying 3 valid oracle signatures."
//      That constraint LIVES IN THIS PROGRAM. A Squads-vault gate would
//      move the check into Squads and our program would just trust the
//      caller PDA — weaker. Threshold sigs PROVE authorship to our code.
//
//   2. SHIPS ON DEVNET. Squads v4 integration has weight — its program ID,
//      IDL pinning, proposal/approve/execute flow, member-set
//      bookkeeping. For a 30-day build with the rest of the stack
//      iterating daily, threshold sigs are far less coupling.
//
//   3. COMPOSABLE LATER. A Squads vote, when it executes, can simply pass
//      the same Vec of signatures to our ix. So Squads is wrappable on
//      top of this; this is not wrappable on top of Squads.
//
// HOW IT WORKS
// ------------
// Solana cannot perform expensive crypto inside a program directly. The
// pattern is to use the `Ed25519` SYSCALL PRECOMPILE: the client puts one
// `Ed25519Program` instruction PER SIGNATURE into the transaction; the
// runtime verifies them natively (cheap); our handler then READS the
// `instructions` sysvar and CONFIRMS that each (pubkey, message, signature)
// the precompile saw was over our canonical cert payload AND from a known
// cluster key, then counts distinct cluster keys >= threshold.
//
// CANONICAL PAYLOAD
// -----------------
// The signed payload is sha256( agent || epoch || score || alert_tier ||
// flags || confidence || immediate_red ). Fixed-width big-endian integers, fixed order
// — same canonical-serialisation discipline as Day 25's commit_reveal. A
// signer signs the DIGEST, not the unhashed bytes, so we control payload
// length (the Ed25519 precompile signs arbitrary-length messages, but
// fixed-length signed-message bytes simplify verification).
// =============================================================================

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    ed25519_program,
    hash::hashv,
    instruction::Instruction,
    sysvar::instructions::{load_instruction_at_checked, ID as INSTRUCTIONS_ID},
};

use crate::errors::CertificateError;
use crate::state::IssuerConfig;

// -----------------------------------------------------------------------------
// Canonical certificate-payload digest
// -----------------------------------------------------------------------------

/// Compute the 32-byte canonical digest the cluster keys sign over.
/// The off-chain signer (helixor-oracle/oracle/cluster/cert_signing.py)
/// computes the identical bytes; mismatch = unsignable certificate.
pub fn cert_payload_digest(
    agent_wallet:   &Pubkey,
    epoch:          u64,
    score:          u16,
    alert_tier:     u8,
    flags:          u32,
    confidence:     u16,
    immediate_red:  bool,
) -> [u8; 32] {
    // The byte layout is FIXED and PUBLIC — every signer and verifier must
    // produce these exact bytes. No floats, no Vec, no length-varying
    // field, no separator ambiguity.
    let immediate_red_byte: u8 = if immediate_red { 1 } else { 0 };
    let h = hashv(&[
        agent_wallet.as_ref(),               // 32 bytes
        &epoch.to_be_bytes(),                //  8 bytes
        &score.to_be_bytes(),                //  2 bytes
        &[alert_tier],                       //  1 byte
        &flags.to_be_bytes(),                //  4 bytes
        &confidence.to_be_bytes(),           //  2 bytes
        &[immediate_red_byte],               //  1 byte
    ]);
    h.to_bytes()
}

// -----------------------------------------------------------------------------
// Ed25519 precompile instruction layout
// -----------------------------------------------------------------------------
//
// The `Ed25519Program` precompile expects, per signature, a 16-byte header
// (offsets) and three fields concatenated: pubkey (32), signature (64),
// message (N). One precompile instruction can carry multiple signature
// records, but we read them one-instruction-per-signature here — simple
// and exactly how the off-chain builder produces them.
//
// Layout (single-signature variant we use):
//   [0]    num_signatures (u8, = 1)
//   [1]    padding       (u8)
//   [2..4] signature_offset (u16 LE)
//   [4..6] signature_instruction_index (u16 LE, 0xFFFF = "this ix")
//   [6..8] public_key_offset (u16 LE)
//   [8..10]public_key_instruction_index (u16 LE)
//   [10..12]message_data_offset (u16 LE)
//   [12..14]message_data_size  (u16 LE)
//   [14..16]message_instruction_index (u16 LE)
//   [16..16+32]   public key
//   [48..48+64]   signature
//   [112..]       message bytes
//
// We only need the published OFFSETS to find pubkey + message; the
// precompile itself has already cryptographically verified the signature
// (or the transaction would have aborted before our handler ran). Our job
// is to READ the (pubkey, message) pairs and check them against our
// expectations.

const ED25519_NUM_SIGNATURES_OFFSET: usize = 0;
const ED25519_HEADER_LEN: usize            = 16;
const ED25519_PUBKEY_LEN: usize            = 32;
const ED25519_SIGNATURE_LEN: usize         = 64;

// The expected message size — our digest is always exactly 32 bytes.
const ED25519_MESSAGE_LEN: usize           = 32;

/// One verified (pubkey, message) pair extracted from a single-signature
/// Ed25519 precompile instruction.
#[derive(Debug, Clone, Copy)]
struct PrecompileRecord {
    pubkey:  [u8; 32],
    message: [u8; 32],
}

fn parse_ed25519_ix(ix: &Instruction) -> Result<PrecompileRecord> {
    // The data must be at least one header + the pubkey + sig + message.
    require!(
        ix.data.len() >= ED25519_HEADER_LEN + ED25519_PUBKEY_LEN
                       + ED25519_SIGNATURE_LEN + ED25519_MESSAGE_LEN,
        CertificateError::MalformedEd25519Instruction,
    );
    // Single-signature record (what our off-chain builder emits).
    require!(
        ix.data[ED25519_NUM_SIGNATURES_OFFSET] == 1,
        CertificateError::MalformedEd25519Instruction,
    );

    // Read the offsets and confirm they point INSIDE this instruction's
    // data, with the expected sizes. (We don't follow cross-instruction
    // references; an attacker that tried would fail the bounds checks.)
    let sig_offset    = u16::from_le_bytes([ix.data[2],  ix.data[3]])  as usize;
    let sig_ix_idx    = u16::from_le_bytes([ix.data[4],  ix.data[5]])  as u16;
    let pk_offset     = u16::from_le_bytes([ix.data[6],  ix.data[7]])  as usize;
    let pk_ix_idx     = u16::from_le_bytes([ix.data[8],  ix.data[9]])  as u16;
    let msg_offset    = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
    let msg_size      = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;
    let msg_ix_idx    = u16::from_le_bytes([ix.data[14], ix.data[15]]) as u16;

    // The sentinel u16::MAX (0xFFFF) means "same instruction" — which is
    // what we require so an attacker cannot misdirect to another ix's data.
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
        pk_offset + ED25519_PUBKEY_LEN <= ix.data.len()
            && sig_offset + ED25519_SIGNATURE_LEN <= ix.data.len()
            && msg_offset + msg_size <= ix.data.len(),
        CertificateError::MalformedEd25519Instruction,
    );

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&ix.data[pk_offset .. pk_offset + ED25519_PUBKEY_LEN]);
    let mut message = [0u8; 32];
    message.copy_from_slice(&ix.data[msg_offset .. msg_offset + msg_size]);

    Ok(PrecompileRecord { pubkey, message })
}

// -----------------------------------------------------------------------------
// The threshold check
// -----------------------------------------------------------------------------

/// Verify that the current transaction carries at least
/// `config.threshold` Ed25519 precompile instructions whose:
///   - signed message equals `expected_digest`,
///   - signer pubkey is a cluster key from `config.cluster_keys`,
///   - and that each distinct cluster key counts only ONCE.
///
/// Below threshold -> InsufficientSignatures, the ix fails.
///
/// `instructions_sysvar` must be the instructions sysvar AccountInfo (the
/// caller declares it; Anchor's `Sysvar<Instructions>` is not used here
/// because we walk every instruction in the tx, including ones before our
/// own).
pub fn verify_threshold_signatures(
    expected_digest:     &[u8; 32],
    config:              &IssuerConfig,
    instructions_sysvar: &AccountInfo,
) -> Result<u8> {
    // Sanity check the sysvar account.
    require!(
        instructions_sysvar.key == &INSTRUCTIONS_ID,
        CertificateError::WrongInstructionsSysvar,
    );

    // Walk every instruction in the transaction, collect the Ed25519
    // precompile ones, parse them, and tally the distinct cluster-key
    // signers whose signed message matches our expected digest.
    let mut signers: Vec<Pubkey> = Vec::with_capacity(IssuerConfig::MAX_CLUSTER_KEYS);
    let mut ix_index: usize = 0;
    loop {
        let ix = match load_instruction_at_checked(ix_index, instructions_sysvar) {
            Ok(ix) => ix,
            Err(_) => break,                          // no more instructions
        };
        ix_index += 1;

        if ix.program_id != ed25519_program::ID {
            continue;                                 // not a precompile ix
        }

        let record = parse_ed25519_ix(&ix)?;

        // The signed MESSAGE must be exactly our expected cert digest.
        // The precompile already verified the signature is valid for this
        // (pubkey, message); our job is to bind the message to OUR payload
        // — a signer signing a DIFFERENT message gets counted out here.
        if record.message != *expected_digest {
            continue;
        }

        let signer = Pubkey::new_from_array(record.pubkey);

        // Must be a cluster key.
        if !config.is_cluster_key(&signer) {
            continue;
        }

        // Distinct only -- a node signing twice counts once.
        if signers.contains(&signer) {
            continue;
        }
        signers.push(signer);
    }

    let count = signers.len() as u8;
    require!(
        count >= config.threshold,
        CertificateError::InsufficientSignatures,
    );

    msg!(
        "threshold signatures verified: {} of {} (threshold {})",
        count, config.cluster_keys.len(), config.threshold,
    );
    Ok(count)
}
