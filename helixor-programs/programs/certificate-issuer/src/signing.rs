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
// flags || baseline_hash || immediate_red ). Fixed-width big-endian integers, fixed order
// — same canonical-serialisation discipline as Day 25's commit_reveal. A
// signer signs the DIGEST, not the unhashed bytes, so we control payload
// length (the Ed25519 precompile signs arbitrary-length messages, but
// fixed-length signed-message bytes simplify verification).
// =============================================================================

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_instruction_at_checked, ID as INSTRUCTIONS_ID};
use solana_program::{hash::hashv, instruction::Instruction};
use solana_sdk_ids::ed25519_program;

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
    baseline_hash:  &[u8; 32],
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
        baseline_hash,                       // 32 bytes
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
        ix.data.len() >= ED25519_HEADER_LEN.saturating_add(ED25519_PUBKEY_LEN)
                       .saturating_add(ED25519_SIGNATURE_LEN).saturating_add(ED25519_MESSAGE_LEN),
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
    let sig_ix_idx    = u16::from_le_bytes([ix.data[4],  ix.data[5]]);
    let pk_offset     = u16::from_le_bytes([ix.data[6],  ix.data[7]])  as usize;
    let pk_ix_idx     = u16::from_le_bytes([ix.data[8],  ix.data[9]]);
    let msg_offset    = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
    let msg_size      = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;
    let msg_ix_idx    = u16::from_le_bytes([ix.data[14], ix.data[15]]);

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

fn maybe_tally_ed25519_ix(
    ix:              &Instruction,
    expected_digest: &[u8; 32],
    config:          &IssuerConfig,
    signers:         &mut Vec<Pubkey>,
) -> Result<()> {
    if ix.program_id != ed25519_program::id() {
        return Ok(());                              // not a precompile ix
    }

    // Gracefully skip precompile instructions we cannot parse (e.g. a
    // multi-signature packed precompile, or wrong digest length). The
    // runtime already validated whatever the precompile says; our only
    // job is to count signers that meet OUR criteria. Unrecognised
    // formats simply produce no tally contribution. The threshold check
    // at the end of verify_threshold_signatures catches any deficit.
    let record = match parse_ed25519_ix(ix) {
        Ok(r)  => r,
        Err(_) => return Ok(()),
    };

    // SECURITY: This is the binding that closes the threshold-bypass attack.
    // The Ed25519 precompile has already cryptographically proven (sig, pubkey)
    // over `record.message`. We now require that `record.message` equals the
    // digest we computed from THIS instruction's exact (agent, epoch, score,
    // alert_tier, flags, baseline_hash, immediate_red) payload. Without this
    // check the threshold degenerates to "did N cluster keys sign anything",
    // enabling replay of any past oracle signature over any historical cert.
    // Every Ed25519 instruction whose message does not match our payload is
    // silently discarded and contributes nothing to the signer count.
    if record.message != *expected_digest {
        return Ok(());
    }

    let signer = Pubkey::new_from_array(record.pubkey);

    // Must be a cluster key.
    if !config.is_cluster_key(&signer) {
        return Ok(());
    }

    // Distinct only -- a node signing twice counts once.
    if signers.contains(&signer) {
        return Ok(());
    }
    signers.push(signer);
    Ok(())
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
    while let Ok(ix) = load_instruction_at_checked(ix_index, instructions_sysvar) {
        ix_index += 1;

        if ix.program_id != ed25519_program::id() {
            continue;                                 // not a precompile ix
        }

        maybe_tally_ed25519_ix(&ix, expected_digest, config, &mut signers)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_keys(cluster_keys: Vec<Pubkey>, threshold: u8) -> IssuerConfig {
        IssuerConfig {
            authority: Pubkey::new_unique(),
            issuer_node: Pubkey::new_unique(),
            cluster_keys,
            threshold,
            bump: 255,
            // VULN-16: signature-verification tests don't exercise the
            // CPI path; a zero allow-list keeps the helper purely about
            // signatures.
            health_oracle_program_id: Pubkey::default(),
        }
    }

    fn ed25519_ix(pubkey: Pubkey, message: [u8; 32]) -> Instruction {
        let mut data = Vec::with_capacity(
            ED25519_HEADER_LEN + ED25519_PUBKEY_LEN + ED25519_SIGNATURE_LEN + ED25519_MESSAGE_LEN,
        );

        let pk_offset: u16 = ED25519_HEADER_LEN as u16;
        let sig_offset: u16 = pk_offset + ED25519_PUBKEY_LEN as u16;
        let msg_offset: u16 = sig_offset + ED25519_SIGNATURE_LEN as u16;
        let this_ix = u16::MAX.to_le_bytes();

        data.push(1);                                // num signatures
        data.push(0);                                // padding
        data.extend_from_slice(&sig_offset.to_le_bytes());
        data.extend_from_slice(&this_ix);
        data.extend_from_slice(&pk_offset.to_le_bytes());
        data.extend_from_slice(&this_ix);
        data.extend_from_slice(&msg_offset.to_le_bytes());
        data.extend_from_slice(&(ED25519_MESSAGE_LEN as u16).to_le_bytes());
        data.extend_from_slice(&this_ix);
        data.extend_from_slice(pubkey.as_ref());
        data.extend_from_slice(&[9u8; ED25519_SIGNATURE_LEN]);
        data.extend_from_slice(&message);

        Instruction {
            program_id: ed25519_program::id(),
            accounts: Vec::new(),
            data,
        }
    }

    // ── Happy-path coverage ──────────────────────────────────────────────────

    #[test]
    fn correct_signatures_over_current_digest_are_counted() {
        let keys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_keys(keys.clone(), 3);
        let digest = [1u8; 32];
        let mut signers = Vec::new();

        for key in keys.iter().take(3) {
            let ix = ed25519_ix(*key, digest);
            maybe_tally_ed25519_ix(&ix, &digest, &config, &mut signers).unwrap();
        }

        assert_eq!(
            signers.len(), 3,
            "three cluster keys signing the correct digest must all be counted",
        );
    }

    #[test]
    fn all_five_signers_counted_when_present() {
        let keys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_keys(keys.clone(), 3);
        let digest = [0xABu8; 32];
        let mut signers = Vec::new();

        for key in &keys {
            let ix = ed25519_ix(*key, digest);
            maybe_tally_ed25519_ix(&ix, &digest, &config, &mut signers).unwrap();
        }

        assert_eq!(signers.len(), 5, "all five cluster keys must be counted");
    }

    // ── Duplicate-signer deduplication ──────────────────────────────────────

    #[test]
    fn duplicate_signer_is_counted_once_not_twice() {
        let keys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_keys(keys.clone(), 3);
        let digest = [2u8; 32];
        let mut signers = Vec::new();

        // Same key submitted in two separate precompile instructions.
        let ix = ed25519_ix(keys[0], digest);
        maybe_tally_ed25519_ix(&ix, &digest, &config, &mut signers).unwrap();
        maybe_tally_ed25519_ix(&ix, &digest, &config, &mut signers).unwrap();

        assert_eq!(
            signers.len(), 1,
            "a cluster key that appears twice must be counted exactly once",
        );
    }

    // ── Non-cluster-key filtering ────────────────────────────────────────────

    #[test]
    fn non_cluster_key_is_not_counted() {
        let keys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_keys(keys.clone(), 3);
        let digest = [3u8; 32];
        let mut signers = Vec::new();

        // A foreign key that is NOT in the cluster.
        let foreign_key = Pubkey::new_unique();
        let ix = ed25519_ix(foreign_key, digest);
        maybe_tally_ed25519_ix(&ix, &digest, &config, &mut signers).unwrap();

        assert!(
            signers.is_empty(),
            "a key not in the cluster must not contribute to the signer count",
        );
    }

    // ── Replay / historical-digest attack ────────────────────────────────────

    #[test]
    fn historical_digest_signatures_do_not_count_toward_threshold() {
        let keys = vec![
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ];
        let config = config_with_keys(keys.clone(), 3);
        let expected_digest = [1u8; 32];
        let historical_digest = [2u8; 32];
        let mut signers = Vec::new();

        for key in keys.iter().take(3) {
            let ix = ed25519_ix(*key, historical_digest);
            maybe_tally_ed25519_ix(&ix, &expected_digest, &config, &mut signers).unwrap();
        }

        assert!(
            signers.is_empty(),
            "valid cluster signatures over the wrong digest must be filtered out",
        );
    }

    // ── VULN-01 attack simulation ────────────────────────────────────────────
    // An attacker collects N valid oracle signatures from past epochs and
    // submits them in a transaction for a DIFFERENT (agent, epoch, score).
    // The precompile accepts those signatures as valid (they are — just for
    // another payload). verify_threshold_signatures must reject them because
    // record.message != expected_digest. These tests confirm that gate holds.

    #[test]
    fn threshold_bypass_attack_with_three_historical_sigs_yields_zero_count() {
        let keys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_keys(keys.clone(), 3);
        // The attacker knows the digest for epoch 9, score 999, agent X.
        let historical_digest = [0xDDu8; 32];
        // The current instruction is for epoch 10, score 999, agent ATTACKER.
        let current_digest    = [0xEEu8; 32];
        let mut signers = Vec::new();

        // Attacker replays 3 legitimate oracle signatures from epoch 9.
        for key in keys.iter().take(3) {
            let ix = ed25519_ix(*key, historical_digest);
            maybe_tally_ed25519_ix(&ix, &current_digest, &config, &mut signers).unwrap();
        }

        assert!(
            signers.is_empty(),
            "replayed historical-epoch oracle signatures must not satisfy the current threshold",
        );
    }

    #[test]
    fn partial_bypass_attack_historical_plus_current_stays_below_threshold() {
        let keys: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_keys(keys.clone(), 3);
        let historical_digest = [0xDDu8; 32];
        let current_digest    = [0xEEu8; 32];
        let mut signers = Vec::new();

        // Attacker has 2 legitimate current sigs but pads with 1 historical sig
        // hoping to reach the threshold of 3.
        let ix_current_0 = ed25519_ix(keys[0], current_digest);
        let ix_current_1 = ed25519_ix(keys[1], current_digest);
        let ix_hist_2    = ed25519_ix(keys[2], historical_digest);

        maybe_tally_ed25519_ix(&ix_current_0, &current_digest, &config, &mut signers).unwrap();
        maybe_tally_ed25519_ix(&ix_current_1, &current_digest, &config, &mut signers).unwrap();
        maybe_tally_ed25519_ix(&ix_hist_2,    &current_digest, &config, &mut signers).unwrap();

        assert_eq!(
            signers.len(), 2,
            "two current-digest sigs + one historical-digest sig must not reach the threshold of 3",
        );
    }

    #[test]
    fn only_current_payload_digest_counts_toward_threshold() {
        let keys = vec![
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ];
        let config = config_with_keys(keys.clone(), 3);
        let expected_digest = [1u8; 32];
        let historical_digest = [2u8; 32];
        let mut signers = Vec::new();

        for key in keys.iter().take(2) {
            let ix = ed25519_ix(*key, expected_digest);
            maybe_tally_ed25519_ix(&ix, &expected_digest, &config, &mut signers).unwrap();
        }
        let replay_ix = ed25519_ix(keys[2], historical_digest);
        maybe_tally_ed25519_ix(&replay_ix, &expected_digest, &config, &mut signers).unwrap();

        assert_eq!(
            signers.len(),
            2,
            "two correct signatures plus one replayed digest must remain below threshold",
        );
    }
}
