// =============================================================================
// programs/certificate-issuer/src/instructions/challenge_certificate.rs
//
// AW-01-EXT.6 — on-chain challenge against a HealthCertificate's slot anchor.
//
// THE THREAT THIS CLOSES
// ----------------------
// The write-time `verify_slot_anchor` check (slot_anchor.rs) defends against
// COORDINATED upstream RPC poisoning while the cert is being issued: at
// issue time, Solana's SlotHashes sysvar (~512-slot / ~3.4-min window) is
// queried directly, so a forged slot anchor is caught on the spot.
//
// BUT: once the cert is on chain and the SlotHashes window has rolled past
// the cert's slot (~3.4 min later), the on-chain handler can no longer
// re-verify the anchor — the sysvar evidence is gone. A sophisticated
// attacker who succeeded in poisoning the cluster's upstream view AT
// scoring time would leave behind an "honest-looking" cert whose anchor
// merely cannot be cross-checked. AW-01-EXT.6 is the defence-in-depth
// against that gap.
//
// SHAPE: AttestedHistorical (Form B)
// ----------------------------------
// A challenger files M-of-N Ed25519 signatures from the configured
// `challenge_attester_keys` cluster (a DISJOINT third-party set — see
// IssuerConfig). Each signature is over the canonical
// CHALLENGE PAYLOAD DIGEST:
//
//     sha256( "helixor-aw01-ext-challenge" || cert_pubkey || true_block_hash )
//
// The attester cluster's job is to fetch `cert.slot_anchor_slot` from an
// INDEPENDENT source (their own RPC, a long-history archive node, etc.)
// and attest to the block hash they observe. The cert's pubkey is folded
// in so a (slot, hash) attestation against cert A cannot be replayed
// against cert B (which targets a different cert and so demands a
// different digest).
//
// OUTCOME
// -------
//   * `true_block_hash != cert.slot_anchor_hash` → UPHELD
//        - cert.challenge_state := Upheld   (REPUDIATED)
//        - record.state         := Upheld
//        - CertificateRepudiated event emitted
//        - downstream slash-authority (off-chain plumbing) reads the event
//   * `true_block_hash == cert.slot_anchor_hash` → REJECTED (frivolous)
//        - cert.challenge_state := Rejected
//        - record.state         := Rejected
//        - challenger's rent on the ChallengeRecord PDA is consumed
//          (the anti-spam cost)
//        - ChallengeRejected event emitted
//
// REPLAY PROTECTION
// -----------------
//   * ChallengeRecord PDA seed = ["challenge", cert_pubkey] → ONE record per
//     cert. Anchor `init` prevents a second challenge.
//   * Challenge digest binds cert_pubkey → a signature on cert A's
//     true_block_hash cannot be reused against cert B (different digest).
//
// =============================================================================

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_instruction_at_checked, ID as INSTRUCTIONS_ID};
use solana_program::{hash::hashv, instruction::Instruction};
use solana_sdk_ids::ed25519_program;

use crate::errors::CertificateError;
use crate::events::{CertificateRepudiated, ChallengeRejected};
use crate::state::{
    challenge_record::ChallengeRecord,
    health_certificate::{ChallengeState, HealthCertificate},
    IssuerConfig,
};

/// Cert layout versions LESS than this have no slot anchor and so cannot be
/// challenged.
const MIN_CHALLENGEABLE_LAYOUT_VERSION: u8 = 4;

/// The challenge window. The on-chain check uses the cert's `issued_at`
/// against `Clock::unix_timestamp`. 90 days is generous enough that an
/// auditor cross-checking historical certs has a meaningful window to
/// catch a coordinated upstream-poisoning attack — but bounded so the
/// cert state eventually becomes immutable (finality for downstream
/// consumers).
pub const CHALLENGE_WINDOW_SECONDS: i64 = 90 * 24 * 60 * 60;

/// Domain-separation tag on the challenge digest. Distinct from the cert
/// digest (`cert_payload_digest`) so an attacker cannot lift a cert
/// signature and reuse it as a challenge signature or vice versa.
const CHALLENGE_DOMAIN_TAG: &[u8] = b"helixor-aw01-ext-challenge";

// -----------------------------------------------------------------------------
// Canonical challenge-payload digest
// -----------------------------------------------------------------------------

/// Compute the 32-byte challenge digest the attester cluster signs over.
///
/// Layout (fixed, public):
///   "helixor-aw01-ext-challenge"  (26 bytes)
///   cert_pubkey                   (32 bytes) — binds the attestation to THIS cert
///   true_block_hash               (32 bytes) — the attester's observed truth
pub fn challenge_payload_digest(
    certificate:     &Pubkey,
    true_block_hash: &[u8; 32],
) -> [u8; 32] {
    let h = hashv(&[
        CHALLENGE_DOMAIN_TAG,
        certificate.as_ref(),
        true_block_hash,
    ]);
    h.to_bytes()
}

// -----------------------------------------------------------------------------
// Ed25519 precompile layout — mirror of signing.rs constants
// -----------------------------------------------------------------------------
//
// Kept local rather than pub-exposed because the cert-signing digest size and
// the challenge digest size happen to be identical (32 bytes); duplicating
// the constants avoids leaking signing.rs internals into a sibling module.

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

    let sig_offset = u16::from_le_bytes([ix.data[2],  ix.data[3]])  as usize;
    let sig_ix_idx = u16::from_le_bytes([ix.data[4],  ix.data[5]]);
    let pk_offset  = u16::from_le_bytes([ix.data[6],  ix.data[7]])  as usize;
    let pk_ix_idx  = u16::from_le_bytes([ix.data[8],  ix.data[9]]);
    let msg_offset = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
    let msg_size   = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;
    let msg_ix_idx = u16::from_le_bytes([ix.data[14], ix.data[15]]);

    const THIS_IX: u16 = u16::MAX;
    require!(
        sig_ix_idx == THIS_IX && pk_ix_idx == THIS_IX && msg_ix_idx == THIS_IX,
        CertificateError::CrossInstructionReference,
    );
    require!(msg_size == ED25519_MESSAGE_LEN, CertificateError::WrongDigestLength);
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

/// Tally a single Ed25519 precompile instruction against the ATTESTER
/// cluster. Mirrors `signing::maybe_tally_ed25519_ix` but checks against
/// `challenge_attester_keys` rather than `cluster_keys`.
fn maybe_tally_attester_ix(
    ix:              &Instruction,
    expected_digest: &[u8; 32],
    config:          &IssuerConfig,
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
    if !config.is_challenge_attester(&signer) {
        return Ok(());
    }
    if signers.contains(&signer) {
        return Ok(());
    }
    signers.push(signer);
    Ok(())
}

/// Verify the transaction carries at least `config.challenge_threshold`
/// Ed25519 precompile signatures whose:
///   - signed message equals `expected_digest`,
///   - signer pubkey is in `config.challenge_attester_keys`,
///   - and each distinct attester counts only once.
///
/// Returns the number of distinct attester-cluster signers counted, or
/// `InsufficientChallengeAttesters` if below threshold.
pub fn verify_attester_threshold(
    expected_digest:     &[u8; 32],
    config:              &IssuerConfig,
    instructions_sysvar: &AccountInfo,
) -> Result<u8> {
    require!(
        instructions_sysvar.key == &INSTRUCTIONS_ID,
        CertificateError::WrongInstructionsSysvar,
    );

    let mut signers: Vec<Pubkey> =
        Vec::with_capacity(IssuerConfig::MAX_CHALLENGE_ATTESTER_KEYS);
    let mut ix_index: usize = 0;
    while let Ok(ix) = load_instruction_at_checked(ix_index, instructions_sysvar) {
        ix_index += 1;
        if ix.program_id != ed25519_program::id() {
            continue;
        }
        maybe_tally_attester_ix(&ix, expected_digest, config, &mut signers)?;
    }

    let count = signers.len() as u8;
    require!(
        count >= config.challenge_threshold,
        CertificateError::InsufficientChallengeAttesters,
    );
    Ok(count)
}

// =============================================================================
// Accounts
// =============================================================================

#[derive(Accounts)]
pub struct ChallengeCertificate<'info> {
    /// The cert under challenge. Mutated to set `challenge_state`.
    /// Pinned by its PDA seeds so the caller cannot swap in a different
    /// cert account at the same address.
    #[account(
        mut,
        seeds = [
            HealthCertificate::SEED_PREFIX,
            certificate.agent_wallet.as_ref(),
            &certificate.epoch.to_le_bytes(),
        ],
        bump = certificate.bump,
    )]
    pub certificate: Account<'info, HealthCertificate>,

    /// The IssuerConfig singleton — supplies the challenge-attester cluster.
    #[account(
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The ChallengeRecord PDA. Init-once: one challenge per cert, ever.
    /// A second `challenge_certificate` against the same cert fails here
    /// (`init` aborts because the account already exists).
    #[account(
        init,
        payer = challenger,
        space = ChallengeRecord::SPACE,
        seeds = [ChallengeRecord::SEED_PREFIX, certificate.key().as_ref()],
        bump,
    )]
    pub challenge_record: Account<'info, ChallengeRecord>,

    /// The challenger — pays rent on the ChallengeRecord PDA. On a Rejected
    /// outcome this rent is consumed (sunk to the PDA, never recoverable).
    /// On an Upheld outcome it likewise stays sunk; an off-chain rebate path
    /// is out-of-scope for the on-chain ix.
    #[account(mut)]
    pub challenger: Signer<'info>,

    /// CHECK: the Instructions sysvar — read inside the handler to find
    /// the Ed25519 precompile instructions that carry the attester
    /// signatures. The handler verifies this is the right sysvar pubkey.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

// =============================================================================
// Handler
// =============================================================================

pub fn handler(
    ctx:             Context<ChallengeCertificate>,
    true_block_hash: [u8; 32],
) -> Result<()> {
    let cert     = &mut ctx.accounts.certificate;
    let config   = &ctx.accounts.issuer_config;
    let record   = &mut ctx.accounts.challenge_record;
    let clock    = Clock::get()?;

    // 1. The challenge cluster must be configured. Empty + zero-threshold
    //    means the operator deliberately left challenges DISABLED at
    //    deploy time (the safe default before attesters are wired). The
    //    write-time `verify_slot_anchor` remains the active defence.
    require!(
        config.challenge_enabled(),
        CertificateError::NoAttesterCluster,
    );

    // 2. The cert must carry a slot anchor. Pre-v4 certs predate AW-01-EXT
    //    and have nothing to challenge. (This will never trip for newly
    //    issued certs — `issue_certificate` always writes v5+ — but the
    //    check is here for the historical-cert path on cluster upgrades.)
    require!(
        cert.layout_version >= MIN_CHALLENGEABLE_LAYOUT_VERSION,
        CertificateError::PreV4CertNotChallengeable,
    );

    // 3. A cert can be challenged at most ONCE. The init-once on the
    //    ChallengeRecord PDA is the primary guard; this is a redundant
    //    direct check that gives the operator a clear error code rather
    //    than a generic "account already exists" Anchor error.
    let prior_state = ChallengeState::from_u8(cert.challenge_state)
        .unwrap_or(ChallengeState::None);
    require!(
        prior_state == ChallengeState::None,
        CertificateError::ChallengeAlreadyFiled,
    );

    // 4. The challenge window. After CHALLENGE_WINDOW_SECONDS the cert is
    //    final — no challenges accepted. (Saturating sub so a future
    //    `issued_at` reads as 0 elapsed and stays inside the window.)
    let age_seconds = clock.unix_timestamp.saturating_sub(cert.issued_at);
    require!(
        age_seconds <= CHALLENGE_WINDOW_SECONDS,
        CertificateError::ChallengeExpired,
    );

    // 5. Verify the attester threshold over the canonical challenge
    //    digest. Same Ed25519-precompile pattern as cert-signing, but
    //    against the DISJOINT attester key set.
    let cert_key = cert.key();
    let digest = challenge_payload_digest(&cert_key, &true_block_hash);
    let attester_count = verify_attester_threshold(
        &digest,
        config,
        &ctx.accounts.instructions_sysvar.to_account_info(),
    )?;

    // 6. Decide UPHELD vs REJECTED purely on the hash comparison. The
    //    attester cluster has cryptographically attested that
    //    `true_block_hash` is what they observe at `cert.slot_anchor_slot`.
    //    The cert is repudiated iff that diverges from what the cert
    //    pinned at issue time.
    let outcome = if true_block_hash == cert.slot_anchor_hash {
        ChallengeState::Rejected
    } else {
        ChallengeState::Upheld
    };

    // 7. Persist the outcome on BOTH the cert (so downstream consumers
    //    can read it from the cert account directly) and the
    //    ChallengeRecord (the immutable audit trail).
    cert.challenge_state = outcome.as_u8();

    record.certificate     = cert_key;
    record.agent_wallet    = cert.agent_wallet;
    record.epoch           = cert.epoch;
    record.challenger      = ctx.accounts.challenger.key();
    record.filed_at        = clock.unix_timestamp;
    record.true_block_hash = true_block_hash;
    record.attester_count  = attester_count;
    record.state           = outcome.as_u8();
    record.layout_version  = ChallengeRecord::CURRENT_LAYOUT_VERSION;
    record.bump            = ctx.bumps.challenge_record;

    // 8. Emit the outcome event. The slash-authority program (off-chain
    //    plumbing) is the primary consumer of CertificateRepudiated —
    //    it triggers the cluster-side slashing flow.
    match outcome {
        ChallengeState::Upheld => {
            emit!(CertificateRepudiated {
                certificate:         cert_key,
                agent_wallet:        cert.agent_wallet,
                epoch:               cert.epoch,
                challenger:          ctx.accounts.challenger.key(),
                cluster_anchor_slot: cert.slot_anchor_slot,
                cluster_anchor_hash: cert.slot_anchor_hash,
                true_block_hash,
                attester_count,
                filed_at:            record.filed_at,
            });
            msg!(
                "challenge UPHELD: cert={} agent={} epoch={} attesters={}",
                cert_key, cert.agent_wallet, cert.epoch, attester_count,
            );
        }
        ChallengeState::Rejected => {
            emit!(ChallengeRejected {
                certificate:        cert_key,
                agent_wallet:       cert.agent_wallet,
                epoch:              cert.epoch,
                challenger:         ctx.accounts.challenger.key(),
                claimed_block_hash: true_block_hash,
                filed_at:           record.filed_at,
            });
            msg!(
                "challenge REJECTED (frivolous): cert={} attesters={}",
                cert_key, attester_count,
            );
        }
        // The `prior_state == None` guard above means we never reach
        // this branch with `None`; the match is exhaustive over the
        // outcome enum.
        ChallengeState::None => unreachable!(
            "outcome can only be Upheld or Rejected post-verification",
        ),
    }

    Ok(())
}

// =============================================================================
// Tests — runtime-free coverage of the challenge digest + decision logic
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_attesters(
        cluster_keys:            Vec<Pubkey>,
        challenge_attester_keys: Vec<Pubkey>,
        challenge_threshold:     u8,
    ) -> IssuerConfig {
        IssuerConfig {
            authority:                Pubkey::new_unique(),
            issuer_node:              Pubkey::new_unique(),
            cluster_keys,
            threshold:                1,
            bump:                     255,
            health_oracle_program_id: Pubkey::default(),
            challenge_attester_keys,
            challenge_threshold,
            // M-05: challenge-tally tests don't exercise the cert-issuance
            // digest path; pin the genesis snapshot.
            config_version:           1,
        }
    }

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
        data.extend_from_slice(&[9u8; ED25519_SIGNATURE_LEN]);
        data.extend_from_slice(&message);

        Instruction { program_id: ed25519_program::id(), accounts: Vec::new(), data }
    }

    // ── Digest properties ───────────────────────────────────────────────────

    #[test]
    fn digest_is_32_bytes() {
        let d = challenge_payload_digest(&Pubkey::new_unique(), &[1u8; 32]);
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn digest_is_deterministic() {
        let cert = Pubkey::new_unique();
        let hash = [7u8; 32];
        assert_eq!(
            challenge_payload_digest(&cert, &hash),
            challenge_payload_digest(&cert, &hash),
        );
    }

    #[test]
    fn digest_binds_to_cert_pubkey() {
        // Same true_block_hash, different certs → different digests.
        // This is the cross-cert replay defence.
        let h = [3u8; 32];
        let a = challenge_payload_digest(&Pubkey::new_unique(), &h);
        let b = challenge_payload_digest(&Pubkey::new_unique(), &h);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_binds_to_true_block_hash() {
        let cert = Pubkey::new_unique();
        let a = challenge_payload_digest(&cert, &[1u8; 32]);
        let b = challenge_payload_digest(&cert, &[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_uses_distinct_domain_tag_from_cert_digest() {
        // The challenge digest must not collide with cert_payload_digest
        // for any plausible inputs — distinct domain tag + distinct
        // structure ensures that. Sanity-check: the prefix bytes differ.
        let cert = Pubkey::new_from_array([0x11; 32]);
        let challenge_d = challenge_payload_digest(&cert, &[0u8; 32]);
        let cert_d = crate::signing::cert_payload_digest(
            &cert, 1, 0, 0, 0, &[0u8; 32], false, &[0u8; 32], 0, &[0u8; 32], 0,
            &[0u8; 32], &[0u8; 32], 0,
            // Day 38: pre-Day-38 sentinel — zero diagnostic certificate.
            0, 0, &[0u8; 32], 0,
        );
        assert_ne!(challenge_d, cert_d);
    }

    // ── Attester-cluster filtering ──────────────────────────────────────────

    #[test]
    fn correct_attester_signatures_are_counted() {
        let attesters: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_attesters(
            vec![Pubkey::new_unique(); 3],
            attesters.clone(),
            2,
        );
        let digest = [1u8; 32];
        let mut signers = Vec::new();
        for key in attesters.iter().take(2) {
            let ix = ed25519_ix(*key, digest);
            maybe_tally_attester_ix(&ix, &digest, &config, &mut signers).unwrap();
        }
        assert_eq!(signers.len(), 2);
    }

    #[test]
    fn duplicate_attester_is_counted_once() {
        let attesters: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_attesters(
            vec![Pubkey::new_unique(); 3],
            attesters.clone(),
            2,
        );
        let digest = [2u8; 32];
        let mut signers = Vec::new();
        let ix = ed25519_ix(attesters[0], digest);
        maybe_tally_attester_ix(&ix, &digest, &config, &mut signers).unwrap();
        maybe_tally_attester_ix(&ix, &digest, &config, &mut signers).unwrap();
        assert_eq!(signers.len(), 1);
    }

    #[test]
    fn non_attester_key_is_not_counted() {
        let attesters: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_attesters(
            vec![Pubkey::new_unique(); 3],
            attesters,
            2,
        );
        let digest = [3u8; 32];
        let mut signers = Vec::new();
        // A random pubkey — not in the attester cluster.
        let ix = ed25519_ix(Pubkey::new_unique(), digest);
        maybe_tally_attester_ix(&ix, &digest, &config, &mut signers).unwrap();
        assert!(signers.is_empty());
    }

    #[test]
    fn cert_signing_key_is_not_counted_as_attester() {
        // The architectural invariant — even if a cert-signing cluster key
        // happens to sign the challenge digest, it MUST NOT count toward
        // the attester threshold (the attester cluster is disjoint by
        // design; this enforces the property at the verifier).
        let cert_signers: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let attesters:    Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_attesters(
            cert_signers.clone(),
            attesters,
            2,
        );
        let digest = [4u8; 32];
        let mut signers = Vec::new();
        let ix = ed25519_ix(cert_signers[0], digest);
        maybe_tally_attester_ix(&ix, &digest, &config, &mut signers).unwrap();
        assert!(signers.is_empty());
    }

    #[test]
    fn wrong_digest_signatures_are_filtered() {
        // The replay defence: a valid attester signature over the WRONG
        // digest must not contribute to the count.
        let attesters: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_attesters(
            vec![Pubkey::new_unique(); 3],
            attesters.clone(),
            2,
        );
        let expected_digest   = [1u8; 32];
        let historical_digest = [2u8; 32];
        let mut signers = Vec::new();
        for key in attesters.iter().take(2) {
            let ix = ed25519_ix(*key, historical_digest);
            maybe_tally_attester_ix(&ix, &expected_digest, &config, &mut signers).unwrap();
        }
        assert!(signers.is_empty());
    }

    // ── Constants ───────────────────────────────────────────────────────────

    #[test]
    fn challenge_window_is_ninety_days() {
        assert_eq!(CHALLENGE_WINDOW_SECONDS, 90 * 24 * 60 * 60);
    }

    #[test]
    fn min_challengeable_layout_version_pins_aw01_ext() {
        assert_eq!(MIN_CHALLENGEABLE_LAYOUT_VERSION, 4);
    }
}
