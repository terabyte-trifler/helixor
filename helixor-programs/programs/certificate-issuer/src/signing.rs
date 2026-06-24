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
// flags || baseline_hash || immediate_red || input_commitment ).
// Fixed-width big-endian integers, fixed order — same canonical-serialisation
// discipline as Day 25's commit_reveal. A signer signs the DIGEST, not the
// unhashed bytes, so we control payload length (the Ed25519 precompile signs
// arbitrary-length messages, but fixed-length signed-message bytes simplify
// verification).
//
// AW-01 — TRUST TRANSITIVITY
// --------------------------
// The trailing 32-byte `input_commitment` is the cluster-majority SHA-256
// commitment over the canonical input transactions + windows that produced
// the score (see helixor-oracle/oracle/cluster/input_commitment.py). Folding
// it into the digest means the Ed25519 signature cryptographically attests to
// the INPUTS — not just to cluster agreement on a derived score. A DeFi
// consumer re-derives the commitment from observable on-chain transactions
// and refuses certs whose declared inputs do not match what they see; this
// closes the bypass where a sophisticated attacker poisons the upstream data
// pipeline (Geyser / Kafka / indexer) so every node honestly agrees on a
// false score over false inputs.
//
// AW-03 — BASELINE DATA AVAILABILITY
// ----------------------------------
// The trailing 8-byte `baseline_commit_nonce` is the
// `AgentRegistration.commit_nonce` at which the cluster's `baseline_hash`
// was committed on health-oracle. Folding it into the digest means the
// threshold signatures attest to a SPECIFIC ROTATION of the baseline — not
// just to "some baseline with this hash". A third-party verifier derives the
// `BaselineDataAccount` PDA from `["baseline_data", agent, nonce_le]`,
// fetches the on-chain payload bytes, and confirms `sha256(payload) ==
// baseline_hash`. Without the nonce in the digest, a malicious cluster
// could rotate the agent's baseline mid-attack and still emit a cert with a
// stale hash that no longer points at a fetchable DA account — folding it in
// makes that drift cryptographically detectable.
//
// AW-04 — SCORING ENGINE PROVENANCE
// ---------------------------------
// The trailing 32-byte `scoring_code_hash` is the SHA-256 over the
// canonical scoring kernel source bytes plus the algo + weights version
// labels (see `helixor-oracle/scoring/bundle_hash.py`). The trailing
// 32-byte `score_components_hash` is the SHA-256 over the canonical-JSON
// per-dimension breakdown the cluster published in the paired
// `ScoreComponentsAccount`. Folding BOTH into the digest closes the
// black-box-scoring gap: the Ed25519 signature now attests to (a) the
// EXACT source bytes that produced this score (a cluster shipping
// patched scoring code while claiming the published algo version cannot
// produce a digest whose `scoring_code_hash` matches what the audit
// gate independently computes from the published source tree), AND
// (b) the FULL per-dimension breakdown (a cluster cannot publish a
// fabricated score without committing to a `dims[]` whose
// `sum(contrib) -> clamp -> delta_guard` produces that same score —
// every input to the off-chain replay is in the signed digest). SDK
// consumers run `verifyScoreComputation` to re-execute the published
// bundle against the published components and refuse certs whose
// replay disagrees with the cert's stored score. The legacy values
// `[0u8; 32]` are the pre-AW-04 sentinels.
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
///
/// AW-01: `input_commitment` is the 32-byte cluster-majority commitment
/// over the canonical input transactions + windows. The cluster only
/// produces a cert if a quorum agreed on this commitment; folding it
/// into the on-chain digest binds the Ed25519 signature to the INPUTS,
/// not just to cluster agreement on a derived score.
///
/// AW-01-EXT: `slot_anchor_slot` + `slot_anchor_hash` is the Solana
/// `(slot, block_hash)` the cluster pinned at scoring time. Folding it
/// into the digest means the threshold signatures attest to a specific
/// point in Solana's own ledger. The on-chain handler additionally
/// verifies the anchor against the `SlotHashes` sysvar — so an attacker
/// who poisoned every upstream RPC the cluster reads from STILL cannot
/// produce a digest that survives on-chain verification, because
/// Solana's own ledger is the independent third source of truth.
///
/// AW-03: `baseline_commit_nonce` is the `AgentRegistration.commit_nonce`
/// the cluster's `baseline_hash` was committed at on health-oracle. It
/// pins the digest to a SPECIFIC ROTATION of the baseline so a verifier
/// can fetch the exact on-chain `BaselineDataAccount` and re-derive
/// `sha256(payload) == baseline_hash`. The legacy value `0` is the
/// pre-AW-03 sentinel (no DA account is reachable for this cert).
///
/// AW-04: `scoring_code_hash` is the SHA-256 over the canonical scoring
/// kernel source bytes + algo/weights version labels (see
/// `helixor-oracle/scoring/bundle_hash.py`). `score_components_hash`
/// is the SHA-256 over the canonical-JSON per-dimension breakdown the
/// cluster wrote into the paired `ScoreComponentsAccount`. Folding both
/// into the digest cryptographically attests to the exact source bytes
/// AND the full per-dimension breakdown — a cluster that fabricates a
/// score, or runs patched scoring code, is caught by an SDK consumer's
/// `verifyScoreComputation` because the replay disagrees with the
/// signed score. The legacy value `[0; 32]` for either kwarg is the
/// pre-AW-04 sentinel (no scoring-provenance binding).
///
/// M-05: `issuer_config_version` is the `IssuerConfig.config_version`
/// active when the cluster signed. Folding it into the digest means a
/// post-issuance config rotation (which MUST strictly increment
/// `config_version`) cannot retroactively change which threshold-signature
/// set verifies against a historical cert — the signed digest no longer
/// matches if a verifier substitutes the current version. Legacy callers
/// pre-M-05 supplied `0`, which is the sentinel for "issued before the
/// immutability tag existed"; the cluster signed against 0 in those
/// cases so verification remains deterministic.
///
/// Day 38 (Cert v2): the four trailing fields extend the cert payload
/// into a FULL DIAGNOSTIC CERTIFICATE. `failure_mode_bitmask` is the
/// u64 cluster-majority per-bit failure-mode bitmask the cluster reached
/// consensus on (see oracle/cluster/aggregation.py `_majority_label_bits`),
/// whose low 32 bits are a u64 widening of `flags` (the legacy invariant
/// `failure_mode_bitmask & 0xFFFF_FFFF == flags as u64` is enforced at
/// the ix layer so every v1..v8 consumer continues to read consistent
/// data). `remediation_codes` is a u32 bit-set of remediation actions
/// the cluster recommends. `diagnosis_payload_hash` is the SHA-256 over
/// the canonical-JSON cluster diagnosis payload published off-chain.
/// `taxonomy_version` names the failure-mode taxonomy schema the bitmask
/// + remediation bits are decoded against. Folding all four into the
/// digest means the threshold signatures cryptographically attest to
/// the full diagnostic certificate — a future cluster cannot publish a
/// score with the right signatures but a fabricated diagnosis. Legacy
/// callers pre-Day-38 supplied `0`, `0`, `[0; 32]`, `0` and the digest
/// extends deterministically — the sentinel means "no diagnostic
/// payload was published with this cert".
/// Day 38 (Cert v2): `failure_mode_bitmask` is the u64 cluster-majority
/// per-bit failure-mode bitmask. `remediation_codes` is the u32 cluster-
/// recommended remediation bit-set. `diagnosis_payload_hash` is the
/// SHA-256 over the canonical-JSON cluster diagnosis payload.
/// `taxonomy_version` names the failure-mode taxonomy schema the bitmask
/// is decoded against. All four are folded into the digest so the
/// threshold signatures cryptographically attest to the full diagnostic
/// certificate — not just the score + alert tier. Legacy v1..v8 callers
/// pass `0`, `0`, `[0; 32]`, `0` and the digest extends deterministically.
pub fn cert_payload_digest(
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
    // The byte layout is FIXED and PUBLIC — every signer and verifier must
    // produce these exact bytes. No floats, no Vec, no length-varying
    // field, no separator ambiguity.
    let immediate_red_byte: u8 = if immediate_red { 1 } else { 0 };
    let h = hashv(&[
        agent_wallet.as_ref(),                    // 32 bytes
        &epoch.to_be_bytes(),                     //  8 bytes
        &score.to_be_bytes(),                     //  2 bytes
        &[alert_tier],                            //  1 byte
        &flags.to_be_bytes(),                     //  4 bytes
        baseline_hash,                            // 32 bytes
        &[immediate_red_byte],                    //  1 byte
        input_commitment,                         // 32 bytes ← AW-01
        &slot_anchor_slot.to_be_bytes(),          //  8 bytes ← AW-01-EXT
        slot_anchor_hash,                         // 32 bytes ← AW-01-EXT
        &baseline_commit_nonce.to_be_bytes(),     //  8 bytes ← AW-03
        scoring_code_hash,                        // 32 bytes ← AW-04
        score_components_hash,                    // 32 bytes ← AW-04
        &issuer_config_version.to_be_bytes(),     //  4 bytes ← M-05
        &failure_mode_bitmask.to_be_bytes(),      //  8 bytes ← Day 38
        &remediation_codes.to_be_bytes(),         //  4 bytes ← Day 38
        diagnosis_payload_hash,                   // 32 bytes ← Day 38
        &[taxonomy_version],                      //  1 byte  ← Day 38
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

    // H-01 defence in depth: the config's stored threshold MUST be a
    // strict-majority over the live cluster size. The init + rotate
    // paths enforce this at write time; this runtime check refuses to
    // verify against a sub-majority threshold even if a future bug
    // somehow lets one land on the config. The cluster-direct cert
    // write fails fast instead of silently issuing a cert backed by an
    // un-safe quorum.
    require!(
        IssuerConfig::is_strict_majority_threshold(
            config.threshold,
            config.cluster_keys.len(),
        ),
        CertificateError::InvalidThreshold,
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

    // H-5: FAULT-DOMAIN DIVERSITY. The distinct-pubkey count above still lets
    // a single compromised host holding K cluster keys reach the threshold by
    // itself. Re-tally over distinct fault DOMAINS (host/region) and require
    // the quorum to span at least `threshold` of them, so one compromised
    // domain contributes at most one. (For a legacy config with no domain map
    // this degrades to the distinct-pubkey count — see distinct_domain_count.)
    let distinct_domains = config.distinct_domain_count(&signers);
    require!(
        distinct_domains >= config.threshold as usize,
        CertificateError::InsufficientSignerDiversity,
    );

    msg!(
        "threshold signatures verified: {} key(s) across {} domain(s) (threshold {})",
        count, distinct_domains, config.threshold,
    );
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_keys(cluster_keys: Vec<Pubkey>, threshold: u8) -> IssuerConfig {
        // H-5: unique domain per key, so the diversity gate behaves exactly
        // like the legacy distinct-pubkey count in these tally tests.
        let cluster_key_domains: Vec<u16> = (0..cluster_keys.len() as u16).collect();
        IssuerConfig {
            authority: Pubkey::new_unique(),
            issuer_node: Pubkey::new_unique(),
            cluster_keys,
            threshold,
            bump: 255,
            cluster_key_domains,
            // VULN-16: signature-verification tests don't exercise the
            // CPI path; a zero allow-list keeps the helper purely about
            // signatures.
            health_oracle_program_id: Pubkey::default(),
            // AW-01-EXT.6: cert-signing tests don't exercise the challenge
            // path either; an empty attester cluster + zero threshold
            // leaves the challenge ix disabled (irrelevant to signing).
            challenge_attester_keys: Vec::new(),
            challenge_threshold: 0,
            // M-05: irrelevant to tally tests — the tally walks the
            // precompile instructions, not the config snapshot. Use the
            // genesis value 1 so the helper matches a fresh deployment.
            config_version: 1,
            // H-3: no authority transfer pending.
            pending_authority: Pubkey::default(),
            authority_transfer_eta: 0,
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

    // =========================================================================
    // VULN-01 Post-Launch — semi-formal verification via property testing.
    //
    // The procedural tests above pin specific attack patterns. The proptest
    // block below pins the GENERAL SPEC: for any cluster, any set of
    // precompile instructions, and any expected digest,
    //
    //     tally_count = |{ k ∈ cluster_keys : ∃ rec, rec.signer = k
    //                                          ∧ rec.message = expected }|
    //
    // i.e. the count is the number of DISTINCT cluster keys that produced at
    // least one matching-digest record. Every invariant the audit cares about
    // — replay defence, dedupe, non-cluster-key filtering, permutation
    // invariance, cluster-size upper bound — is a corollary of that spec.
    //
    // proptest's shrinker minimises any counterexample to the smallest
    // failing input automatically, so a regression is exhibited as a tiny
    // failing case rather than a 30-element opaque vector.
    // =========================================================================

    use proptest::prelude::*;
    use std::collections::HashSet;

    /// The reference implementation — the formal spec the verifier must
    /// match. Pure: no precompile parsing, no AccountInfo, just set theory.
    fn reference_count(
        records: &[(Pubkey, [u8; 32])],
        expected: &[u8; 32],
        cluster_keys: &[Pubkey],
    ) -> usize {
        let mut hit: HashSet<Pubkey> = HashSet::new();
        for (signer, msg) in records {
            if msg == expected && cluster_keys.contains(signer) {
                hit.insert(*signer);
            }
        }
        hit.len()
    }

    /// Drive the real `maybe_tally_ed25519_ix` path through a list of
    /// (signer, message) records and return the resulting distinct-signer
    /// count.
    fn tally_via_impl(
        records: &[(Pubkey, [u8; 32])],
        expected: &[u8; 32],
        cluster_keys: Vec<Pubkey>,
    ) -> usize {
        let config = config_with_keys(cluster_keys, 1);
        let mut signers: Vec<Pubkey> = Vec::new();
        for (signer, msg) in records {
            let ix = ed25519_ix(*signer, *msg);
            maybe_tally_ed25519_ix(&ix, expected, &config, &mut signers).unwrap();
        }
        signers.len()
    }

    /// Generate `cluster_size` cluster keys plus `rogue_size` foreign keys
    /// and resolve each ix-seed (`(u8_index, message)`) to a real pubkey by
    /// indexing into the combined key list mod its length.
    fn build_setup(
        cluster_size: usize,
        rogue_size: usize,
        ix_seeds: Vec<(u8, [u8; 32])>,
    ) -> (Vec<Pubkey>, Vec<(Pubkey, [u8; 32])>) {
        let cluster_keys: Vec<Pubkey> =
            (0..cluster_size).map(|_| Pubkey::new_unique()).collect();
        let rogue_keys: Vec<Pubkey> =
            (0..rogue_size).map(|_| Pubkey::new_unique()).collect();
        let all_keys: Vec<Pubkey> =
            cluster_keys.iter().chain(rogue_keys.iter()).copied().collect();
        let records: Vec<(Pubkey, [u8; 32])> = ix_seeds
            .into_iter()
            .map(|(idx, msg)| (all_keys[(idx as usize) % all_keys.len()], msg))
            .collect();
        (cluster_keys, records)
    }

    proptest! {
        /// SPEC: the verifier's tally equals the reference count
        /// (distinct cluster-key signers over the expected digest), for
        /// any random multiset of precompile records.
        #[test]
        fn tally_matches_reference_spec(
            cluster_size in 1usize..=5,        // MAX_CLUSTER_KEYS
            rogue_size in 0usize..=4,
            ix_seeds in proptest::collection::vec(
                (any::<u8>(), any::<[u8; 32]>()),
                0..30,
            ),
            expected_digest in any::<[u8; 32]>(),
        ) {
            let (cluster_keys, records) = build_setup(cluster_size, rogue_size, ix_seeds);
            let via_impl = tally_via_impl(&records, &expected_digest, cluster_keys.clone());
            let via_ref  = reference_count(&records, &expected_digest, &cluster_keys);
            prop_assert_eq!(via_impl, via_ref);
        }

        /// INVARIANT: the count is invariant under permutation of the
        /// instruction list — the verifier is order-insensitive.
        #[test]
        fn tally_is_permutation_invariant(
            cluster_size in 1usize..=5,
            rogue_size in 0usize..=4,
            ix_seeds in proptest::collection::vec(
                (any::<u8>(), any::<[u8; 32]>()),
                0..20,
            ),
            expected_digest in any::<[u8; 32]>(),
            shuffle_seed in any::<u64>(),
        ) {
            let (cluster_keys, records) = build_setup(cluster_size, rogue_size, ix_seeds);
            let order_a = tally_via_impl(&records, &expected_digest, cluster_keys.clone());

            // Deterministic Fisher-Yates driven by the shrunk seed.
            let mut shuffled = records.clone();
            let mut s = shuffle_seed;
            for i in (1..shuffled.len()).rev() {
                s = s.wrapping_mul(6364136223846793005)
                     .wrapping_add(1442695040888963407);
                let j = (s as usize) % (i + 1);
                shuffled.swap(i, j);
            }
            let order_b = tally_via_impl(&shuffled, &expected_digest, cluster_keys);
            prop_assert_eq!(order_a, order_b);
        }

        /// INVARIANT (dedupe): duplicating the entire instruction list
        /// never changes the count — every cluster key contributes at
        /// most once.
        #[test]
        fn tally_is_idempotent_under_duplicates(
            cluster_size in 1usize..=5,
            rogue_size in 0usize..=4,
            ix_seeds in proptest::collection::vec(
                (any::<u8>(), any::<[u8; 32]>()),
                0..15,
            ),
            expected_digest in any::<[u8; 32]>(),
        ) {
            let (cluster_keys, records) = build_setup(cluster_size, rogue_size, ix_seeds);
            let once = tally_via_impl(&records, &expected_digest, cluster_keys.clone());
            let mut doubled = records.clone();
            doubled.extend(records.iter().copied());
            let twice = tally_via_impl(&doubled, &expected_digest, cluster_keys);
            prop_assert_eq!(once, twice);
        }

        /// VULN-01 SPEC: if NO record carries the expected digest, the
        /// count is zero — replayed signatures over any other digest
        /// contribute nothing, even when the signer is a cluster key.
        #[test]
        fn digest_mismatch_yields_zero(
            cluster_size in 1usize..=5,
            ix_seeds in proptest::collection::vec(
                (any::<u8>(), any::<[u8; 32]>()),
                0..20,
            ),
            expected_digest in any::<[u8; 32]>(),
            wrong_digest in any::<[u8; 32]>(),
        ) {
            // Random [u8;32] collision is astronomically rare but the
            // assume keeps the property well-defined.
            prop_assume!(expected_digest != wrong_digest);
            let seeds: Vec<(u8, [u8; 32])> = ix_seeds
                .into_iter()
                .map(|(idx, _)| (idx, wrong_digest))
                .collect();
            let (cluster_keys, records) = build_setup(cluster_size, 0, seeds);
            let count = tally_via_impl(&records, &expected_digest, cluster_keys);
            prop_assert_eq!(count, 0);
        }

        /// INVARIANT: the count is bounded above by cluster_keys.len()
        /// regardless of how many precompile instructions are submitted.
        #[test]
        fn tally_bounded_by_cluster_size(
            cluster_size in 1usize..=5,
            rogue_size in 0usize..=4,
            ix_seeds in proptest::collection::vec(
                (any::<u8>(), any::<[u8; 32]>()),
                0..40,
            ),
            expected_digest in any::<[u8; 32]>(),
        ) {
            let (cluster_keys, records) = build_setup(cluster_size, rogue_size, ix_seeds);
            let count = tally_via_impl(&records, &expected_digest, cluster_keys.clone());
            prop_assert!(count <= cluster_keys.len());
        }
    }
}
