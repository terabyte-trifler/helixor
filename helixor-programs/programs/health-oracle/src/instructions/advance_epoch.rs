// =============================================================================
// programs/health-oracle/src/instructions/advance_epoch.rs
//
// advance_epoch — tick the epoch counter at the end of a 24h cycle.
//
// C-01 — 2-PHASE COMMIT
// ---------------------
// The pre-C-01 handler verified Tier-1/Tier-2 authority AND mutated
// `current_epoch` in a single transaction — i.e. the only observability
// off-chain monitors got was AFTER the tick committed. C-01 splits this
// into two ix's, exported as the `propose_advance_epoch` and
// `finalize_advance_epoch` entry-points on `lib.rs`:
//
//   * `propose_handler`: runs the SAME Tier-1/Tier-2 verification as
//     before, but writes `EpochState.pending_target_epoch /
//     pending_proposed_at / pending_attester_count / pending_by_fallback`
//     INSTEAD of mutating `current_epoch`. Emits `EpochAdvanceProposed`.
//     Refuses if a fresh pending proposal already exists (overwriting
//     only allowed after `PROPOSE_OVERWRITE_DELAY_SECONDS` of staleness).
//
//   * `finalize_handler`: requires `now >= pending_proposed_at +
//     FINALIZE_DELAY_SECONDS`, then commits the staged target into
//     `current_epoch`, clears the pending fields, and emits the
//     canonical `EpochAdvanced` plus the tier-specific
//     `EpochAdvancedByThreshold` / `EpochAdvancedByFallback` event using
//     the COUNTS / TIER captured at propose time. From the off-chain
//     event-stream perspective, the (Proposed, Finalized) pair are the
//     two halves of one canonical tick.
//
// Off-chain monitors observe the proposal AT LEAST `FINALIZE_DELAY_SECONDS`
// before the commit lands — enough to react if a hostile cluster member
// assembled a quorum with the wrong digest or in the wrong direction.
//
// The oracle calls this once per cycle. It increments current_epoch, so the
// next round of certificates is issued under a fresh epoch number — a fresh
// set of ["cert", agent, epoch] PDAs. The previous epoch's certificates are
// untouched: epoch history accumulates on chain.
//
// AUTHORITY (AW-02 FIX — M-of-N THRESHOLD-ATTESTED TIER 1)
// --------------------------------------------------------
// The MVP path was a single `advance_authority` key. VULN-02 added a
// liveness-fallback tier (any cluster key at 2× duration) so a lost or
// compromised key cannot permanently halt the protocol. But the Tier-1
// normal path remained SOLE-SIGNER: one key picked the exact instant of
// every epoch tick. The audit (AW-02) flagged this as a coverage gap —
// every other consensus-critical op in the protocol (score submission,
// cert issuance, oracle key rotation) goes through the cluster's M-of-N
// threshold mechanism. Epoch advancement did not.
//
// AW-02 closes the gap: Tier 1 is now M-of-N attested. Tier 2 (the
// liveness fallback) is unchanged.
//
//   Tier 1 (normal, ≥ 1× duration elapsed):
//       The transaction must carry ≥ consensus_threshold(cluster) Ed25519
//       PRECOMPILE instructions whose signed message equals the canonical
//       advance digest (see `advance_payload_digest` below) and whose
//       signer is a current OracleConfig cluster key. The submitting
//       signer is just the fee payer / tx submitter — they have no
//       sole-signer authority.
//
//   Tier 2 (liveness fallback, ≥ 2× duration elapsed):
//       UNCHANGED. A SINGLE cluster key may advance solo. This is the
//       last-resort path for catastrophic cluster failure (e.g. 2 of 3
//       nodes down for ≥ 2 epochs). Emits EpochAdvancedByFallback so an
//       operator alerts on every fallback.
//
// THE LEGACY `advance_authority` FIELD
// ------------------------------------
// `EpochState.advance_authority` is retained for ACCOUNT-LAYOUT compat
// (the account is in the existing deployment; changing its size requires
// a realloc-migration). It is no longer a sole-signer privilege on the
// Tier-1 path. `rotate_advance_authority` remains available so an
// operator can keep the field current for auditability, but a stale
// `advance_authority` no longer blocks epoch advancement.
//
// DOMAIN SEPARATION
// -----------------
// The advance digest uses the distinct tag `b"helixor-epoch-advance"`,
// so a cluster signature over a cert payload or a challenge payload
// CANNOT be replayed as an advance attestation (and vice versa). The
// digest also folds in `current_epoch`, `target_epoch`, and the
// `last_advanced_at` snapshot so an attestation for advance N→N+1
// cannot be reused for any other advance, even if all timestamps line
// up by chance.
// =============================================================================

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_instruction_at_checked, ID as INSTRUCTIONS_ID};
use solana_program::{hash::hashv, instruction::Instruction};
use solana_sdk_ids::ed25519_program;

use crate::errors::HelixorError;
use crate::events::{
    EpochAdvanceProposed, EpochAdvanced,
    EpochAdvancedByFallback, EpochAdvancedByThreshold,
};
use crate::state::{EpochState, OracleConfig};

// -----------------------------------------------------------------------------
// Domain-separation tag for the advance-epoch digest.
//
// Distinct from `helixor-cert-v1` (cert signing) and
// `helixor-aw01-ext-challenge` (challenge attestations) so an honest
// cluster signature can NEVER be lifted from one purpose to another.
// -----------------------------------------------------------------------------
pub const ADVANCE_EPOCH_DOMAIN_TAG: &[u8] = b"helixor-epoch-advance";

// -----------------------------------------------------------------------------
// Canonical advance-payload digest
// -----------------------------------------------------------------------------

/// Compute the 32-byte digest the cluster signs over for an epoch advance.
///
/// Layout (fixed, public):
///   "helixor-epoch-advance"   (21 bytes) — domain separator
///   current_epoch              (8 bytes, LE)
///   target_epoch               (8 bytes, LE) — always current_epoch + 1
///   last_advanced_at           (8 bytes, LE) — the epoch state's snapshot
///
/// `last_advanced_at` is folded in so an attestation against advance N→N+1
/// at time T1 cannot be re-used for a different advance N→N+1 at time T2
/// (the value at the moment of the previous tick uniquely identifies the
/// transition).
pub fn advance_payload_digest(
    current_epoch:    u64,
    target_epoch:     u64,
    last_advanced_at: i64,
) -> [u8; 32] {
    let h = hashv(&[
        ADVANCE_EPOCH_DOMAIN_TAG,
        &current_epoch.to_le_bytes(),
        &target_epoch.to_le_bytes(),
        &last_advanced_at.to_le_bytes(),
    ]);
    h.to_bytes()
}

// -----------------------------------------------------------------------------
// Ed25519 precompile layout — local mirror of the same constants used by
// certificate-issuer's signing.rs / challenge_certificate.rs. Kept local so
// the health-oracle program does not take an inter-program dependency on the
// cert-issuer's internal helpers.
// -----------------------------------------------------------------------------

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
        ix.data.len() >= ED25519_HEADER_LEN
            .saturating_add(ED25519_PUBKEY_LEN)
            .saturating_add(ED25519_SIGNATURE_LEN)
            .saturating_add(ED25519_MESSAGE_LEN),
        HelixorError::MalformedAdvanceEd25519Instruction,
    );
    require!(
        ix.data[ED25519_NUM_SIGNATURES_OFFSET] == 1,
        HelixorError::MalformedAdvanceEd25519Instruction,
    );

    let sig_offset = u16::from_le_bytes([ix.data[2],  ix.data[3]])  as usize;
    let sig_ix_idx = u16::from_le_bytes([ix.data[4],  ix.data[5]]);
    let pk_offset  = u16::from_le_bytes([ix.data[6],  ix.data[7]])  as usize;
    let pk_ix_idx  = u16::from_le_bytes([ix.data[8],  ix.data[9]]);
    let msg_offset = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
    let msg_size   = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;
    let msg_ix_idx = u16::from_le_bytes([ix.data[14], ix.data[15]]);

    // The precompile supports "look up signature data in another instruction
    // in the same tx". We refuse that — the signed bytes must be IN the
    // precompile ix's own data, not pulled from elsewhere in the tx, so
    // an attacker cannot craft a precompile that pretends to verify a
    // message that lives in some other ix's data.
    const THIS_IX: u16 = u16::MAX;
    require!(
        sig_ix_idx == THIS_IX && pk_ix_idx == THIS_IX && msg_ix_idx == THIS_IX,
        HelixorError::AdvanceCrossInstructionReference,
    );
    require!(
        msg_size == ED25519_MESSAGE_LEN,
        HelixorError::WrongAdvanceDigestLength,
    );
    require!(
        pk_offset.saturating_add(ED25519_PUBKEY_LEN) <= ix.data.len()
            && sig_offset.saturating_add(ED25519_SIGNATURE_LEN) <= ix.data.len()
            && msg_offset.saturating_add(msg_size) <= ix.data.len(),
        HelixorError::MalformedAdvanceEd25519Instruction,
    );

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&ix.data[pk_offset .. pk_offset + ED25519_PUBKEY_LEN]);
    let mut message = [0u8; 32];
    message.copy_from_slice(&ix.data[msg_offset .. msg_offset + msg_size]);
    Ok(PrecompileRecord { pubkey, message })
}

/// Inspect a single instruction and, if it is an Ed25519 precompile carrying
/// a valid signature by a CURRENT cluster key over `expected_digest`, push
/// that signer into `signers` (once — duplicates are deduped).
///
/// Silent-ignore semantics on non-matching ixs: a tx may contain unrelated
/// precompiles (e.g. a separate cert-signing bundle) and the verifier must
/// not refuse them — it simply does not count them.
fn maybe_tally_cluster_ix(
    ix:              &Instruction,
    expected_digest: &[u8; 32],
    config:          &OracleConfig,
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
    if !config.is_cluster_member(&signer) {
        return Ok(());
    }
    if signers.contains(&signer) {
        return Ok(());
    }
    signers.push(signer);
    Ok(())
}

/// Verify the transaction carries at least `config.consensus_threshold()`
/// Ed25519 precompile signatures whose:
///   - signed message equals `expected_digest`,
///   - signer pubkey is a CURRENT member of `config.oracle_keys`,
///   - and each distinct cluster member counts at most once.
///
/// Returns the number of distinct cluster signers counted, or
/// `InsufficientAdvanceAttestations` if below threshold.
pub fn verify_cluster_threshold(
    expected_digest:     &[u8; 32],
    config:              &OracleConfig,
    instructions_sysvar: &AccountInfo,
) -> Result<u8> {
    require!(
        instructions_sysvar.key == &INSTRUCTIONS_ID,
        HelixorError::WrongAdvanceInstructionsSysvar,
    );

    let mut signers: Vec<Pubkey> =
        Vec::with_capacity(OracleConfig::MAX_ORACLE_KEYS);
    let mut ix_index: usize = 0;
    while let Ok(ix) = load_instruction_at_checked(ix_index, instructions_sysvar) {
        ix_index += 1;
        if ix.program_id != ed25519_program::id() {
            continue;
        }
        maybe_tally_cluster_ix(&ix, expected_digest, config, &mut signers)?;
    }

    let count = signers.len() as u8;
    let required = config.consensus_threshold() as u8;
    require!(
        count >= required,
        HelixorError::InsufficientAdvanceAttestations,
    );
    Ok(count)
}

// =============================================================================
// Accounts
// =============================================================================

#[derive(Accounts)]
pub struct AdvanceEpoch<'info> {
    /// The epoch counter.
    #[account(
        mut,
        seeds = [EpochState::SEED],
        bump  = epoch_state.bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// OracleConfig — supplies the cluster key set for both the
    /// Tier-1 M-of-N threshold check AND the Tier-2 single-member
    /// liveness-fallback check.
    #[account(
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The fee payer / tx submitter. Has NO sole-signer privilege on
    /// the Tier-1 path — authority comes from the bundled M-of-N
    /// Ed25519 attestations. On the Tier-2 fallback path their key
    /// must be a current cluster member.
    pub advancer: Signer<'info>,

    /// CHECK: The Instructions sysvar — read inside the handler to find
    /// the Ed25519 precompile instructions that carry the cluster
    /// attestations. The handler verifies this is the right sysvar.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

// =============================================================================
// C-01 — Phase 1: propose_advance_epoch
// =============================================================================
//
// Verifies the SAME Tier-1/Tier-2 authority that the pre-C-01 monolithic
// advance_epoch did, but instead of mutating `current_epoch`, it stages
// the target into the EpochState pending fields. A matching
// `finalize_advance_epoch` tx commits the tick after the observability
// window elapses.

pub fn propose_handler(ctx: Context<AdvanceEpoch>) -> Result<()> {
    let clock    = Clock::get()?;
    let now      = clock.unix_timestamp;
    let advancer = ctx.accounts.advancer.key();

    // Snapshot epoch_state fields BEFORE the mutable borrow we take to
    // write the staged target. The digest depends on the PRE-tick state.
    let current_epoch    = ctx.accounts.epoch_state.current_epoch;
    let last_advanced_at = ctx.accounts.epoch_state.last_advanced_at;
    let may_advance      = ctx.accounts.epoch_state.may_advance(now);
    let fallback_open    = ctx.accounts.epoch_state.liveness_fallback_elapsed(now);
    let overwrite_ok     =
        ctx.accounts.epoch_state.pending_overwrite_allowed(now);

    // ── Guard 1: epoch duration must have elapsed ────────────────────────────
    require!(may_advance, HelixorError::EpochNotElapsed);

    // ── Guard 2 (C-01): a fresh pending proposal blocks new proposals ───────
    // A pending proposal younger than PROPOSE_OVERWRITE_DELAY_SECONDS
    // is "in flight" — the legitimate next step is finalize, not
    // overwrite. After the staleness window elapses (1h) any proposer
    // may overwrite, so a crashed proposer cannot deadlock the next
    // tick.
    require!(
        overwrite_ok,
        HelixorError::PendingAdvanceAlreadyInFlight,
    );

    let target_epoch = current_epoch
        .checked_add(1)
        .ok_or(HelixorError::EpochCounterOverflow)?;

    // ── Guard 3: authority check (two-tier) ──────────────────────────────────
    //
    // Tier 1 (normal): try to verify M-of-N cluster attestations over the
    //   canonical digest. If that succeeds, advance with a threshold event.
    //
    // Tier 2 (fallback): if and only if the fallback window is open AND the
    //   submitter is a current cluster member, allow the single-signer
    //   liveness path. This preserves the post-VULN-02 invariant that the
    //   protocol cannot be permanently halted by missing/compromised keys.
    //
    // The ORDER matters: Tier 1 is tried first. A cluster operating
    //   normally never hits the fallback path. Tier 2 only fires when the
    //   cluster has been silent for ≥ 2× duration AND the M-of-N path
    //   could not be assembled — both conditions, not either.
    let digest = advance_payload_digest(current_epoch, target_epoch, last_advanced_at);
    let tier1 = verify_cluster_threshold(
        &digest,
        &ctx.accounts.oracle_config,
        &ctx.accounts.instructions_sysvar.to_account_info(),
    );

    let (by_fallback, attester_count) = match tier1 {
        Ok(count) => (false, count),
        Err(_)    => {
            // Tier 1 failed (no quorum). Try Tier 2.
            let is_cluster_member =
                ctx.accounts.oracle_config.is_cluster_member(&advancer);
            require!(
                fallback_open && is_cluster_member,
                HelixorError::NotAuthorisedAdvancer,
            );
            (true, 1u8)
        }
    };

    // ── Stage the pending advance ───────────────────────────────────────────
    // The pending fields are zero-initialised at `initialize_epoch` and
    // re-zeroed by `finalize_advance_epoch`. We clear before writing in
    // case we're overwriting a stale proposal (overwrite_ok above).
    let epoch_state = &mut ctx.accounts.epoch_state;
    epoch_state.clear_pending_advance();
    epoch_state.pending_target_epoch   = target_epoch;
    epoch_state.pending_proposed_at    = now;
    epoch_state.pending_attester_count = attester_count;
    epoch_state.pending_by_fallback    = u8::from(by_fallback);

    emit!(EpochAdvanceProposed {
        from_epoch:     current_epoch,
        target_epoch,
        proposed_at:    now,
        attester_count,
        by_fallback,
        proposer:       advancer,
    });
    msg!(
        "epoch advance PROPOSED: {} -> {} by {} (tier={}, attesters={})",
        current_epoch, target_epoch, advancer,
        if by_fallback { "fallback" } else { "threshold" },
        attester_count,
    );

    Ok(())
}

// =============================================================================
// C-01 — Phase 2: finalize_advance_epoch
// =============================================================================

#[derive(Accounts)]
pub struct FinalizeAdvanceEpoch<'info> {
    /// The epoch counter — same singleton mutated by the legacy
    /// advance_epoch handler. The mutation is identical; only the
    /// gating moved into the pending-state machine.
    #[account(
        mut,
        seeds = [EpochState::SEED],
        bump  = epoch_state.bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// OracleConfig — read to allow finalize to (re-)check cluster
    /// membership for the Tier-2 path AT FINALIZE TIME as well. (The
    /// propose handler already gated on cluster membership; this is
    /// a defence-in-depth replay against a propose-then-rotate-keys
    /// hostile sequence that would otherwise let an out-of-cluster
    /// finalizer rubber-stamp a fallback proposal.)
    #[account(
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The fee payer / tx submitter. C-01 keeps finalize permissionless
    /// in the M-of-N (Tier-1) case — any signer can finalize once the
    /// FINALIZE_DELAY_SECONDS observability window has elapsed — but
    /// gates Tier-2 (fallback) finalize on the submitter being a
    /// current cluster member (matching the Tier-2 propose gate).
    pub finalizer: Signer<'info>,
}

pub fn finalize_handler(ctx: Context<FinalizeAdvanceEpoch>) -> Result<()> {
    let clock     = Clock::get()?;
    let now       = clock.unix_timestamp;
    let finalizer = ctx.accounts.finalizer.key();

    // ── Guard 1: a pending proposal must exist ───────────────────────────────
    require!(
        ctx.accounts.epoch_state.has_pending_advance(),
        HelixorError::NoPendingAdvance,
    );

    // ── Guard 2: the finalize-delay window must have elapsed ─────────────────
    require!(
        ctx.accounts.epoch_state.pending_advance_ready(now),
        HelixorError::PendingAdvanceFinalizeDelayActive,
    );

    // Snapshot before the mutable borrow.
    let current_epoch    = ctx.accounts.epoch_state.current_epoch;
    let pending_target   = ctx.accounts.epoch_state.pending_target_epoch;
    let attester_count   = ctx.accounts.epoch_state.pending_attester_count;
    let by_fallback      = ctx.accounts.epoch_state.pending_by_fallback != 0;

    // ── Guard 3: the staged target must still be current_epoch + 1 ─────────
    // Defence-in-depth against a propose that somehow targeted the wrong
    // epoch (or against a future bug that advances current_epoch through
    // a path other than this handler). Without this check, a stale
    // pending could silently advance the chain by an unintended delta.
    let expected_target = current_epoch
        .checked_add(1)
        .ok_or(HelixorError::EpochCounterOverflow)?;
    require!(
        pending_target == expected_target,
        HelixorError::PendingAdvanceTargetDrift,
    );

    // ── Guard 4 (Tier-2 defence-in-depth): only a cluster member may ────────
    // finalize a fallback proposal. Tier-1 proposals are permissionless to
    // finalize — the M-of-N attestations were already verified at propose.
    if by_fallback {
        require!(
            ctx.accounts.oracle_config.is_cluster_member(&finalizer),
            HelixorError::NotAuthorisedAdvancer,
        );
    }

    // ── Commit ───────────────────────────────────────────────────────────────
    let epoch_state = &mut ctx.accounts.epoch_state;
    let from = epoch_state.current_epoch;
    epoch_state.current_epoch    = pending_target;
    epoch_state.last_advanced_at = now;
    epoch_state.clear_pending_advance();

    emit!(EpochAdvanced {
        from_epoch:  from,
        to_epoch:    epoch_state.current_epoch,
        advanced_at: now,
    });

    if by_fallback {
        emit!(EpochAdvancedByFallback {
            from_epoch:  from,
            to_epoch:    epoch_state.current_epoch,
            advanced_at: now,
            cluster_key: finalizer,
        });
        msg!(
            "epoch advance FINALIZED via liveness fallback: {} -> {} by cluster key {}",
            from, epoch_state.current_epoch, finalizer,
        );
    } else {
        emit!(EpochAdvancedByThreshold {
            from_epoch:     from,
            to_epoch:       epoch_state.current_epoch,
            advanced_at:    now,
            attester_count,
            submitter:      finalizer,
        });
        msg!(
            "epoch advance FINALIZED via M-of-N threshold: {} -> {} (attesters={})",
            from, epoch_state.current_epoch, attester_count,
        );
    }

    Ok(())
}

// =============================================================================
// Tests — runtime-free coverage of the digest + threshold logic
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_cluster(cluster_keys: Vec<Pubkey>) -> OracleConfig {
        OracleConfig {
            authority:      Pubkey::new_unique(),
            oracle_node:    cluster_keys.first().copied().unwrap_or_default(),
            oracle_keys:    cluster_keys,
            min_confidence: 0,
            bump:           255,
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
        let d = advance_payload_digest(1, 2, 0);
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(
            advance_payload_digest(7, 8, 1_700_000_000),
            advance_payload_digest(7, 8, 1_700_000_000),
        );
    }

    #[test]
    fn digest_binds_to_current_epoch() {
        // Same target_epoch & last_advanced_at, different current_epoch =>
        // different digests. This prevents a cluster sig for advance N→N+1
        // being replayed for advance M→N+1.
        let a = advance_payload_digest(5, 6, 1_000);
        let b = advance_payload_digest(7, 6, 1_000);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_binds_to_target_epoch() {
        let a = advance_payload_digest(5, 6, 1_000);
        let b = advance_payload_digest(5, 7, 1_000);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_binds_to_last_advanced_at() {
        // The crucial cross-tick replay defence: two advances of N→N+1 at
        // different timestamps demand different sigs (last_advanced_at
        // differs at the moment of the previous tick).
        let a = advance_payload_digest(5, 6, 1_000);
        let b = advance_payload_digest(5, 6, 2_000);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_uses_distinct_domain_tag() {
        // Compare the prefix-tag bytes to confirm the domain separator is
        // present and distinct from the cert / challenge tags.
        assert_eq!(ADVANCE_EPOCH_DOMAIN_TAG, b"helixor-epoch-advance");
        assert_ne!(ADVANCE_EPOCH_DOMAIN_TAG, b"helixor-cert-v1");
        assert_ne!(ADVANCE_EPOCH_DOMAIN_TAG, b"helixor-aw01-ext-challenge");
    }

    #[test]
    fn digest_for_advance_and_challenge_diverge() {
        // Belt-and-braces: identical-looking inputs through the two
        // digesters must NOT collide. The domain tag is the only thing
        // protecting the protocol from a cert-sig replay-as-advance.
        let advance = advance_payload_digest(1, 2, 0);
        let collision_probe = hashv(&[
            b"helixor-cert-v1",
            &1u64.to_le_bytes(),
            &2u64.to_le_bytes(),
            &0i64.to_le_bytes(),
        ]).to_bytes();
        assert_ne!(advance, collision_probe);
    }

    // ── Cluster-filtering verifier ──────────────────────────────────────────

    #[test]
    fn correct_cluster_signatures_are_counted() {
        let cluster: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_cluster(cluster.clone());
        let digest = [1u8; 32];
        let mut signers = Vec::new();
        for key in cluster.iter().take(2) {
            let ix = ed25519_ix(*key, digest);
            maybe_tally_cluster_ix(&ix, &digest, &config, &mut signers).unwrap();
        }
        assert_eq!(signers.len(), 2);
    }

    #[test]
    fn duplicate_cluster_key_is_counted_once() {
        let cluster: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_cluster(cluster.clone());
        let digest = [2u8; 32];
        let mut signers = Vec::new();
        let ix = ed25519_ix(cluster[0], digest);
        maybe_tally_cluster_ix(&ix, &digest, &config, &mut signers).unwrap();
        maybe_tally_cluster_ix(&ix, &digest, &config, &mut signers).unwrap();
        assert_eq!(signers.len(), 1);
    }

    #[test]
    fn non_cluster_key_is_not_counted() {
        let cluster: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_cluster(cluster);
        let digest = [3u8; 32];
        let mut signers = Vec::new();
        // A random pubkey — not in the cluster.
        let ix = ed25519_ix(Pubkey::new_unique(), digest);
        maybe_tally_cluster_ix(&ix, &digest, &config, &mut signers).unwrap();
        assert!(signers.is_empty());
    }

    #[test]
    fn wrong_digest_signatures_are_filtered() {
        // A valid cluster signature over the WRONG digest must not count.
        // This is the primary defence against replay across ticks.
        let cluster: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let config = config_with_cluster(cluster.clone());
        let expected_digest   = [1u8; 32];
        let historical_digest = [2u8; 32];
        let mut signers = Vec::new();
        for key in cluster.iter().take(2) {
            let ix = ed25519_ix(*key, historical_digest);
            maybe_tally_cluster_ix(&ix, &expected_digest, &config, &mut signers).unwrap();
        }
        assert!(signers.is_empty());
    }

    // ── Threshold math ──────────────────────────────────────────────────────

    #[test]
    fn threshold_matches_consensus_majority() {
        // 1-node cluster: threshold 1
        // 3-node cluster: threshold 2
        // 5-node cluster: threshold 3
        for (size, expected) in [(1, 1), (3, 2), (5, 3)] {
            let cluster: Vec<Pubkey> = (0..size).map(|_| Pubkey::new_unique()).collect();
            let config = config_with_cluster(cluster);
            assert_eq!(config.consensus_threshold(), expected,
                "cluster size {} expected threshold {}", size, expected);
        }
    }

    // ── Constants ───────────────────────────────────────────────────────────

    #[test]
    fn domain_tag_is_stable() {
        // Pin the exact tag bytes — a change here is a breaking on-chain
        // protocol change and would invalidate every queued cluster sig.
        assert_eq!(ADVANCE_EPOCH_DOMAIN_TAG, b"helixor-epoch-advance");
        assert_eq!(ADVANCE_EPOCH_DOMAIN_TAG.len(), 21);
    }
}
