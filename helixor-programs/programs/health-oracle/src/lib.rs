// =============================================================================
// programs/health-oracle/src/lib.rs
//
// health-oracle — entry point. Only Day-3 instructions are wired here; the
// Day 1-12 instructions (register_agent, update_score, get_health, ...) are
// already in the deployed MVP and are NOT redeclared in this delta package.
//
// To merge into the existing repo: add the two new instructions to the
// program's #[program] block, plus the new state file + errors + events.
// =============================================================================

// Anchor 0.30 emits internal cfgs such as `anchor-debug` from its derive
// macros. They are toolchain noise, not Helixor logic warnings. Keep the
// audit gate strict for our code while allowing those upstream macro cfgs.
#![allow(unexpected_cfgs, ambiguous_glob_reexports, clippy::diverging_sub_expression)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod events;
pub mod instructions;
pub mod slot_gate;
pub mod state;

use instructions::*;

// Replace with the actual deployed program ID when merging into the real repo.
declare_id!("EKK2Aj4C9GW8yt4rE2DmYN9A69LFmazGZgfWsFGwuaRN");

#[program]
pub mod health_oracle {
    use super::*;

    /// Day-3 NEW: commit a baseline-hash to an agent's registration.
    /// See commit_baseline::handler for the full authority + replay logic.
    pub fn commit_baseline(
        ctx:  Context<CommitBaseline>,
        args: CommitBaselineArgs,
    ) -> Result<()> {
        instructions::commit_baseline::handler(ctx, args)
    }

    /// Day-3 NEW: one-time per-agent realloc from v1 (MVP) to v2 layout.
    /// Owner-only; pays the additional rent for the larger account.
    pub fn migrate_registration(ctx: Context<MigrateRegistration>) -> Result<()> {
        instructions::migrate_registration::handler(ctx)
    }

    // ── Day 19: epoch management + CPI score submission ─────────────────────

    /// Day-19 NEW: one-time creation of the EpochState singleton (epoch 1).
    /// Day-19 NEW: one-time creation of the EpochState singleton (epoch 1).
    pub fn initialize_epoch(ctx: Context<InitializeEpoch>) -> Result<()> {
        instructions::initialize_epoch::handler(ctx)
    }

    /// Day-23 NEW: create the OracleConfig singleton for the oracle
    /// cluster — the 3-5 node pubkeys and the confidence floor. A 1-node
    /// cluster is the explicit backward-compatible single-node deployment.
    pub fn initialize_oracle_config(
        ctx:            Context<InitializeOracleConfig>,
        oracle_keys:    Vec<Pubkey>,
        min_confidence: u16,
    ) -> Result<()> {
        instructions::initialize_oracle_config::handler(ctx, oracle_keys, min_confidence)
    }

    /// Day-19 NEW: tick the epoch counter at the end of a 24h cycle.
    /// Guarded — the epoch duration must have elapsed.
    ///
    /// AW-02 FIX (supersedes VULN-02 single-key): the Tier-1 normal path
    /// now requires M-of-N cluster Ed25519 attestations over the canonical
    /// advance digest (sha256("helixor-epoch-advance" || current_epoch ||
    /// target_epoch || last_advanced_at)). Single-key advance via
    /// `advance_authority` is GONE — the field is retained as a layout-
    /// compatible hint only. Tier 2 (liveness fallback at 2× duration)
    /// remains: any cluster member may advance solo. See advance_epoch.rs
    /// for the full design and threat model.
    pub fn advance_epoch(ctx: Context<AdvanceEpoch>) -> Result<()> {
        instructions::advance_epoch::handler(ctx)
    }

    /// Rotate the advance_authority key to a new pubkey.
    ///
    /// AW-02 STATUS — DEPRECATED-BUT-RETAINED. `advance_authority` is no
    /// longer a sole-signer authority on the Tier-1 advance path; it is a
    /// non-authoritative hint kept for layout compatibility and ops
    /// forensics. This instruction still updates the hint; admin-gated
    /// (oracle_config.authority / Squads multisig in production). See
    /// rotate_advance_authority.rs.
    pub fn rotate_advance_authority(
        ctx:           Context<RotateAdvanceAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::rotate_advance_authority::handler(ctx, new_authority)
    }

    /// Day-19 NEW: the oracle submits an agent's epoch score. Writes the
    /// on-chain HealthCertificate by CPI into the certificate-issuer
    /// program. Atomic — if the certificate write reverts, so does this.
    ///
    /// AW-01: `input_commitment` is the 32-byte cluster-majority input
    /// commitment; passed through to certificate-issuer verbatim.
    ///
    /// AW-01-EXT: `slot_anchor_slot` + `slot_anchor_hash` is the Solana
    /// `(slot, block_hash)` the cluster pinned at scoring time. Forwarded
    /// to the certificate-issuer CPI which verifies it against the
    /// SlotHashes sysvar — Solana itself becomes a third source of truth
    /// beyond the cluster's RPC fleet.
    pub fn submit_score(
        ctx:                      Context<SubmitScore>,
        epoch:                    u64,
        score:                    u16,
        alert_tier:               u8,
        flags:                    u32,
        immediate_red:            bool,
        input_commitment:         [u8; 32],
        slot_anchor_slot:         u64,
        slot_anchor_hash:         [u8; 32],
        // AW-04: scoring-kernel bundle hash + raw canonical components
        // payload. Forwarded to the certificate-issuer CPI which hashes
        // the payload on chain and folds both into the cert digest.
        scoring_code_hash:        [u8; 32],
        score_components_payload: Vec<u8>,
    ) -> Result<()> {
        instructions::submit_score::handler(
            ctx, epoch, score, alert_tier, flags, immediate_red,
            input_commitment, slot_anchor_slot, slot_anchor_hash,
            scoring_code_hash, score_components_payload,
        )
    }

    /// Day-19 NEW: read an agent's current-epoch HealthCertificate. The V2
    /// replacement for the MVP's single-score get_health — same intent,
    /// new on-chain source (the epoch-keyed certificate).
    pub fn get_health(ctx: Context<GetHealth>, agent_wallet: Pubkey) -> Result<()> {
        instructions::get_health::handler(ctx, agent_wallet)
    }

    // ── VULN-13: time-locked, N-of-M-attested oracle key rotation ───────────
    //
    // The audit flagged single-admin oracle-key replacement as CRITICAL:
    // any admin-key compromise would let the attacker swap in 5
    // attacker-controlled cluster keys and issue perfect GREEN certs for
    // any agent. The four instructions below implement the audit-mandated
    // mitigations: rotation must go through a time-locked governance
    // proposal that requires N-of-M EXISTING cluster nodes to attest.
    // Admin alone cannot rewrite cluster membership.

    /// VULN-13: propose a new oracle cluster. Singleton PDA; admin OR any
    /// current cluster member may propose. Sets `enact_after = now +
    /// timelock_seconds` with a 48h floor.
    pub fn propose_oracle_key_rotation(
        ctx:                Context<ProposeOracleKeyRotation>,
        new_keys:           Vec<Pubkey>,
        new_min_confidence: u16,
        timelock_seconds:   i64,
    ) -> Result<()> {
        instructions::propose_oracle_key_rotation::handler(
            ctx, new_keys, new_min_confidence, timelock_seconds,
        )
    }

    /// VULN-13: a current cluster member attests to the open proposal.
    /// Each cluster key counts once; proposed-but-not-yet-current keys
    /// cannot attest (the gate is the LIVE cluster).
    pub fn attest_oracle_key_rotation(
        ctx: Context<AttestOracleKeyRotation>,
    ) -> Result<()> {
        instructions::attest_oracle_key_rotation::handler(ctx)
    }

    /// VULN-13: enact a fully-vetted proposal. Anyone may call once
    /// `now >= enact_after` AND `attestations >= consensus_threshold(
    /// current_cluster)`. Closes the PDA and refunds rent to the proposer.
    pub fn enact_oracle_key_rotation(
        ctx: Context<EnactOracleKeyRotation>,
    ) -> Result<()> {
        instructions::enact_oracle_key_rotation::handler(ctx)
    }

    /// VULN-13: cancel an open proposal. Admin OR any current cluster
    /// member may cancel — a single honest cluster member is enough to
    /// veto a hostile proposal during the 48h window.
    pub fn cancel_oracle_key_rotation(
        ctx: Context<CancelOracleKeyRotation>,
    ) -> Result<()> {
        instructions::cancel_oracle_key_rotation::handler(ctx)
    }
}
