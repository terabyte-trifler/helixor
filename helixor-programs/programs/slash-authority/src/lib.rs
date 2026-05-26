// =============================================================================
// programs/slash-authority/src/lib.rs
//
// slash-authority — Helixor V2's third on-chain program.
//
// Doc 2 splits the protocol into three programs:
//   - health-oracle       (registration, baseline, scores, epochs)
//   - certificate-issuer  (the epoch-keyed trust certificates)
//   - slash-authority     (THIS — economically real collateral slashing)
//
// Day 20 scaffolds slash-authority:
//   - EscrowVault PDA  (["escrow", agent])  — holds REAL staked SOL.
//   - SlashRecord PDA  (["slash", agent, count]) — append-only history.
//   - SlashConfig      (["slash_config"])  — authority + treasury.
//   - initialize_config / open_vault / execute_slash instructions.
//
// THE DOC-2 CHANGE: the MVP locked a 0.01 SOL escrow but never touched it.
// V2 makes the stake economically real — execute_slash moves lamports out
// of the vault: a penalty to the treasury, or, for a confirmed compromise,
// a burn to the incinerator.
//
// Separate program => separate program ID. Replace the placeholder below
// with the deployed key when this is published to devnet.
// =============================================================================

// Anchor 0.30 emits internal cfgs such as `anchor-debug` from its derive
// macros. They are toolchain noise, not Helixor logic warnings. Keep the
// audit gate strict for our code while allowing those upstream macro cfgs.
#![allow(unexpected_cfgs, ambiguous_glob_reexports, clippy::diverging_sub_expression)]

use anchor_lang::prelude::*;

pub mod errors;
pub mod events;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("S1ash1xor1111111111111111111111111111111111");

#[program]
pub mod slash_authority {
    use super::*;

    /// One-time: create the SlashConfig singleton with VULN-04's
    /// separated-authority model: distinct executor / resolver / pauser
    /// keys, plus the settlement timelock (>= 72h).
    pub fn initialize_config(
        ctx:                         Context<InitializeConfig>,
        slash_executor:              Pubkey,
        appeal_resolver:             Pubkey,
        pause_authority:             Pubkey,
        treasury:                    Pubkey,
        settlement_timelock_seconds: i64,
    ) -> Result<()> {
        instructions::initialize_config::handler(
            ctx,
            slash_executor,
            appeal_resolver,
            pause_authority,
            treasury,
            settlement_timelock_seconds,
        )
    }

    /// SPOF-#2 DEPRECATED-AND-REFUSED. Pre-mitigation this was admin-gated
    /// single-tx rotation. It now ALWAYS returns
    /// `SingleAdminUpdateRemoved` (6088) — use the propose/attest/enact
    /// ceremony below. Retained for IDL compatibility only.
    pub fn update_authorities(
        ctx:                         Context<UpdateAuthorities>,
        slash_executor:              Pubkey,
        appeal_resolver:             Pubkey,
        pause_authority:             Pubkey,
        settlement_timelock_seconds: i64,
    ) -> Result<()> {
        instructions::update_authorities::handler(
            ctx,
            slash_executor,
            appeal_resolver,
            pause_authority,
            settlement_timelock_seconds,
        )
    }

    // ── SPOF-#2: time-locked, 2-of-3-attested authority rotation ───────────
    //
    // The audit flagged single-admin role-key replacement as HIGH risk
    // (collapses VULN-04 separation). Rotation now mirrors VULN-13's
    // oracle-key ceremony: 48h+ timelock, attestation from a strict
    // majority of the LIVE role keys (2 of 3), and any honest role key
    // can cancel during the window.

    /// SPOF-#2: propose a slash-authority rotation. Singleton PDA;
    /// admin OR any current role key may propose. Role-key proposers
    /// auto-attest; admin alone cannot enact.
    pub fn propose_authority_rotation(
        ctx:                                 Context<ProposeAuthorityRotation>,
        new_slash_executor:                  Pubkey,
        new_appeal_resolver:                 Pubkey,
        new_pause_authority:                 Pubkey,
        new_treasury:                        Pubkey,
        new_settlement_timelock_seconds:     i64,
        timelock_seconds:                    i64,
    ) -> Result<()> {
        instructions::propose_authority_rotation::handler(
            ctx,
            new_slash_executor,
            new_appeal_resolver,
            new_pause_authority,
            new_treasury,
            new_settlement_timelock_seconds,
            timelock_seconds,
        )
    }

    /// SPOF-#2: a current role key attests to the open proposal.
    /// Admin attestations do NOT count (separation by design).
    pub fn attest_authority_rotation(
        ctx: Context<AttestAuthorityRotation>,
    ) -> Result<()> {
        instructions::attest_authority_rotation::handler(ctx)
    }

    /// SPOF-#2: enact a fully-vetted proposal. Anyone may call once
    /// `now >= enact_after` AND attestations >= 2-of-3.
    pub fn enact_authority_rotation(
        ctx: Context<EnactAuthorityRotation>,
    ) -> Result<()> {
        instructions::enact_authority_rotation::handler(ctx)
    }

    /// SPOF-#2: cancel an open proposal. Admin OR any current role key
    /// may cancel — a single honest role key is enough to veto a
    /// hostile proposal during the 48h window.
    pub fn cancel_authority_rotation(
        ctx: Context<CancelAuthorityRotation>,
    ) -> Result<()> {
        instructions::cancel_authority_rotation::handler(ctx)
    }

    /// VULN-04: the pause kill switch — freeze execute_slash,
    /// resolve_appeal and settle_slash. Pause_authority gated; cannot
    /// move funds.
    pub fn pause_settlements(ctx: Context<PauseSettlements>) -> Result<()> {
        instructions::pause_settlements::pause_handler(ctx)
    }

    /// VULN-04: unpause the slash pipeline.
    pub fn unpause_settlements(ctx: Context<PauseSettlements>) -> Result<()> {
        instructions::pause_settlements::unpause_handler(ctx)
    }

    /// Open an agent's EscrowVault and fund it with real staked collateral.
    pub fn open_vault(
        ctx:            Context<OpenVault>,
        agent_wallet:   Pubkey,
        stake_lamports: u64,
    ) -> Result<()> {
        instructions::open_vault::handler(ctx, agent_wallet, stake_lamports)
    }

    /// Execute a tiered slash: ENCUMBER collateral in the EscrowVault and
    /// write a Pending SlashRecord. Authority-gated on the slash authority.
    /// Day 21: funds are held (encumbered), not moved — settle_slash moves
    /// them after the appeal window, appeal_slash can intercept.
    pub fn execute_slash(
        ctx:           Context<ExecuteSlash>,
        index:         u64,
        offense_tier:  u8,
        evidence_hash: [u8; 32],
    ) -> Result<()> {
        instructions::execute_slash::handler(ctx, index, offense_tier, evidence_hash)
    }

    // ── Day 21: dispute mechanisms ──────────────────────────────────────────

    /// Day-21 NEW: an agent owner appeals a Pending slash. Pending ->
    /// Appealed; the encumbered funds stay held. Requires a non-zero
    /// justification, an open appeal window, and the appeal cooldown.
    pub fn appeal_slash(
        ctx:           Context<AppealSlash>,
        justification: [u8; 32],
    ) -> Result<()> {
        instructions::appeal_slash::handler(ctx, justification)
    }

    /// Day-21 NEW: the slash authority resolves an Appealed slash.
    /// uphold=false overturns it (funds released back to free stake);
    /// uphold=true lets the slash stand (becomes settleable).
    pub fn resolve_appeal(ctx: Context<ResolveAppeal>, uphold: bool) -> Result<()> {
        instructions::resolve_appeal::handler(ctx, uphold)
    }

    /// Day-21 NEW: finalise a Pending slash after its appeal window closes.
    /// Moves the encumbered lamports out of the vault — to the treasury, or
    /// burned to the incinerator for a Compromise.
    pub fn settle_slash(ctx: Context<SettleSlash>) -> Result<()> {
        instructions::settle_slash::handler(ctx)
    }

    /// Day-21 NEW: the watchdog mechanism. Anyone may challenge an oracle
    /// node for a bad submission. The instruction records the accusation
    /// and evidence hash; slash-authority review verifies referenced
    /// artifacts before any oracle-side slashing.
    pub fn challenge_oracle(
        ctx:           Context<ChallengeOracle>,
        proof_type:    u8,
        proof_hash:    [u8; 32],
        subject_epoch: u64,
        score_a:       u16,
        score_b:       u16,
    ) -> Result<()> {
        instructions::challenge_oracle::handler(
            ctx, proof_type, proof_hash, subject_epoch, score_a, score_b,
        )
    }
}
