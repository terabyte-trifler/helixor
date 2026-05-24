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

    /// One-time: create the SlashConfig singleton — the slash authority
    /// (the Phase-4 multisig stand-in) and the treasury.
    pub fn initialize_config(
        ctx:             Context<InitializeConfig>,
        slash_authority: Pubkey,
        treasury:        Pubkey,
    ) -> Result<()> {
        instructions::initialize_config::handler(ctx, slash_authority, treasury)
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
    /// node for a bad submission. On-chain-verifiable proof types
    /// (conflicting scores, phantom agent) are recorded Verified; an
    /// off-chain evidence claim is recorded Pending for governance review.
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
