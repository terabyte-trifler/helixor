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

use anchor_lang::prelude::*;

pub mod errors;
pub mod events;
pub mod instructions;
pub mod state;

use instructions::*;

// Replace with the actual deployed program ID when merging into the real repo.
declare_id!("Hex1xor111111111111111111111111111111111111");

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
    pub fn advance_epoch(ctx: Context<AdvanceEpoch>) -> Result<()> {
        instructions::advance_epoch::handler(ctx)
    }

    /// Day-19 NEW: the oracle submits an agent's epoch score. Writes the
    /// on-chain HealthCertificate by CPI into the certificate-issuer
    /// program. Atomic — if the certificate write reverts, so does this.
    pub fn submit_score(
        ctx:           Context<SubmitScore>,
        epoch:         u64,
        score:         u16,
        alert_tier:    u8,
        flags:         u32,
        confidence:    u16,
        immediate_red: bool,
    ) -> Result<()> {
        instructions::submit_score::handler(
            ctx, epoch, score, alert_tier, flags, confidence, immediate_red,
        )
    }

    /// Day-19 NEW: read an agent's current-epoch HealthCertificate. The V2
    /// replacement for the MVP's single-score get_health — same intent,
    /// new on-chain source (the epoch-keyed certificate).
    pub fn get_health(ctx: Context<GetHealth>, agent_wallet: Pubkey) -> Result<()> {
        instructions::get_health::handler(ctx, agent_wallet)
    }
}
