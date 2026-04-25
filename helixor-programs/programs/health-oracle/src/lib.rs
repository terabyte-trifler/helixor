// =============================================================================
// Helixor — health-oracle program
//
// Single-program MVP. Handles:
//   - register_agent   (Day 2 — COMPLETE)
//   - get_health       (Day 3 — stub)
//   - update_score     (Day 7 — stub)
//
// Scope reduction decisions:
//   - No certificate_issuer program. TrustCertificate lives here.
//   - No slash_authority program. Score itself is the penalty.
//   - No SPL token dependency. Native SOL escrow for MVP.
//   - No multisig on oracle key. Single oracle for MVP; rotate via
//     update_oracle_key governance ix in V2.
// =============================================================================

use anchor_lang::prelude::*;

pub mod errors;
pub mod state;
pub mod instructions;

pub use state::{RegisterParams, ScorePayload, TrustScore};

declare_id!("Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P");

#[program]
pub mod health_oracle {
    use super::*;

    /// Register a new AI agent with Helixor.
    ///
    /// Creates two PDAs:
    ///   - AgentRegistration at ["agent", agent_wallet]
    ///   - EscrowVault        at ["escrow", agent_wallet]
    ///
    /// Transfers MIN_ESCROW_LAMPORTS (0.01 SOL) from owner to vault.
    /// Agent starts with no score; first score is written by oracle at next epoch.
    pub fn register_agent(
        ctx:    Context<RegisterAgent>,
        params: RegisterParams,
    ) -> Result<()> {
        instructions::register_agent::handler(ctx, params)
    }

    /// Read-only trust score query. Called by DeFi protocols via CPI.
    /// Returns TrustScore including freshness flag (false if cert > 48h old).
    /// Returns synthetic PROVISIONAL score if cert doesn't exist yet.
    pub fn get_health(ctx: Context<GetHealth>) -> Result<TrustScore> {
        instructions::get_health::handler(ctx)
    }

    /// Oracle-only: write a new trust score on-chain.
    /// Guard rails: 23h cooldown, 200pt max delta per epoch, oracle signer check.
    pub fn update_score(
        ctx:     Context<UpdateScore>,
        payload: ScorePayload,
    ) -> Result<()> {
        instructions::update_score::handler(ctx, payload)
    }
}

#[derive(Accounts)]
pub struct RegisterAgent<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: validated in handler
    pub agent_wallet: UncheckedAccount<'info>,
    #[account(
        init,
        payer = owner,
        space = 8 + state::AgentRegistration::INIT_SPACE,
        seeds = [b"agent", agent_wallet.key().as_ref()],
        bump,
    )]
    pub agent_registration: Account<'info, state::AgentRegistration>,
    #[account(
        init,
        payer = owner,
        space = 0,
        seeds = [b"escrow", agent_wallet.key().as_ref()],
        bump,
    )]
    /// CHECK: created here as a system-owned PDA with zero data.
    pub escrow_vault: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GetHealth<'info> {
    /// CHECK: any caller — read-only endpoint
    pub querier: UncheckedAccount<'info>,
    /// CHECK: Day 3 wires proper seeds
    pub agent_registration: UncheckedAccount<'info>,
    /// CHECK: Day 3 handles missing cert
    pub trust_certificate: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct UpdateScore<'info> {
    pub oracle: Signer<'info>,
    /// CHECK: Day 7 wires seeds
    pub agent_registration: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: Day 7 wires init_if_needed
    pub trust_certificate: UncheckedAccount<'info>,
    /// CHECK: Day 7 wires seeds
    pub oracle_config: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
