// =============================================================================
// Helixor — health-oracle program
//
// Day 1: stubs deployed
// Day 2: register_agent — COMPLETE
// Day 3: get_health     — COMPLETE
// Day 7: update_score   — pending
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

    /// Register a new AI agent.
    pub fn register_agent(
        ctx:    Context<RegisterAgent>,
        params: RegisterParams,
    ) -> Result<()> {
        instructions::register_agent::handler(ctx, params)
    }

    /// Read-only trust score query — the public CPI endpoint.
    ///
    /// Consumers (DeFi protocols, elizaOS plugins, off-chain services) call
    /// this to ask "what does Helixor say about this agent right now?"
    ///
    /// Returns TrustScore with a `source` field that explains where the
    /// answer came from: Live, Stale, Provisional, or Deactivated.
    /// Consumers inspect `source` and `is_fresh` to decide their own policy.
    pub fn get_health(ctx: Context<GetHealth>) -> Result<TrustScore> {
        instructions::get_health::handler(ctx)
    }

    /// Oracle-only: write a new trust score on-chain (Day 7).
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
    /// CHECK: read-only public endpoint, any account allowed
    pub querier: UncheckedAccount<'info>,
    #[account(
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump = agent_registration.bump,
    )]
    pub agent_registration: Account<'info, state::AgentRegistration>,
    /// CHECK: validated in handler against canonical PDA + deserialized payload
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
