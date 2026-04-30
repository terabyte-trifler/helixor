// =============================================================================
// Helixor health-oracle program — Day 7 COMPLETE
//
// Five instructions:
//   register_agent             (Day 2)
//   get_health                 (Day 3)
//   update_score               (Day 7) — oracle writes trust certificate
//   initialize_oracle_config   (Day 7) — bootstrap singleton
//   update_oracle_config       (Day 7) — admin rotates oracle/admin keys + pause
// =============================================================================

use anchor_lang::prelude::*;

pub mod errors;
pub mod state;
pub mod instructions;

pub use state::{
    InitOracleConfigParams, RegisterParams, ScorePayload, TrustScore,
    UpdateOracleConfigParams, AgentRegistration, AlertLevel, OracleConfig, ScoreSource,
    TrustCertificate,
};

declare_id!("Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P");

#[program]
pub mod health_oracle {
    use super::*;

    pub fn register_agent(ctx: Context<RegisterAgent>, params: RegisterParams) -> Result<()> {
        instructions::register_agent::handler(ctx, params)
    }

    pub fn get_health(ctx: Context<GetHealth>) -> Result<TrustScore> {
        instructions::get_health::handler(ctx)
    }

    /// Oracle-only: write a fresh TrustCertificate.
    /// Validations: oracle key, pause, agent active, 23h cooldown, 200pt cap.
    pub fn update_score(ctx: Context<UpdateScore>, payload: ScorePayload) -> Result<()> {
        instructions::update_score::handler(ctx, payload)
    }

    /// Bootstrap singleton OracleConfig PDA. Run once after deploy.
    pub fn initialize_oracle_config(
        ctx:    Context<InitializeOracleConfig>,
        params: InitOracleConfigParams,
    ) -> Result<()> {
        instructions::initialize_oracle_config::handler(ctx, params)
    }

    /// Admin-only: rotate keys or pause/unpause.
    pub fn update_oracle_config(
        ctx:    Context<UpdateOracleConfig>,
        params: UpdateOracleConfigParams,
    ) -> Result<()> {
        instructions::update_oracle_config::handler(ctx, params)
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
        payer  = owner,
        space  = 8 + AgentRegistration::INIT_SPACE,
        seeds  = [b"agent", agent_wallet.key().as_ref()],
        bump,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    #[account(
        init,
        payer  = owner,
        space  = 0,
        seeds  = [b"escrow", agent_wallet.key().as_ref()],
        bump,
    )]
    /// CHECK: created here as a system-owned PDA with zero data.
    pub escrow_vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GetHealth<'info> {
    /// CHECK: any caller
    pub querier: UncheckedAccount<'info>,

    #[account(
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump  = agent_registration.bump,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    /// CHECK: validated in handler
    pub trust_certificate: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct UpdateScore<'info> {
    /// The oracle node submitting the score. Must match oracle_config.oracle_key.
    /// Pays rent for cert PDA on first update of each agent.
    #[account(mut)]
    pub oracle: Signer<'info>,

    /// AgentRegistration PDA — must exist (agent registered).
    #[account(
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump  = agent_registration.bump,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    /// TrustCertificate PDA — created on first call, mutated on subsequent.
    #[account(
        init_if_needed,
        payer  = oracle,
        space  = 8 + TrustCertificate::INIT_SPACE,
        seeds  = [b"score", agent_registration.agent_wallet.as_ref()],
        bump,
    )]
    pub trust_certificate: Account<'info, TrustCertificate>,

    /// OracleConfig singleton. Mutated to bump epoch counter.
    #[account(
        mut,
        seeds = [b"oracle_config"],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeOracleConfig<'info> {
    #[account(mut)]
    pub deployer: Signer<'info>,

    #[account(
        init,
        payer  = deployer,
        space  = 8 + OracleConfig::INIT_SPACE,
        seeds  = [b"oracle_config"],
        bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateOracleConfig<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [b"oracle_config"],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,
}
