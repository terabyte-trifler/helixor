// =============================================================================
// Helixor health-oracle program — V2 Day 3 merged
//
// Existing MVP instructions stay live, and Day 3 adds baseline commitment:
//   register_agent
//   get_health
//   update_score
//   initialize_oracle_config
//   update_oracle_config
//   commit_baseline
//   migrate_registration
// =============================================================================

use anchor_lang::prelude::*;

pub mod errors;
pub mod events;
pub mod instructions;
pub mod state;

pub use instructions::CommitBaselineArgs;
pub use state::{
    AgentRegistration, AlertLevel, InitOracleConfigParams, OracleConfig, RegisterParams,
    ScorePayload, ScoreSource, TrustCertificate, TrustScore, UpdateOracleConfigParams,
};

declare_id!("Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P");

pub const BOOTSTRAP_AUTHORITY: Pubkey = pubkey!("ANoJSqqxqih1kSkjYaRno9YeBMVaYB8gmcPnBdV5NqQJ");

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
        ctx: Context<InitializeOracleConfig>,
        params: InitOracleConfigParams,
    ) -> Result<()> {
        instructions::initialize_oracle_config::handler(ctx, params)
    }

    /// Admin-only: rotate keys or pause/unpause.
    pub fn update_oracle_config(
        ctx: Context<UpdateOracleConfig>,
        params: UpdateOracleConfigParams,
    ) -> Result<()> {
        instructions::update_oracle_config::handler(ctx, params)
    }

    /// Day-3 NEW: commit a baseline-hash to an agent's registration.
    /// See commit_baseline::handler for the full authority + replay logic.
    pub fn commit_baseline(ctx: Context<CommitBaseline>, args: CommitBaselineArgs) -> Result<()> {
        instructions::commit_baseline::handler(ctx, args)
    }

    /// Day-3 NEW: one-time per-agent realloc from v1 (MVP) to v2 layout.
    /// Owner-only; pays the additional rent for the larger account.
    pub fn migrate_registration(ctx: Context<MigrateRegistration>) -> Result<()> {
        instructions::migrate_registration::handler(ctx)
    }
}

#[derive(Accounts)]
pub struct RegisterAgent<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    pub agent_wallet: Signer<'info>,

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

#[derive(Accounts)]
#[instruction(args: CommitBaselineArgs)]
pub struct CommitBaseline<'info> {
    /// The agent registration we are committing on. Must be active and at
    /// the current layout version (older layouts need migrate_registration).
    #[account(
        mut,
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump  = agent_registration.bump,
        constraint = agent_registration.active @ errors::HelixorError::AgentInactive,
        constraint = agent_registration.layout_version == AgentRegistration::CURRENT_LAYOUT_VERSION
            @ errors::HelixorError::LayoutMigrationRequired,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    /// OracleConfig is the source of truth for oracle authority.
    #[account(
        seeds = [b"oracle_config"],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The signer claiming the right to commit. Validated in the handler.
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct MigrateRegistration<'info> {
    #[account(
        mut,
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump  = agent_registration.bump,
        realloc            = AgentRegistration::SPACE,
        realloc::payer     = owner,
        realloc::zero      = true,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    #[account(
        mut,
        constraint = owner.key() == agent_registration.owner_wallet @ errors::HelixorError::NotAgentOwner,
    )]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}
