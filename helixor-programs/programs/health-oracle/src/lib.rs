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

use state::{
    InitOracleConfigParams, RegisterParams, ScorePayload, TrustScore,
    UpdateOracleConfigParams,
};

use instructions::{
    get_health::GetHealth,
    initialize_oracle_config::InitializeOracleConfig,
    register_agent::RegisterAgent,
    update_oracle_config::UpdateOracleConfig,
    update_score::UpdateScore,
};
use instructions::get_health::__client_accounts_get_health;
use instructions::initialize_oracle_config::__client_accounts_initialize_oracle_config;
use instructions::register_agent::__client_accounts_register_agent;
use instructions::update_oracle_config::__client_accounts_update_oracle_config;
use instructions::update_score::__client_accounts_update_score;

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
