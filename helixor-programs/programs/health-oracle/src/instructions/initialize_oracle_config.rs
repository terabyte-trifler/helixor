// =============================================================================
// initialize_oracle_config — Day 7
//
// Creates the singleton OracleConfig PDA. Called once during deployment
// migration. Subsequent calls fail (init constraint).
//
// The deployer of this instruction becomes the initial admin. They can later
// rotate to a multisig or governance contract via update_oracle_config.
// =============================================================================

use anchor_lang::prelude::*;

use crate::{
    errors::HelixorError,
    state::{InitOracleConfigParams, OracleConfig},
};

pub fn handler(
    ctx: Context<InitializeOracleConfig>,
    params: InitOracleConfigParams,
) -> Result<()> {
    require_keys_neq!(
        params.oracle_key, params.admin_key,
        HelixorError::OracleKeyEqualsAdmin
    );

    let cfg = &mut ctx.accounts.oracle_config;
    cfg.oracle_key = params.oracle_key;
    cfg.admin_key  = params.admin_key;
    cfg.bump       = ctx.bumps.oracle_config;
    cfg.paused     = false;
    cfg.epoch      = 0;

    emit!(OracleConfigInitialized {
        oracle_key: params.oracle_key,
        admin_key:  params.admin_key,
        timestamp:  Clock::get()?.unix_timestamp,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeOracleConfig<'info> {
    /// First caller becomes the initial deployer (typically the deploy wallet).
    /// They don't need to BE the admin — they're just the rent payer.
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

#[event]
pub struct OracleConfigInitialized {
    pub oracle_key: Pubkey,
    pub admin_key:  Pubkey,
    pub timestamp:  i64,
}
