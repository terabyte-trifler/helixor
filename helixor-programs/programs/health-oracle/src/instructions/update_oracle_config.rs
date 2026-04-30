// =============================================================================
// update_oracle_config — Day 7
//
// Admin-only: rotate oracle_key, rotate admin_key, or pause/unpause.
// All three params are Optional — caller updates only what they want.
//
// Why the admin path matters:
//   - Oracle node compromised → admin rotates oracle_key to new node
//   - Admin team turnover → admin rotates admin_key to new wallet/multisig
//   - Bug found in scoring → admin pauses, no further on-chain writes
//     (off-chain scoring continues; nothing reaches the cert)
// =============================================================================

use anchor_lang::prelude::*;

use crate::{
    errors::HelixorError,
    state::UpdateOracleConfigParams,
};

pub fn handler(
    ctx: Context<crate::UpdateOracleConfig>,
    params: UpdateOracleConfigParams,
) -> Result<()> {
    let cfg = &mut ctx.accounts.oracle_config;

    require_keys_eq!(
        ctx.accounts.admin.key(),
        cfg.admin_key,
        HelixorError::UnauthorizedAdmin
    );

    if let Some(new_oracle) = params.new_oracle_key {
        require_keys_neq!(
            new_oracle, cfg.admin_key,
            HelixorError::OracleKeyEqualsAdmin
        );
        cfg.oracle_key = new_oracle;
    }
    if let Some(new_admin) = params.new_admin_key {
        require_keys_neq!(
            new_admin, cfg.oracle_key,
            HelixorError::OracleKeyEqualsAdmin
        );
        cfg.admin_key = new_admin;
    }
    if let Some(paused) = params.new_paused {
        cfg.paused = paused;
    }

    emit!(OracleConfigUpdated {
        oracle_key: cfg.oracle_key,
        admin_key:  cfg.admin_key,
        paused:     cfg.paused,
        timestamp:  Clock::get()?.unix_timestamp,
    });

    Ok(())
}

#[event]
pub struct OracleConfigUpdated {
    pub oracle_key: Pubkey,
    pub admin_key:  Pubkey,
    pub paused:     bool,
    pub timestamp:  i64,
}
