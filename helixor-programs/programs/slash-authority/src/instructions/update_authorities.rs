// =============================================================================
// programs/slash-authority/src/instructions/update_authorities.rs
//
// update_authorities — admin-gated rotation of the three role keys and
// the settlement timelock. VULN-04 requires the keys to stay distinct
// after rotation and the timelock to remain >= MIN_SETTLEMENT_TIMELOCK.
//
// Use this to:
//   - rotate a leaked slash_executor without redeploying,
//   - swap a single-key role for the Phase-4 multisig PDA,
//   - lengthen (never shorten below the floor) the settlement timelock.
//
// The admin key itself is not rotated here — that is a deliberate
// separation; a compromised slash_executor cannot escalate to admin via
// this instruction.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::AuthoritiesUpdated;
use crate::state::{
    validate_authority_separation, AuthoritySeparationError, SlashConfig,
    MIN_SETTLEMENT_TIMELOCK_SECONDS,
};

#[derive(Accounts)]
pub struct UpdateAuthorities<'info> {
    /// SlashConfig — the role keys live here.
    #[account(
        mut,
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The admin — only key permitted to rotate the role set.
    #[account(
        constraint = admin.key() == slash_config.admin @ SlashError::NotAdmin,
    )]
    pub admin: Signer<'info>,
}

pub fn handler(
    ctx:                         Context<UpdateAuthorities>,
    slash_executor:              Pubkey,
    appeal_resolver:             Pubkey,
    pause_authority:             Pubkey,
    settlement_timelock_seconds: i64,
) -> Result<()> {
    // Authority separation re-validated on every rotation.
    match validate_authority_separation(
        &slash_executor,
        &appeal_resolver,
        &pause_authority,
    ) {
        Ok(()) => {}
        Err(AuthoritySeparationError::DefaultPubkey) => {
            return err!(SlashError::DefaultPubkey);
        }
        Err(AuthoritySeparationError::NotDistinct) => {
            return err!(SlashError::AuthoritiesMustDiffer);
        }
    }

    // Timelock floor — never below the protocol minimum (72h). A future
    // admin could raise it but never lower below this gate.
    require!(
        settlement_timelock_seconds >= MIN_SETTLEMENT_TIMELOCK_SECONDS,
        SlashError::SettlementTimelockTooShort,
    );

    let config = &mut ctx.accounts.slash_config;
    config.slash_executor              = slash_executor;
    config.appeal_resolver             = appeal_resolver;
    config.pause_authority             = pause_authority;
    config.settlement_timelock_seconds = settlement_timelock_seconds;

    emit!(AuthoritiesUpdated {
        slash_executor,
        appeal_resolver,
        pause_authority,
        settlement_timelock_seconds,
        updated_at: Clock::get()?.unix_timestamp,
    });

    msg!(
        "slash-authority roles rotated: executor={}, resolver={}, \
         pauser={}, timelock={}s",
        slash_executor, appeal_resolver, pause_authority,
        settlement_timelock_seconds,
    );
    Ok(())
}
