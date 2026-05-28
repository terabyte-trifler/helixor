// =============================================================================
// programs/slash-authority/src/instructions/initialize_config.rs
//
// initialize_config — one-time creation of the SlashConfig singleton.
//
// VULN-04: the single `slash_authority` key was replaced by three
// independent roles (slash_executor, appeal_resolver, pause_authority)
// plus a settlement-timelock parameter. All three keys must be distinct,
// non-default; the timelock must be at least
// MIN_SETTLEMENT_TIMELOCK_SECONDS (72h).
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::state::{
    validate_authority_separation, AuthoritySeparationError, SlashConfig,
    MIN_SETTLEMENT_TIMELOCK_SECONDS, SLASH_CONFIG_LAYOUT_VERSION,
};

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    /// The SlashConfig singleton, created here.
    #[account(
        init,
        payer = admin,
        space = SlashConfig::SPACE,
        seeds = [SlashConfig::SEED],
        bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// The admin — pays rent, becomes the config update authority.
    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:                         Context<InitializeConfig>,
    slash_executor:              Pubkey,
    appeal_resolver:             Pubkey,
    pause_authority:             Pubkey,
    treasury:                    Pubkey,
    settlement_timelock_seconds: i64,
) -> Result<()> {
    // Authority separation: all three role keys must be distinct + non-zero.
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

    // Timelock must meet the protocol minimum (72h).
    require!(
        settlement_timelock_seconds >= MIN_SETTLEMENT_TIMELOCK_SECONDS,
        SlashError::SettlementTimelockTooShort,
    );

    // Treasury sanity — refuse default Pubkey (a typo'd treasury would
    // silently send slashed funds to the all-zero address forever).
    require!(treasury != Pubkey::default(), SlashError::DefaultPubkey);

    let config = &mut ctx.accounts.slash_config;
    config.admin                       = ctx.accounts.admin.key();
    config.slash_executor              = slash_executor;
    config.appeal_resolver             = appeal_resolver;
    config.pause_authority             = pause_authority;
    config.treasury                    = treasury;
    config.settlement_timelock_seconds = settlement_timelock_seconds;
    config.paused                      = false;
    config.paused_at                   = 0;
    // H-04: bounded-pause auto-expiry timer; zero until the first pause.
    config.paused_until                = 0;
    config.bump                        = ctx.bumps.slash_config;
    config.layout_version              = SLASH_CONFIG_LAYOUT_VERSION;
    config._reserved                   = [0u8; 22];

    msg!(
        "slash-authority config initialised: executor={}, resolver={}, \
         pauser={}, treasury={}, timelock={}s",
        config.slash_executor,
        config.appeal_resolver,
        config.pause_authority,
        config.treasury,
        config.settlement_timelock_seconds,
    );
    Ok(())
}
