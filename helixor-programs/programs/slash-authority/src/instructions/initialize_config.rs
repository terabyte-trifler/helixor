// =============================================================================
// programs/slash-authority/src/instructions/initialize_config.rs
//
// initialize_config — one-time creation of the SlashConfig singleton.
//
// Sets the slash authority (a single key today, the Phase-4 multisig
// stand-in) and the treasury that receives non-burn slashes.
// =============================================================================

use anchor_lang::prelude::*;

use crate::state::SlashConfig;

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
    ctx:             Context<InitializeConfig>,
    slash_authority: Pubkey,
    treasury:        Pubkey,
) -> Result<()> {
    let config = &mut ctx.accounts.slash_config;
    config.admin           = ctx.accounts.admin.key();
    config.slash_authority = slash_authority;
    config.treasury        = treasury;
    config.bump            = ctx.bumps.slash_config;

    msg!(
        "slash-authority config initialised: slash_authority={}, treasury={}",
        config.slash_authority, config.treasury,
    );
    Ok(())
}
