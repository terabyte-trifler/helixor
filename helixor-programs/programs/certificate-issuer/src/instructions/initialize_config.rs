// =============================================================================
// programs/certificate-issuer/src/instructions/initialize_config.rs
//
// initialize_config — one-time creation of the IssuerConfig singleton.
//
// Run once at program deployment. Establishes which oracle authority may
// issue certificates. The admin `authority` can later rotate `issuer_node`
// via a separate update instruction (out of scope for Day 18).
// =============================================================================

use anchor_lang::prelude::*;

use crate::state::IssuerConfig;

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    /// The IssuerConfig singleton, created here.
    #[account(
        init,
        payer = admin,
        space = IssuerConfig::SPACE,
        seeds = [IssuerConfig::SEED],
        bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The admin — pays rent and becomes the config's update authority.
    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializeConfig>, issuer_node: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.issuer_config;
    config.authority   = ctx.accounts.admin.key();
    config.issuer_node = issuer_node;
    config.bump        = ctx.bumps.issuer_config;

    msg!(
        "certificate-issuer config initialised: authority={}, issuer_node={}",
        config.authority,
        config.issuer_node,
    );
    Ok(())
}
