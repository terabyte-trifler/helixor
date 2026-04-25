// =============================================================================
// register_agent — Day 2 (frozen for Day 3)
// =============================================================================

use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer as SystemTransfer};

use crate::{
    errors::HelixorError,
    state::{AgentRegistration, RegisterParams},
    RegisterAgent,
};

pub fn handler(ctx: Context<RegisterAgent>, params: RegisterParams) -> Result<()> {
    let name_bytes = params.name.as_bytes();
    require!(!name_bytes.is_empty(), HelixorError::NameEmpty);
    require!(
        name_bytes.len() <= AgentRegistration::MAX_NAME_BYTES,
        HelixorError::NameTooLong
    );
    require!(
        ctx.accounts.agent_wallet.key() != ctx.accounts.owner.key(),
        HelixorError::AgentSameAsOwner
    );

    let clock = Clock::get()?;
    let owner_key = ctx.accounts.owner.key();
    let agent_key = ctx.accounts.agent_wallet.key();
    let registration_pda = ctx.accounts.agent_registration.key();
    let vault_pda = ctx.accounts.escrow_vault.key();
    let reg = &mut ctx.accounts.agent_registration;

    reg.agent_wallet    = agent_key;
    reg.owner_wallet    = owner_key;
    reg.registered_at   = clock.unix_timestamp;
    reg.escrow_lamports = AgentRegistration::MIN_ESCROW_LAMPORTS;
    reg.active          = true;
    reg.bump            = ctx.bumps.agent_registration;
    reg.vault_bump      = ctx.bumps.escrow_vault;

    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            SystemTransfer {
                from: ctx.accounts.owner.to_account_info(),
                to:   ctx.accounts.escrow_vault.to_account_info(),
            },
        ),
        AgentRegistration::MIN_ESCROW_LAMPORTS,
    )?;

    emit!(AgentRegistered {
        agent:            reg.agent_wallet,
        owner:            reg.owner_wallet,
        name:             params.name.clone(),
        escrow_lamports:  AgentRegistration::MIN_ESCROW_LAMPORTS,
        registration_pda,
        vault_pda,
        timestamp:        clock.unix_timestamp,
    });

    Ok(())
}

#[event]
pub struct AgentRegistered {
    pub agent:            Pubkey,
    pub owner:            Pubkey,
    pub name:             String,
    pub escrow_lamports:  u64,
    pub registration_pda: Pubkey,
    pub vault_pda:        Pubkey,
    pub timestamp:        i64,
}
