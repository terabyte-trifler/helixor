use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer as SystemTransfer};

use crate::{
    errors::HelixorError,
    state::{AgentRegistration, RegisterParams},
};

pub fn handler(ctx: Context<crate::RegisterAgent>, params: RegisterParams) -> Result<()> {
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

    let reg = &mut ctx.accounts.agent_registration;
    let clock = Clock::get()?;

    reg.agent_wallet = ctx.accounts.agent_wallet.key();
    reg.owner_wallet = ctx.accounts.owner.key();
    reg.registered_at = clock.unix_timestamp;
    reg.escrow_lamports = AgentRegistration::MIN_ESCROW_LAMPORTS;
    reg.active = true;
    reg.bump = ctx.bumps.agent_registration;
    reg.vault_bump = ctx.bumps.escrow_vault;
    reg.baseline_committed = false;
    reg.baseline_hash = [0; 32];
    reg.baseline_algo_version = 0;
    reg.baseline_committer = Pubkey::default();
    reg.baseline_committed_at = 0;
    reg.commit_nonce = 0;
    reg.layout_version = AgentRegistration::CURRENT_LAYOUT_VERSION;
    reg._reserved = [0; 64];

    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            SystemTransfer {
                from: ctx.accounts.owner.to_account_info(),
                to: ctx.accounts.escrow_vault.to_account_info(),
            },
        ),
        AgentRegistration::MIN_ESCROW_LAMPORTS,
    )?;

    emit!(AgentRegistered {
        agent: reg.agent_wallet,
        owner: reg.owner_wallet,
        name: params.name.clone(),
        escrow_lamports: AgentRegistration::MIN_ESCROW_LAMPORTS,
        registration_pda: ctx.accounts.agent_registration.key(),
        vault_pda: ctx.accounts.escrow_vault.key(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[event]
pub struct AgentRegistered {
    pub agent: Pubkey,
    pub owner: Pubkey,
    pub name: String,
    pub escrow_lamports: u64,
    pub registration_pda: Pubkey,
    pub vault_pda: Pubkey,
    pub timestamp: i64,
}
