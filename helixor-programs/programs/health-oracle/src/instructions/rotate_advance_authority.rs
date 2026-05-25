// =============================================================================
// programs/health-oracle/src/instructions/rotate_advance_authority.rs
//
// rotate_advance_authority — update EpochState.advance_authority to a new key.
//
// MOTIVATION (VULN-02)
// --------------------
// advance_authority was a single non-rotatable key. If it was lost or
// compromised the epoch could never advance again. This instruction lets the
// admin (oracle_config.authority) replace the key at any time, restoring the
// normal advancement path without requiring a program redeploy.
//
// AUTHORITY GATE
// --------------
// Only oracle_config.authority (the admin, held by the Squads multisig in
// production) can rotate the key. This keeps the rotation path under
// governance control — a compromised oracle node cannot self-promote its own
// key as the new advance_authority.
//
// GUARDS
//   - new_authority != Pubkey::default()   (no rotation to the zero key)
//   - new_authority != current authority   (no no-op rotation)
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::HelixorError;
use crate::events::AdvanceAuthorityRotated;
use crate::state::{EpochState, OracleConfig};

#[derive(Accounts)]
pub struct RotateAdvanceAuthority<'info> {
    /// The epoch counter — advance_authority is updated here.
    #[account(
        mut,
        seeds = [EpochState::SEED],
        bump  = epoch_state.bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// OracleConfig — supplies the admin authority that gates this rotation.
    #[account(
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The admin. Must be oracle_config.authority.
    #[account(
        constraint = admin.key() == oracle_config.authority
            @ HelixorError::NotOracleAuthority,
    )]
    pub admin: Signer<'info>,
}

pub fn handler(
    ctx:           Context<RotateAdvanceAuthority>,
    new_authority: Pubkey,
) -> Result<()> {
    // Reject rotation to the zero pubkey — it has no private key and would
    // re-introduce the same permanent-halt risk from the other direction.
    require!(
        new_authority != Pubkey::default(),
        HelixorError::ZeroAdvanceAuthority,
    );

    let epoch_state   = &mut ctx.accounts.epoch_state;
    let old_authority = epoch_state.advance_authority;

    // Reject no-op rotations — they serve no purpose and can obscure audit
    // trails (an event should always correspond to a real state change).
    require!(
        new_authority != old_authority,
        HelixorError::SameAdvanceAuthority,
    );

    epoch_state.advance_authority = new_authority;

    let clock = Clock::get()?;
    emit!(AdvanceAuthorityRotated {
        old_authority,
        new_authority,
        rotated_by: ctx.accounts.admin.key(),
        rotated_at: clock.unix_timestamp,
    });

    msg!(
        "advance_authority rotated: {} -> {} by admin {}",
        old_authority, new_authority, ctx.accounts.admin.key(),
    );
    Ok(())
}
