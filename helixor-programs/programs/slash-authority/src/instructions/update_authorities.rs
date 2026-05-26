// =============================================================================
// programs/slash-authority/src/instructions/update_authorities.rs
//
// SPOF-#2 REMEDIATION — DEPRECATED-AND-REFUSED.
//
// The pre-SPOF-#2 design admin-gated a single-tx rotation of all three
// role keys + the settlement timelock. That collapsed the audit's
// VULN-04 separated-authority guarantee back to a single-key risk: a
// compromised admin could install three attacker-controlled role keys
// in one transaction and drain every escrow vault.
//
// The fix replaces single-admin rotation with the time-locked,
// 2-of-3-attested propose/attest/enact ceremony in:
//   - instructions::propose_authority_rotation
//   - instructions::attest_authority_rotation
//   - instructions::enact_authority_rotation
//   - instructions::cancel_authority_rotation
//
// This handler is RETAINED only so callers of the old IDL get a clean,
// typed rejection (`SingleAdminUpdateRemoved`, code 6088) pointing them
// at the new ceremony. The instruction now ALWAYS returns the error
// regardless of signer, arguments, or state — it cannot be used to
// rewrite authority.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::state::SlashConfig;

#[derive(Accounts)]
pub struct UpdateAuthorities<'info> {
    /// SlashConfig — read-only here. Retained on the account-list so the
    /// IDL shape matches the pre-SPOF-#2 instruction; the handler refuses
    /// before any state read matters.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// Retained for IDL compatibility; signature is not validated because
    /// the handler always refuses.
    pub admin: Signer<'info>,
}

pub fn handler(
    _ctx:                         Context<UpdateAuthorities>,
    _slash_executor:              Pubkey,
    _appeal_resolver:             Pubkey,
    _pause_authority:             Pubkey,
    _settlement_timelock_seconds: i64,
) -> Result<()> {
    msg!(
        "update_authorities is removed under SPOF-#2 — use \
         propose_authority_rotation + attest_authority_rotation + \
         enact_authority_rotation (48h timelock, 2-of-3 role keys must \
         attest)",
    );
    err!(SlashError::SingleAdminUpdateRemoved)
}
