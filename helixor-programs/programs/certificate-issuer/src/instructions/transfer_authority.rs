// =============================================================================
// programs/certificate-issuer/src/instructions/transfer_authority.rs
//
// H-3 — two-step, time-locked transfer of the IssuerConfig admin authority.
//
// THE AUDIT FINDING
// -----------------
// `issuer_config.authority` was written ONCE by `initialize_config` and there
// was NO instruction anywhere to change it. Consequences:
//
//   * A single compromised admin key had full, irrevocable control of cluster
//     rotation (`rotate_cluster_keys`) and admin revokes — the precise failure
//     the threshold-signing architecture exists to survive — with no on-chain
//     remedy.
//   * A LOST admin key meant the cluster keys could never be rotated again,
//     forcing a full `IssuerConfig` redeploy that orphans every
//     config_version-bound certificate.
//
// THE FIX (Ownable2Step + a timelock)
// -----------------------------------
//   1. PROPOSE — the current `authority` nominates a successor. Recorded as
//      `pending_authority` with `eta = now + 48h`. NOT yet effective.
//   2. ACCEPT  — the `pending_authority` itself signs, AFTER `eta`. This
//      proves the successor controls the key (no fat-finger to an unspendable
//      address) and atomically swaps `authority`. Clears the pending slot.
//   3. CANCEL  — the current `authority` aborts a pending proposal during the
//      window (the veto path; pairs with off-chain monitoring of the
//      AuthorityTransferProposed event).
//
// This does NOT fully neutralise a compromised CURRENT key (the attacker can
// propose their own successor and, after the timelock, accept it). It DOES
// give the system the recovery path it entirely lacked, forces every handoff
// to be an on-chain-observable, delayed event, and prevents accidental
// transfer to an uncontrolled address. The residual hardening — making
// `authority` a Squads multisig in production — is an org/key-management
// decision layered on top of this mechanism.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::{
    AuthorityTransferAccepted, AuthorityTransferCancelled, AuthorityTransferProposed,
};
use crate::state::IssuerConfig;

// -----------------------------------------------------------------------------
// 1. PROPOSE — current authority nominates a successor
// -----------------------------------------------------------------------------

#[derive(Accounts)]
pub struct ProposeAuthorityTransfer<'info> {
    #[account(
        mut,
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The CURRENT authority. Must equal `issuer_config.authority`.
    pub authority: Signer<'info>,
}

pub fn propose_handler(
    ctx:           Context<ProposeAuthorityTransfer>,
    new_authority: Pubkey,
) -> Result<()> {
    let config = &mut ctx.accounts.issuer_config;

    require_keys_eq!(
        ctx.accounts.authority.key(),
        config.authority,
        CertificateError::NotIssuerAuthority,
    );
    require!(
        new_authority != Pubkey::default(),
        CertificateError::ZeroPendingAuthority,
    );
    require!(
        new_authority != config.authority,
        CertificateError::PendingAuthorityIsCurrent,
    );

    let now = Clock::get()?.unix_timestamp;
    // checked_add so a pathological clock value can never wrap the eta.
    let eta = now
        .checked_add(IssuerConfig::AUTHORITY_TRANSFER_TIMELOCK_SECONDS)
        .ok_or(error!(CertificateError::AuthorityTransferTimelockNotElapsed))?;

    // Overwriting any prior pending proposal is intentional: the current
    // authority may re-propose a different successor, which simply restarts
    // the timelock against the new key.
    config.pending_authority      = new_authority;
    config.authority_transfer_eta = eta;

    emit!(AuthorityTransferProposed {
        current_authority: config.authority,
        pending_authority: new_authority,
        eta,
        proposed_at_unix:  now,
    });
    msg!("H-3: authority transfer proposed -> {} (eta {})", new_authority, eta);
    Ok(())
}

// -----------------------------------------------------------------------------
// 2. ACCEPT — the pending successor claims the authority (after the timelock)
// -----------------------------------------------------------------------------

#[derive(Accounts)]
pub struct AcceptAuthorityTransfer<'info> {
    #[account(
        mut,
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The PENDING successor. Must equal `issuer_config.pending_authority`.
    /// Requiring this signer is the proof-of-possession that closes the
    /// fat-finger / unspendable-address gap.
    pub new_authority: Signer<'info>,
}

pub fn accept_handler(ctx: Context<AcceptAuthorityTransfer>) -> Result<()> {
    let config = &mut ctx.accounts.issuer_config;

    require!(
        config.has_pending_authority_transfer(),
        CertificateError::NoPendingAuthorityTransfer,
    );
    require_keys_eq!(
        ctx.accounts.new_authority.key(),
        config.pending_authority,
        CertificateError::NotPendingAuthority,
    );

    let now = Clock::get()?.unix_timestamp;
    require!(
        now >= config.authority_transfer_eta,
        CertificateError::AuthorityTransferTimelockNotElapsed,
    );

    let old_authority = config.authority;
    let new_authority = config.pending_authority;

    config.authority              = new_authority;
    config.pending_authority      = Pubkey::default();
    config.authority_transfer_eta = 0;

    emit!(AuthorityTransferAccepted {
        old_authority,
        new_authority,
        accepted_at_unix: now,
    });
    msg!("H-3: authority transfer accepted: {} -> {}", old_authority, new_authority);
    Ok(())
}

// -----------------------------------------------------------------------------
// 3. CANCEL — current authority vetoes a pending proposal
// -----------------------------------------------------------------------------

#[derive(Accounts)]
pub struct CancelAuthorityTransfer<'info> {
    #[account(
        mut,
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The CURRENT authority. Must equal `issuer_config.authority`.
    pub authority: Signer<'info>,
}

pub fn cancel_handler(ctx: Context<CancelAuthorityTransfer>) -> Result<()> {
    let config = &mut ctx.accounts.issuer_config;

    require_keys_eq!(
        ctx.accounts.authority.key(),
        config.authority,
        CertificateError::NotIssuerAuthority,
    );
    require!(
        config.has_pending_authority_transfer(),
        CertificateError::NoPendingAuthorityTransfer,
    );

    let cancelled_pending = config.pending_authority;
    config.pending_authority      = Pubkey::default();
    config.authority_transfer_eta = 0;

    let now = Clock::get()?.unix_timestamp;
    emit!(AuthorityTransferCancelled {
        authority:         config.authority,
        cancelled_pending,
        cancelled_at_unix: now,
    });
    msg!("H-3: authority transfer cancelled (was -> {})", cancelled_pending);
    Ok(())
}
