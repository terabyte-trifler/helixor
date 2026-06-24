// =============================================================================
// programs/certificate-issuer/src/instructions/invalidate_certificate.rs
//
// M-6 — authority-gated certificate invalidation (the on-chain recovery path).
//
// THE AUDIT FINDING
// -----------------
// The certificate PDA ["cert", agent, epoch] is WRITE-ONCE (immutability is a
// deliberate guarantee). A buggy or malicious oracle that wrote a WRONG SCORE
// for an (agent, epoch) therefore locked the agent into that bad cert with no
// on-chain recovery: the slot-anchor `challenge_certificate` path only catches
// a wrong slot ANCHOR, not a wrong score, and the cert can never be re-issued
// at the same PDA. Combined with H-1 (slashing on cert evidence), a bad cert
// could get an agent slashed with no way to repudiate the cert on chain.
//
// THE FIX
// -------
// An authority-gated invalidation that flips the cert's `challenge_state` to
// `Invalidated` (a repudiated state, downstream-equivalent to `Upheld`). The
// cert's signed CONTENT is never mutated — its immutability as a historical
// record is preserved — but consumers now see it as repudiated, and the
// agent's NEXT-epoch cert supersedes it. Gated on `issuer_config.authority`
// (post-H-3 a rotatable, timelocked authority); invalidation can only REMOVE
// trust (mark a cert invalid), never forge a good one, so the blast radius of
// a misused authority is a liveness/grief at worst — recoverable next epoch.
//
// Only a still-`None` cert may be invalidated; one already Upheld/Rejected/
// Invalidated has been resolved (CertificateAlreadyResolved).
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::CertificateInvalidated;
use crate::state::{ChallengeState, HealthCertificate, IssuerConfig};

#[derive(Accounts)]
pub struct InvalidateCertificate<'info> {
    /// The certificate to invalidate. Pinned by its self-referential PDA
    /// seeds + stored bump, so the caller cannot swap in a different account.
    #[account(
        mut,
        seeds = [
            HealthCertificate::SEED_PREFIX,
            certificate.agent_wallet.as_ref(),
            &certificate.epoch.to_le_bytes(),
        ],
        bump = certificate.bump,
    )]
    pub certificate: Account<'info, HealthCertificate>,

    /// IssuerConfig — supplies the authority gate.
    #[account(
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The issuer authority. Must equal `issuer_config.authority`.
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<InvalidateCertificate>) -> Result<()> {
    let config = &ctx.accounts.issuer_config;
    require_keys_eq!(
        ctx.accounts.authority.key(),
        config.authority,
        CertificateError::NotIssuerAuthority,
    );

    let cert = &mut ctx.accounts.certificate;

    // Only an as-yet-unresolved cert may be invalidated.
    let prior = ChallengeState::from_u8(cert.challenge_state)
        .unwrap_or(ChallengeState::None);
    require!(
        prior == ChallengeState::None,
        CertificateError::CertificateAlreadyResolved,
    );

    cert.challenge_state = ChallengeState::Invalidated.as_u8();

    let now = Clock::get()?.unix_timestamp;
    emit!(CertificateInvalidated {
        certificate:        cert.key(),
        agent_wallet:       cert.agent_wallet,
        epoch:              cert.epoch,
        authority:          ctx.accounts.authority.key(),
        invalidated_at_unix: now,
    });
    msg!(
        "M-6: certificate invalidated: agent={} epoch={} by authority={}",
        cert.agent_wallet, cert.epoch, ctx.accounts.authority.key(),
    );
    Ok(())
}
