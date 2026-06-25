// =============================================================================
// programs/certificate-issuer/src/instructions/revoke_verified_consumer.rs
//
// DBP-2 — Revoke a VerifiedConsumer badge.
//
// REVOCATION MODEL
// ----------------
// Two distinct revoke paths, dispatched on the signer + reason:
//
//   * PARTNER SELF-REVOKE
//       - signer:        partner_wallet
//       - reason:        PartnerSelfRevoke (1)
//       - when:          the partner is deprecating an integration, rotating
//                        to a new manifest, or otherwise voluntarily exiting.
//
//   * ADMIN REVOKE
//       - signer:        issuer_config.authority
//       - reason:        AdminBadFaith (2)  — manifest was a bad-faith
//                                             attestation (linter green on
//                                             paper, production code differs)
//                        AdminTerminated (3) — legal / ToS / contract breach
//       - when:          a drain post-mortem traces back to the partner's
//                        cert-reader, OR the partner has otherwise violated
//                        the Verified Integrator program terms.
//
// THE ACCOUNT IS NOT CLOSED
// -------------------------
// Revocation FLIPS state to Revoked and stamps `(revoked_at_unix, revoked_by,
// revoke_reason)`. The account persists so the audit trail is permanent:
// a downstream lending contract can read the badge and KNOW the partner
// HAD it and lost it (the partner is on the public revoked-list now), which
// is structurally different from "the partner never claimed a badge."
//
// The architectural invariant is: `is_active()` is the gate, NOT account
// presence. A consumer that relies on account presence alone is broken
// (which is why is_active() is unit-tested as a pure function of `state`).
//
// RE-REGISTRATION
// ---------------
// Once revoked, the partner cannot re-register against a different
// manifest because Anchor `init` on the same PDA fails. Re-registration
// requires a SEPARATE admin `close_verified_consumer` instruction (not in
// v1 — deferred until a partner actually needs to rotate). The v1
// constraint is intentional: a partner who burns their badge once must
// engage with the admin to start over, which gates re-entry on a manual
// review.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::VerifiedConsumerRevoked;
use crate::state::{
    issuer_config::IssuerConfig,
    verified_consumer::{RevokeReason, VerifiedConsumer, VerifiedConsumerState},
};

#[derive(Accounts)]
pub struct RevokeVerifiedConsumer<'info> {
    /// The VerifiedConsumer PDA being revoked. Pinned by its PDA seeds so
    /// the caller cannot swap in a different account at the same address.
    #[account(
        mut,
        seeds = [
            VerifiedConsumer::SEED_PREFIX,
            verified_consumer.partner_wallet.as_ref(),
        ],
        bump = verified_consumer.bump,
    )]
    pub verified_consumer: Account<'info, VerifiedConsumer>,

    /// IssuerConfig — supplies the admin authority for admin-revoke paths.
    /// Not mutated; just read to compare authority against the signer.
    #[account(
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The revoker — either the partner_wallet (self-revoke) or the
    /// issuer_config.authority (admin revoke). The handler dispatches on
    /// `signer.key() == verified_consumer.partner_wallet` vs `signer.key()
    /// == issuer_config.authority` and rejects everything else.
    pub signer: Signer<'info>,
}

pub fn handler(
    ctx:           Context<RevokeVerifiedConsumer>,
    revoke_reason: u8,
) -> Result<()> {
    let vc       = &mut ctx.accounts.verified_consumer;
    let cfg      = &ctx.accounts.issuer_config;
    let signer   = ctx.accounts.signer.key();
    let clock    = Clock::get()?;

    // 1. Already-revoked is a no-op and refused, so the audit trail records
    //    exactly one revoke event per badge. A partner trying to "change
    //    their revoke reason" cannot rewrite history.
    require!(
        vc.is_active(),
        CertificateError::BadgeAlreadyRevoked,
    );

    // 2. The reason byte must name a real revoke variant. NotRevoked (0) is
    //    invalid in a revoke call — it's the default state for an Active
    //    badge, not an intentional revocation.
    let reason = RevokeReason::from_u8(revoke_reason)
        .ok_or(CertificateError::InvalidRevokeReason)?;
    require!(
        reason != RevokeReason::NotRevoked,
        CertificateError::InvalidRevokeReason,
    );

    // 3. Dispatch on the signer. Partner-self-revoke vs admin-revoke have
    //    distinct allowed reason codes, so a partner cannot accidentally
    //    (or maliciously) self-revoke with the AdminBadFaith reason and
    //    pollute the audit trail's signal.
    let is_partner = signer == vc.partner_wallet;
    let is_admin   = signer == cfg.authority;

    require!(
        is_partner || is_admin,
        CertificateError::UnauthorizedRevoke,
    );

    match reason {
        RevokeReason::PartnerSelfRevoke => {
            require!(is_partner, CertificateError::RevokeReasonSignerMismatch);
        }
        RevokeReason::AdminBadFaith | RevokeReason::AdminTerminated => {
            require!(is_admin, CertificateError::RevokeReasonSignerMismatch);
        }
        RevokeReason::NotRevoked => {
            // Already guarded by the require! above — defensive double-check.
            return err!(CertificateError::InvalidRevokeReason);
        }
    }

    // 4. Persist the revocation. `is_active()` returns false after this
    //    block; downstream contracts that gate on `state == Active`
    //    immediately stop trusting the partner's cert-derived params.
    vc.state           = VerifiedConsumerState::Revoked as u8;
    vc.revoked_at_unix = clock.unix_timestamp;
    vc.revoked_by      = signer;
    vc.revoke_reason   = reason as u8;

    emit!(VerifiedConsumerRevoked {
        partner_wallet:    vc.partner_wallet,
        verified_consumer: vc.key(),
        revoked_by:        signer,
        revoke_reason:     reason as u8,
        revoked_at_unix:   vc.revoked_at_unix,
    });

    msg!(
        "VerifiedConsumer REVOKED: partner={} by={} reason={} unix={}",
        vc.partner_wallet, signer, reason as u8, vc.revoked_at_unix,
    );

    Ok(())
}
