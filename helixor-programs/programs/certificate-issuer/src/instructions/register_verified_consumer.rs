// =============================================================================
// programs/certificate-issuer/src/instructions/register_verified_consumer.rs
//
// DBP-2 — Mint the on-chain "Verified Integrator" badge.
//
// FLOW
// ----
// A DeFi partner who:
//   1. Has run `audit/consumer_integration_check.py` against their fork and
//      it lights GREEN,
//   2. Has merged their `launch/integrations/<name>.json` manifest into the
//      Helixor repo (the PR-gated DBP-1 audit step), and
//   3. Controls the `partner_wallet` keypair the manifest names,
//
// calls THIS instruction once with their canonical `integration_hash` (the
// sha256 over the manifest minus its self-referential fields). The handler
// writes the VerifiedConsumer PDA and emits `VerifiedConsumerRegistered`.
//
// IDENTITY MODEL — DIRECT-SIGNER (DBP-2 v1)
// -----------------------------------------
// DBP-2 v1 uses the simplest possible identity model: `partner_wallet` IS
// the transaction `Signer<'info>`. Anchor's Signer constraint guarantees a
// valid Solana signature over the tx, which is cryptographically equivalent
// to the partner having signed over the (integration_hash, instruction)
// pair. There is no off-chain Ed25519 precompile dance for the v1 path —
// the on-chain reality is "the partner sent this tx, full stop."
//
// Partners who don't hold raw keys (institutional partners, multisig
// custody, etc.) use a Squads multisig as `partner_wallet` and that works
// transparently — Squads is just another Solana signer.
//
// INIT-ONCE
// ---------
// The PDA seed `["verified_consumer", partner_wallet]` is one-per-partner
// and Anchor `init` makes the first call wins. A second call by the same
// partner fails at Anchor init (`account already in use`). To rotate to a
// new manifest, the partner must first `revoke_verified_consumer` (which
// merely flips state, not closes), and an admin must close the account
// before a new registration is possible. The two-step intentional flow
// keeps an immutable audit trail of every manifest a partner has claimed.
//
// CANONICAL DIGEST BINDING
// ------------------------
// The handler does NOT verify a separate detached signature over
// `registration_attestation_digest(partner_wallet, integration_hash)` in
// v1 — the tx signer IS the partner_wallet, so the binding is implicit in
// the Anchor Signer constraint. The digest helper in
// `state::verified_consumer::registration_attestation_digest` is still
// exported because a future v2 with delegated submission (off-chain
// signature + anyone-can-submit relayer) would verify it on chain.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::VerifiedConsumerRegistered;
use crate::state::verified_consumer::{
    RevokeReason, VerifiedConsumer, VerifiedConsumerState,
};

#[derive(Accounts)]
#[instruction(integration_hash: [u8; 32])]
pub struct RegisterVerifiedConsumer<'info> {
    /// The VerifiedConsumer PDA — `["verified_consumer", partner_wallet]`.
    /// Init-once: a second call by the same partner fails on init. To
    /// re-register against a different manifest, the partner must first
    /// revoke (and an admin must close the account).
    #[account(
        init,
        payer = partner_wallet,
        space = VerifiedConsumer::SPACE,
        seeds = [
            VerifiedConsumer::SEED_PREFIX,
            partner_wallet.key().as_ref(),
        ],
        bump,
    )]
    pub verified_consumer: Account<'info, VerifiedConsumer>,

    /// The partner's wallet — pays the rent AND signs the tx, so the on-
    /// chain registration is cryptographically bound to the partner's
    /// keypair. (Future v2 may delegate this via an off-chain precompile
    /// signature + relayer; v1 keeps it simple.)
    #[account(mut)]
    pub partner_wallet: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:              Context<RegisterVerifiedConsumer>,
    integration_hash: [u8; 32],
) -> Result<()> {
    // 1. Refuse empty manifest hashes. A zero hash would let a partner mint
    //    a badge that attests to "no manifest" — the audit trail must always
    //    point at SOME canonical manifest.
    require!(
        integration_hash != [0u8; 32],
        CertificateError::ZeroIntegrationHash,
    );

    // 2. Refuse the default (zero) pubkey. Solana lets a Signer in principle
    //    be `Pubkey::default()` only via pathological setups, but treating it
    //    as a programmer-error guard is cheap and makes the badge identity
    //    non-degenerate by construction.
    let partner_wallet_key = ctx.accounts.partner_wallet.key();
    require!(
        partner_wallet_key != Pubkey::default(),
        CertificateError::ZeroPartnerWallet,
    );

    let clock = Clock::get()?;
    let vc    = &mut ctx.accounts.verified_consumer;

    vc.partner_wallet     = partner_wallet_key;
    vc.integration_hash   = integration_hash;
    vc.registered_at_slot = clock.slot;
    vc.registered_at_unix = clock.unix_timestamp;
    vc.state              = VerifiedConsumerState::Active as u8;
    vc.revoked_at_unix    = 0;
    vc.revoked_by         = Pubkey::default();
    vc.revoke_reason      = RevokeReason::NotRevoked as u8;
    vc.layout_version     = VerifiedConsumer::CURRENT_LAYOUT_VERSION;
    vc.bump               = ctx.bumps.verified_consumer;
    vc._reserved          = [0u8; 16];

    emit!(VerifiedConsumerRegistered {
        partner_wallet:     partner_wallet_key,
        verified_consumer:  vc.key(),
        integration_hash,
        registered_at_slot: vc.registered_at_slot,
        registered_at_unix: vc.registered_at_unix,
    });

    msg!(
        "VerifiedConsumer registered: partner={} slot={} unix={}",
        partner_wallet_key, vc.registered_at_slot, vc.registered_at_unix,
    );

    Ok(())
}
