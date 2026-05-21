// =============================================================================
// consumer-example — Reference DeFi Protocol Integration
//
// Day 19 changed Helixor's on-chain source of truth: the old MVP
// `get_health` return-data CPI was replaced by an epoch-keyed
// HealthCertificate owned by certificate-issuer.
//
// A protocol integration does not need to CPI just to read a score. It passes
// the current EpochState plus the current-epoch HealthCertificate, Anchor
// verifies the PDAs, and the protocol applies its own risk policy locally.
// =============================================================================

#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

use certificate_issuer::state::HealthCertificate;
use health_oracle::state::EpochState;

declare_id!("94Gg1gnTZex9mFAJZHB3kLbTiJYYEcRvGTgkArftHJmu");

/// Minimum score this protocol requires to allow a protected action.
/// Real protocols would make this configurable (e.g. governance-controlled).
pub const MIN_TRUST_SCORE: u16 = 600;

/// A certificate older than this is stale for the consumer protocol.
pub const MAX_CERT_AGE_SECONDS: i64 = 48 * 60 * 60;

#[program]
pub mod consumer_example {
    use super::*;

    /// Demonstrates the Day-19+ integration flow:
    ///   1. Anchor verifies the current epoch and certificate PDAs.
    ///   2. The protocol reads the immutable HealthCertificate.
    ///   3. The protocol applies its own policy.
    ///   4. If the policy passes, the protected action proceeds.
    pub fn do_protected_action(ctx: Context<DoProtectedAction>) -> Result<()> {
        let cert = &ctx.accounts.certificate;
        let now = Clock::get()?.unix_timestamp;

        require!(
            cert.agent_wallet == ctx.accounts.agent_wallet.key(),
            ConsumerError::CertificateAgentMismatch,
        );
        require!(
            cert.epoch == ctx.accounts.epoch_state.current_epoch,
            ConsumerError::CertificateNotCurrent,
        );
        require!(
            now.saturating_sub(cert.issued_at) <= MAX_CERT_AGE_SECONDS,
            ConsumerError::ScoreTooStale,
        );
        require!(
            !cert.immediate_red,
            ConsumerError::ImmediateRed,
        );
        require!(
            cert.score >= MIN_TRUST_SCORE,
            ConsumerError::ScoreBelowMinimum,
        );

        msg!(
            "consumer-example: action APPROVED — agent={} epoch={} score={} tier={}",
            cert.agent_wallet,
            cert.epoch,
            cert.score,
            cert.alert_tier,
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct DoProtectedAction<'info> {
    /// The user/agent triggering the protected action.
    pub caller: Signer<'info>,

    /// The agent whose score gates this action.
    /// CHECK: used as a PDA seed and compared against certificate.agent_wallet.
    pub agent_wallet: UncheckedAccount<'info>,

    /// Helixor's current epoch account, owned by health-oracle.
    #[account(
        seeds = [EpochState::SEED],
        bump = epoch_state.bump,
        seeds::program = health_oracle::ID,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// The current-epoch certificate, owned by certificate-issuer.
    #[account(
        seeds = [
            HealthCertificate::SEED_PREFIX,
            agent_wallet.key().as_ref(),
            &epoch_state.current_epoch.to_le_bytes(),
        ],
        bump = certificate.bump,
        seeds::program = certificate_issuer::ID,
    )]
    pub certificate: Account<'info, HealthCertificate>,
}

#[error_code]
pub enum ConsumerError {
    #[msg("Trust score is below the protocol minimum (600).")]
    ScoreBelowMinimum,
    #[msg("Trust certificate is stale (>48h). Aborting for safety.")]
    ScoreTooStale,
    #[msg("Certificate was issued for a different agent.")]
    CertificateAgentMismatch,
    #[msg("Certificate is not for the current Helixor epoch.")]
    CertificateNotCurrent,
    #[msg("Agent has an immediate-red security flag.")]
    ImmediateRed,
}
