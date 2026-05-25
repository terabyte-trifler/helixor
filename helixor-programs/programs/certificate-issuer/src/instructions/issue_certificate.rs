// =============================================================================
// programs/certificate-issuer/src/instructions/issue_certificate.rs
//
// issue_certificate — write a HealthCertificate for an (agent, epoch).
//
//     seeds = ["cert", agent_pubkey, epoch]
//
// The certificate PDA is created with `init`. Because the epoch is in the
// seed, every epoch has its OWN account — and because `init` fails if the
// account already exists, a certificate is WRITE-ONCE: it can never be
// re-issued or mutated for an epoch once written. That immutability is the
// guarantee a certificate is meant to provide.
//
// AUTHORITY: only the configured issuer_node (from IssuerConfig) may issue.
//
// PRECONDITION: the agent must have a recorded BaselineStats — a certificate
// stamps the baseline_hash it derives from, so the baseline must exist.
//
// VALIDATION: the score must be in range, the alert tier must be a valid
// code, and the (score, alert) pair must be CONSISTENT — a GREEN alert with
// a score of 100 would be a malformed certificate and is rejected.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::CertificateIssued;
use crate::state::{
    AlertTier, BaselineStats, HealthCertificate, IssuerConfig,
};

/// The score thresholds the on-chain consistency check uses. These mirror
/// the off-chain scoring thresholds (scoring/composite.py: GREEN >= 700,
/// YELLOW >= 400). Kept as program constants so a certificate's stored
/// (score, alert) pair is verified, not trusted.
pub const GREEN_THRESHOLD:  u16 = 700;
pub const YELLOW_THRESHOLD: u16 = 400;

#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct IssueCertificate<'info> {
    /// The agent's baseline record. Must exist (record_baseline first).
    /// Declared first because the certificate PDA's seeds reference
    /// `baseline_stats.agent_wallet` — Anchor resolves accounts top-down.
    #[account(
        seeds = [
            BaselineStats::SEED_PREFIX,
            baseline_stats.agent_wallet.as_ref(),
        ],
        bump = baseline_stats.bump,
    )]
    pub baseline_stats: Account<'info, BaselineStats>,

    /// The certificate PDA for this (agent, epoch). Created here; `init`
    /// makes the certificate write-once — a second issue for the same
    /// (agent, epoch) fails because the account already exists.
    #[account(
        init,
        payer = issuer,
        space = HealthCertificate::SPACE,
        seeds = [
            HealthCertificate::SEED_PREFIX,
            baseline_stats.agent_wallet.as_ref(),
            &epoch.to_le_bytes(),
        ],
        bump,
    )]
    pub certificate: Account<'info, HealthCertificate>,

    /// IssuerConfig — supplies the cluster's signing keys + threshold.
    /// The cluster signatures are what authorise the write; the signer
    /// below is only the fee/rent payer (anyone may submit as long as the
    /// threshold signatures are present).
    #[account(
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The submitter — pays rent + tx fee. Day 27 NO LONGER gates on this
    /// being a fixed authority; the cluster THRESHOLD SIGNATURES gate the
    /// write instead. Anyone may submit the ix as long as the tx carries
    /// `issuer_config.threshold` valid cluster-key Ed25519 precompile
    /// signatures over the canonical cert payload.
    #[account(mut)]
    pub issuer: Signer<'info>,

    /// CHECK: the Instructions sysvar — read inside the handler to find
    /// the Ed25519 precompile instructions that carry the cluster
    /// signatures. The handler verifies this is the right sysvar pubkey.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:           Context<IssueCertificate>,
    epoch:         u64,
    score:         u16,
    alert_tier:    u8,
    flags:         u32,
    immediate_red: bool,
) -> Result<()> {
    // ── Validate the inputs ─────────────────────────────────────────────────
    require!(epoch > 0, CertificateError::ZeroEpoch);
    require!(
        score <= HealthCertificate::MAX_SCORE,
        CertificateError::ScoreOutOfRange,
    );

    let tier = AlertTier::from_u8(alert_tier)
        .ok_or(CertificateError::InvalidAlertTier)?;

    // The baseline must be real — record_baseline must have run, and it
    // refuses a zero hash, so a zero hash here means no baseline.
    require!(
        ctx.accounts.baseline_stats.baseline_hash != [0u8; 32],
        CertificateError::BaselineNotRecorded,
    );

    // ── Verify the (score, alert) pair is consistent ────────────────────────
    // A certificate carries both the numeric score and the categorical
    // tier; storing an inconsistent pair would be a malformed attestation.
    // The IMMEDIATE_RED fast-path is the one exception: it forces RED
    // regardless of score, so a RED+high-score pair IS valid when
    // immediate_red is set.
    validate_score_alert(score, tier, immediate_red)?;

    // ── DAY 27: verify the THRESHOLD SIGNATURES from the cluster ────────────
    // The cert payload (the canonical digest of agent/epoch/score/tier/
    // flags/baseline_hash/immediate_red) MUST have been signed by at least `threshold`
    // distinct cluster keys, via Ed25519 precompile instructions in this
    // same transaction. Below threshold -> InsufficientSignatures -> ix
    // fails. This is the on-chain enforcement of 3-of-5 (or whatever the
    // configured threshold is).
    let digest = crate::signing::cert_payload_digest(
        &ctx.accounts.baseline_stats.agent_wallet,
        epoch, score, alert_tier, flags,
        &ctx.accounts.baseline_stats.baseline_hash,
        immediate_red,
    );
    let valid_signers = crate::signing::verify_threshold_signatures(
        &digest,
        &ctx.accounts.issuer_config,
        &ctx.accounts.instructions_sysvar.to_account_info(),
    )?;

    // ── Write the certificate ───────────────────────────────────────────────
    let clock = Clock::get()?;
    let cert = &mut ctx.accounts.certificate;

    cert.agent_wallet   = ctx.accounts.baseline_stats.agent_wallet;
    cert.epoch          = epoch;
    cert.score          = score;
    cert.alert_tier     = tier.as_u8();
    cert.flags          = flags;
    cert.issued_at      = clock.unix_timestamp;
    cert.issuer         = ctx.accounts.issuer.key();
    cert.baseline_hash  = ctx.accounts.baseline_stats.baseline_hash;
    cert.immediate_red  = immediate_red;
    cert.bump           = ctx.bumps.certificate;
    cert.layout_version = HealthCertificate::CURRENT_LAYOUT_VERSION;

    emit!(CertificateIssued {
        agent_wallet:  cert.agent_wallet,
        epoch,
        score,
        alert_tier:    cert.alert_tier,
        flags,
        immediate_red,
        issuer:        cert.issuer,
        issued_at:     cert.issued_at,
    });

    msg!(
        "certificate issued: agent={} epoch={} score={} tier={:?} signers={}/{}",
        cert.agent_wallet, epoch, score, tier,
        valid_signers, ctx.accounts.issuer_config.threshold,
    );
    Ok(())
}

/// Verify a (score, alert_tier) pair is internally consistent.
///
/// Pure — extracted so it is unit-testable without a runtime (see
/// tests/certificate_logic.rs).
///
///   GREEN  needs score >= GREEN_THRESHOLD
///   YELLOW needs YELLOW_THRESHOLD <= score < GREEN_THRESHOLD
///   RED    needs score < YELLOW_THRESHOLD
///
/// EXCEPTION: when `immediate_red` is set, the security fast-path forced a
/// RED tier irrespective of the numeric score — so RED is valid at ANY
/// score. immediate_red therefore only ever RELAXES the check (toward RED).
pub fn validate_score_alert(
    score:         u16,
    tier:          AlertTier,
    immediate_red: bool,
) -> Result<()> {
    // The fast-path forced RED — any score is consistent with that.
    if immediate_red {
        require!(
            tier == AlertTier::Red,
            CertificateError::InconsistentScoreAlert,
        );
        return Ok(());
    }

    let consistent = match tier {
        AlertTier::Green  => score >= GREEN_THRESHOLD,
        AlertTier::Yellow => (YELLOW_THRESHOLD..GREEN_THRESHOLD).contains(&score),
        AlertTier::Red    => score < YELLOW_THRESHOLD,
    };
    require!(consistent, CertificateError::InconsistentScoreAlert);
    Ok(())
}
