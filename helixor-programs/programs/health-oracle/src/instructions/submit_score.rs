// =============================================================================
// programs/health-oracle/src/instructions/submit_score.rs
//
// submit_score — the oracle submits an agent's epoch score, and this
// instruction writes the on-chain certificate by CROSS-PROGRAM INVOCATION
// into the certificate-issuer program.
//
// THE DAY-19 WIRING
// -----------------
// Doc 2 splits certificate-writing into its own program. So health-oracle
// does NOT write the certificate itself — it CPI-calls
// certificate_issuer::issue_certificate. health-oracle owns the score
// submission + authority + epoch; certificate-issuer owns the certificate
// account. One oracle transaction, two programs, one atomic result.
//
// FLOW
//   1. authority check      — signer is the configured oracle node
//   2. precondition checks  — agent active, baseline committed, score sane
//   3. epoch check          — the supplied epoch == the current on-chain epoch
//   4. CPI                  — issue_certificate on certificate-issuer, which
//                             creates the ["cert", agent, epoch] PDA
//
// Because step 4 is a CPI, the whole thing is ATOMIC: if issue_certificate
// reverts (e.g. the certificate already exists for this epoch), the entire
// submit_score transaction reverts. The oracle cannot half-submit a score.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::HelixorError;
use crate::events::ScoreSubmitted;
use crate::state::{AgentRegistration, EpochState, OracleConfig};

// The certificate-issuer program — pulled in as a CPI dependency. Anchor
// generates the `cpi` module (the typed CPI builders) and re-exports the
// program's accounts + the program struct.
use certificate_issuer::cpi::accounts::IssueCertificate as IssueCertificateAccounts;
use certificate_issuer::cpi::issue_certificate as cpi_issue_certificate;
use certificate_issuer::program::CertificateIssuer;
use certificate_issuer::state::{BaselineStats, HealthCertificate, IssuerConfig};

#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct SubmitScore<'info> {
    // ── health-oracle's own accounts ────────────────────────────────────────
    /// The agent being scored. Must be active and have a committed baseline.
    #[account(
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump  = agent_registration.bump,
        constraint = agent_registration.active           @ HelixorError::AgentInactive,
        constraint = agent_registration.baseline_committed
            @ HelixorError::BaselineNotCommitted,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    /// OracleConfig — the source of truth for the oracle authority.
    #[account(
        seeds = [b"oracle_config"],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The epoch counter. The supplied `epoch` must equal current_epoch.
    #[account(
        seeds = [EpochState::SEED],
        bump  = epoch_state.bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// The oracle node — signs the score submission AND the CPI.
    #[account(
        mut,
        constraint = oracle.key() == oracle_config.oracle_node
            @ HelixorError::NotOracleAuthority,
    )]
    pub oracle: Signer<'info>,

    // ── certificate-issuer accounts (passed through to the CPI) ─────────────
    /// The certificate PDA the CPI will CREATE. Derived on the
    /// certificate-issuer program with seeds ["cert", agent, epoch].
    /// CHECK: validated by certificate-issuer's own `init` + seed constraints
    /// inside the CPI — Anchor cannot type it here because it is owned by
    /// the callee program.
    #[account(mut)]
    pub certificate: UncheckedAccount<'info>,

    /// The agent's BaselineStats on the certificate-issuer program.
    pub baseline_stats: Account<'info, BaselineStats>,

    /// The certificate-issuer's IssuerConfig.
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The certificate-issuer program — the CPI target.
    pub certificate_issuer_program: Program<'info, CertificateIssuer>,

    /// CHECK: the Instructions sysvar — passed through to the CPI so the
    /// certificate-issuer's threshold-signature verification (Day 27) can
    /// read the Ed25519 precompile instructions attached to THIS outer
    /// transaction. The cluster-direct path is the primary cert write
    /// path in Phase 4; this CPI route is retained for backward
    /// compatibility and only succeeds when the same outer tx carries the
    /// required threshold signatures.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:           Context<SubmitScore>,
    epoch:         u64,
    score:         u16,
    alert_tier:    u8,
    flags:         u32,
    confidence:    u16,
    immediate_red: bool,
) -> Result<()> {
    // ── 2. precondition checks ──────────────────────────────────────────────
    require!(
        score <= HealthCertificate::MAX_SCORE,
        HelixorError::ScoreOutOfRange,
    );
    require!(
        confidence <= HealthCertificate::MAX_CONFIDENCE,
        HelixorError::ConfidenceOutOfRange,
    );

    // ── 3. epoch check — the score must be for the CURRENT epoch ────────────
    require!(
        epoch == ctx.accounts.epoch_state.current_epoch,
        HelixorError::EpochMismatch,
    );

    // ── 4. CPI into certificate-issuer ──────────────────────────────────────
    // Build the typed CPI context. The oracle signer carries through — the
    // certificate-issuer's issue_certificate verifies the issuer against
    // ITS IssuerConfig, so the oracle node must also be the issuer node
    // (configured once at deployment).
    let cpi_accounts = IssueCertificateAccounts {
        baseline_stats:      ctx.accounts.baseline_stats.to_account_info(),
        certificate:         ctx.accounts.certificate.to_account_info(),
        issuer_config:       ctx.accounts.issuer_config.to_account_info(),
        issuer:              ctx.accounts.oracle.to_account_info(),
        instructions_sysvar: ctx.accounts.instructions_sysvar.to_account_info(),
        system_program:      ctx.accounts.system_program.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(
        ctx.accounts.certificate_issuer_program.to_account_info(),
        cpi_accounts,
    );

    // This CALL is the certificate write. If it reverts, submit_score
    // reverts — the score submission is all-or-nothing.
    cpi_issue_certificate(
        cpi_ctx, epoch, score, alert_tier, flags, confidence, immediate_red,
    )?;

    // ── emit the oracle-side event ──────────────────────────────────────────
    let clock = Clock::get()?;
    emit!(ScoreSubmitted {
        agent_wallet:  ctx.accounts.agent_registration.agent_wallet,
        epoch,
        score,
        alert_tier,
        flags,
        confidence,
        immediate_red,
        oracle:        ctx.accounts.oracle.key(),
        submitted_at:  clock.unix_timestamp,
    });

    msg!(
        "score submitted via CPI: agent={} epoch={} score={}",
        ctx.accounts.agent_registration.agent_wallet, epoch, score,
    );
    Ok(())
}
