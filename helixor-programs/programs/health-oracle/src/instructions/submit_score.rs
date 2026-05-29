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
use anchor_lang::system_program::{self, Transfer};

use crate::errors::HelixorError;
use crate::events::{ScoreSubmitted, SubmitScoreEscrowFunded};
use crate::slot_gate::verify_slot_anchor;
use crate::state::{
    AgentRegistration, EpochState, OracleConfig, SubmitScoreEscrow,
    MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS,
};

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

    /// M-13: the anti-griefing rent-escrow PDA for this (agent, epoch).
    /// `init` makes it write-once for the pairing — a repeat submission
    /// for the same (agent, epoch) fails here the same way the cert
    /// account would. The oracle pays the rent-exempt minimum at init
    /// and ADDITIONALLY transfers `MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS`
    /// from itself to this PDA inside the handler — that extra deposit
    /// is the per-submission economic floor the audit asked for.
    #[account(
        init,
        payer = oracle,
        space = SubmitScoreEscrow::SPACE,
        seeds = [
            SubmitScoreEscrow::SEED_PREFIX,
            agent_registration.agent_wallet.as_ref(),
            &epoch.to_le_bytes(),
        ],
        bump,
    )]
    pub submit_score_escrow: Account<'info, SubmitScoreEscrow>,

    // ── certificate-issuer accounts (passed through to the CPI) ─────────────
    /// The certificate PDA the CPI will CREATE. Derived on the
    /// certificate-issuer program with seeds ["cert", agent, epoch].
    /// CHECK: validated by certificate-issuer's own `init` + seed constraints
    /// inside the CPI — Anchor cannot type it here because it is owned by
    /// the callee program.
    #[account(mut)]
    pub certificate: UncheckedAccount<'info>,

    /// AW-04: the ScoreComponentsAccount PDA the CPI will CREATE on the
    /// certificate-issuer program with seeds ["score_components", agent,
    /// epoch]. Validated by the callee's own `init` + seed constraints.
    /// CHECK: see `certificate` above — owned by the callee program.
    #[account(mut)]
    pub score_components: UncheckedAccount<'info>,

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
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    /// CHECK: the SlotHashes sysvar — passed through to the
    /// certificate-issuer CPI so it can verify the AW-01-EXT slot anchor.
    /// `address` pins the expected sysvar pubkey at the Anchor layer;
    /// the callee re-checks it inside `verify_slot_anchor`.
    #[account(address = solana_program::sysvar::slot_hashes::ID)]
    pub slot_hashes_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:                      Context<SubmitScore>,
    epoch:                    u64,
    score:                    u16,
    alert_tier:               u8,
    flags:                    u32,
    immediate_red:            bool,
    // AW-01: cluster-majority input-provenance commitment. Passes through
    // verbatim into the certificate-issuer CPI; the cert-issuer enforces
    // the non-zero gate.
    input_commitment:         [u8; 32],
    // AW-01-EXT: Solana slot-anchor `(slot, block_hash)` the cluster
    // pinned at scoring time. Forwarded to the CPI; the cert-issuer
    // verifies the pair against the SlotHashes sysvar and rejects a
    // zero anchor.
    slot_anchor_slot:         u64,
    slot_anchor_hash:         [u8; 32],
    // AW-04: scoring-kernel bundle hash + raw canonical components
    // payload. Forwarded to the CPI; the cert-issuer hashes the payload
    // on chain (NEVER trusts a caller-supplied digest), folds both
    // hashes into the cert digest, and writes the payload bytes into
    // the paired ScoreComponentsAccount.
    scoring_code_hash:        [u8; 32],
    score_components_payload: Vec<u8>,
) -> Result<()> {
    // ── 2. precondition checks ──────────────────────────────────────────────
    require!(
        score <= HealthCertificate::MAX_SCORE,
        HelixorError::ScoreOutOfRange,
    );

    // ── 3. epoch check — the score must be for the CURRENT epoch ────────────
    require!(
        epoch == ctx.accounts.epoch_state.current_epoch,
        HelixorError::EpochMismatch,
    );

    // ── 3a. M-04 — SECONDARY oracle-side slot-anchor verification ───────────
    // The certificate-issuer ALSO verifies the slot anchor against the
    // SlotHashes sysvar inside its CPI; that primary check is unchanged.
    // The audit asked for a defence-in-depth secondary gate ON the oracle
    // side so a regression / bypass / alternative cert-write path cannot
    // let an un-anchored score reach the certificate. Two independent
    // implementations of the same invariant — see slot_gate.rs.
    verify_slot_anchor(
        &ctx.accounts.slot_hashes_sysvar.to_account_info(),
        slot_anchor_slot,
        &slot_anchor_hash,
    )?;

    // ── 3b. M-13 — fund the per-submission anti-griefing rent escrow ───────
    // The `init` constraint above already paid the rent-exempt minimum
    // for the SubmitScoreEscrow PDA from the oracle. M-13's signal floor
    // is an ADDITIONAL deposit on top of rent: a system::transfer of
    // `MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS` from oracle to the PDA. This
    // makes the per-submission cost three orders of magnitude above the
    // base tx fee, so a runaway oracle script can no longer spam at
    // ~5_000 lamports per call.
    //
    // No refund / drain instruction is provided in M-13 — the floor is
    // the cost. A future M-XX may introduce a conditional refund or a
    // challenge-driven slash; the M-13 contract is to LOCK the lamports.
    let escrow_ai = ctx.accounts.submit_score_escrow.to_account_info();
    let escrow_balance_before_deposit = escrow_ai.lamports();
    let deposit_lamports = MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS;
    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.oracle.to_account_info(),
                to:   escrow_ai.clone(),
            },
        ),
        deposit_lamports,
    )?;

    // Defence-in-depth balance check: the live escrow balance MUST be
    // at least the rent-exempt minimum (init guarantees) PLUS the floor.
    // Re-read from the AccountInfo so a future refactor that mistakenly
    // sends the transfer elsewhere fails this gate.
    let escrow_balance_after_deposit = escrow_ai.lamports();
    let floor_required = escrow_balance_before_deposit
        .checked_add(deposit_lamports)
        .ok_or(HelixorError::SubmitEscrowBelowFloor)?;
    require!(
        escrow_balance_after_deposit >= floor_required,
        HelixorError::SubmitEscrowBelowFloor,
    );

    // Populate the escrow account body — the lamports themselves ARE the
    // floor; the body is for forensic attribution (which oracle funded
    // this escrow, when, and what (agent, epoch) it belongs to).
    let clock_now = Clock::get()?;
    {
        let escrow = &mut ctx.accounts.submit_score_escrow;
        escrow.agent_wallet       = ctx.accounts.agent_registration.agent_wallet;
        escrow.epoch              = epoch;
        escrow.oracle             = ctx.accounts.oracle.key();
        escrow.deposited_at       = clock_now.unix_timestamp;
        escrow.deposited_lamports = deposit_lamports;
        escrow.bump               = ctx.bumps.submit_score_escrow;
        escrow.layout_version     = SubmitScoreEscrow::CURRENT_LAYOUT_VERSION;
    }

    emit!(SubmitScoreEscrowFunded {
        escrow:               ctx.accounts.submit_score_escrow.key(),
        agent_wallet:         ctx.accounts.agent_registration.agent_wallet,
        epoch,
        oracle:               ctx.accounts.oracle.key(),
        deposited_lamports:   deposit_lamports,
        escrow_balance_after: escrow_balance_after_deposit,
        funded_at:            clock_now.unix_timestamp,
    });

    // ── 4. CPI into certificate-issuer ──────────────────────────────────────
    // Build the typed CPI context. The oracle signer carries through — the
    // certificate-issuer's issue_certificate verifies the issuer against
    // ITS IssuerConfig, so the oracle node must also be the issuer node
    // (configured once at deployment).
    let cpi_accounts = IssueCertificateAccounts {
        baseline_stats:      ctx.accounts.baseline_stats.to_account_info(),
        certificate:         ctx.accounts.certificate.to_account_info(),
        score_components:    ctx.accounts.score_components.to_account_info(),
        issuer_config:       ctx.accounts.issuer_config.to_account_info(),
        issuer:              ctx.accounts.oracle.to_account_info(),
        instructions_sysvar: ctx.accounts.instructions_sysvar.to_account_info(),
        slot_hashes_sysvar:  ctx.accounts.slot_hashes_sysvar.to_account_info(),
        system_program:      ctx.accounts.system_program.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(
        ctx.accounts.certificate_issuer_program.key(),
        cpi_accounts,
    );

    // This CALL is the certificate write. If it reverts, submit_score
    // reverts — the score submission is all-or-nothing.
    cpi_issue_certificate(
        cpi_ctx, epoch, score, alert_tier, flags, immediate_red,
        input_commitment,          // AW-01: pass through verbatim
        slot_anchor_slot,          // AW-01-EXT: forwarded to sysvar check
        slot_anchor_hash,
        scoring_code_hash,         // AW-04: scoring-kernel bundle hash
        score_components_payload,  // AW-04: raw canonical components payload
    )?;

    // ── emit the oracle-side event ──────────────────────────────────────────
    // Reuse `clock_now` captured during the M-13 escrow funding above —
    // the two events should bear the same unix timestamp anyway (they are
    // emitted from the same handler invocation), and dropping the
    // duplicate `Clock::get()` keeps the handler tight.
    emit!(ScoreSubmitted {
        agent_wallet:  ctx.accounts.agent_registration.agent_wallet,
        epoch,
        score,
        alert_tier,
        flags,
        immediate_red,
        oracle:        ctx.accounts.oracle.key(),
        submitted_at:  clock_now.unix_timestamp,
    });

    msg!(
        "score submitted via CPI: agent={} epoch={} score={}",
        ctx.accounts.agent_registration.agent_wallet, epoch, score,
    );
    Ok(())
}
