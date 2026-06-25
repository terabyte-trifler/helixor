// =============================================================================
// programs/certificate-issuer/src/instructions/get_certificate.rs
//
// get_certificate — the on-chain read instruction for a HealthCertificate.
//
//     seeds = ["cert", agent_pubkey, epoch]
//
// A NOTE ON "READ INSTRUCTIONS"
// -----------------------------
// On Solana the normal way to read an account is a client-side RPC fetch —
// no transaction, no fee. A certificate consumer SHOULD just fetch the
// `["cert", agent, epoch]` PDA directly.
//
// `get_certificate` exists for the callers that want a TRANSACTION-shaped,
// CPI-able read: a program calling into certificate-issuer, or a caller
// that wants the certificate surfaced as a structured event in a
// transaction log. The instruction loads the PDA — Anchor's account
// resolution already proves the certificate exists and is the right PDA —
// validates the requested (agent, epoch) matches, and emits a
// `CertificateRead` event carrying the contents.
//
// It is read-only: no account is `mut`, nothing is written.
//
// H-4 — ON-CHAIN FRESHNESS GATE (+ A HARD CONSUMER REQUIREMENT)
// -------------------------------------------------------------
// A certificate is a snapshot; a STALE cert is a security hazard for a
// downstream lender (an agent that has since gone RED still presents an old
// GREEN). On-chain freshness CANNOT be forced on a passive account read — a
// raw `getAccountInfo(["cert", agent, epoch])` fetch runs no program code.
// Therefore:
//
//   * Consumers that read the raw PDA directly MUST enforce freshness
//     themselves: reject a cert whose `issued_at` is older than their policy
//     window (see `HealthCertificate::is_fresh_at` / `MAX_AGE_SECONDS`). This
//     is a HARD requirement, not advisory — Phylanx cannot enforce it for a
//     passive read.
//   * Consumers that take the TRANSACTION-shaped `get_certificate` path get an
//     on-chain freshness gate here: pass `max_age_seconds > 0` and the
//     instruction fails with `CertificateStale` if the cert is older than
//     that window (wiring the previously-unused `is_fresh_at` into the read
//     path). Pass `max_age_seconds == 0` to disable the gate (legacy
//     behaviour — the read always succeeds if the PDA exists).
//
// M-09 — CANONICAL-PDA BIND ON THE EVENT
// --------------------------------------
// The audit flagged the pre-M-09 event as informational only: a downstream
// indexer reading `CertificateRead { agent_wallet, epoch, score, … }` had
// no way to PROVE the event came from the canonical
// `["cert", agent_wallet, epoch_le]` PDA. The Anchor `seeds=` constraint
// validates this on chain at resolution time — but a future refactor that
// silently drops or relaxes the constraint, or a future ix that emits the
// same event shape from a non-canonical account, would have fooled every
// consumer at runtime.
//
// M-09 closes the gap with two reinforcing guards:
//   (1) The handler explicitly recomputes the canonical PDA via
//       `Pubkey::create_program_address(["cert", agent, epoch_le, bump])`
//       and `require_keys_eq!`s it against the supplied account. If a
//       future refactor breaks the `seeds=` invariant, the explicit
//       check still fails closed with `CertificatePdaMismatch` (6130).
//   (2) The emitted `CertificateRead` event now carries `certificate`
//       (the canonical PDA pubkey) and `program_id`. A downstream indexer
//       reading ONLY the event payload can independently call
//       `find_program_address(["cert", agent_wallet, epoch_le], program_id)`
//       and verify the result equals `certificate` — no trust in the
//       transaction's program-id slot, no trust in cluster discipline.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::CertificateRead;
use crate::state::HealthCertificate;

#[derive(Accounts)]
#[instruction(agent_wallet: Pubkey, epoch: u64, max_age_seconds: i64)]
pub struct GetCertificate<'info> {
    /// The certificate PDA being read. Anchor's seed resolution proves it
    /// is exactly the ["cert", agent_wallet, epoch] account — a non-existent
    /// certificate makes the instruction fail at account resolution, which
    /// is the correct "not found" signal. M-09's handler-side recompute is
    /// defence in depth so a future refactor that relaxes this constraint
    /// still fails closed.
    #[account(
        seeds = [
            HealthCertificate::SEED_PREFIX,
            agent_wallet.as_ref(),
            &epoch.to_le_bytes(),
        ],
        bump = certificate.bump,
    )]
    pub certificate: Account<'info, HealthCertificate>,
}

pub fn handler(
    ctx:             Context<GetCertificate>,
    agent_wallet:    Pubkey,
    epoch:           u64,
    // H-4: optional on-chain freshness gate. 0 disables the check (the cert
    // is returned as long as the PDA exists — the legacy behaviour); a
    // positive value requires `issued_at` to be within `max_age_seconds` of
    // the current Clock, else `CertificateStale`.
    max_age_seconds: i64,
) -> Result<()> {
    let cert = &ctx.accounts.certificate;

    // ── H-4: freshness gate (opt-in via max_age_seconds > 0) ────────────────
    if max_age_seconds > 0 {
        let now = Clock::get()?.unix_timestamp;
        require!(
            cert.is_fresh_at(now, max_age_seconds),
            CertificateError::CertificateStale,
        );
    }

    // ── M-09: explicit canonical-PDA recompute ─────────────────────────────
    // Anchor's `seeds=` constraint already validates this, but recomputing
    // here means the canonical-PDA invariant is documented in the source
    // AND survives a refactor that accidentally drops the constraint.
    // `create_program_address` is the deterministic form — given the same
    // (seeds, bump, program_id) it returns the same address, so we don't
    // pay the `find_program_address` bump search cost on a read path.
    let canonical_pda = Pubkey::create_program_address(
        &[
            HealthCertificate::SEED_PREFIX,
            agent_wallet.as_ref(),
            &epoch.to_le_bytes(),
            &[cert.bump],
        ],
        ctx.program_id,
    )
    .map_err(|_| error!(CertificateError::CertificatePdaMismatch))?;

    require_keys_eq!(
        canonical_pda,
        ctx.accounts.certificate.key(),
        CertificateError::CertificatePdaMismatch,
    );

    // Surface the certificate as a structured event. The canonical PDA and
    // emitting program ID are pinned in-payload so an off-chain consumer
    // can re-derive `find_program_address([SEED_PREFIX, agent_wallet,
    // epoch_le], program_id)` and verify it equals `certificate` without
    // trusting anything outside the event itself (M-09).
    emit!(CertificateRead {
        certificate:   canonical_pda,
        program_id:    *ctx.program_id,
        agent_wallet:  cert.agent_wallet,
        epoch:         cert.epoch,
        score:         cert.score,
        alert_tier:    cert.alert_tier,
        flags:         cert.flags,
        immediate_red: cert.immediate_red,
        issued_at:     cert.issued_at,
    });

    msg!(
        "certificate read: agent={} epoch={} score={} tier={} issued_at={}",
        cert.agent_wallet, cert.epoch, cert.score,
        cert.alert_tier, cert.issued_at,
    );
    Ok(())
}
