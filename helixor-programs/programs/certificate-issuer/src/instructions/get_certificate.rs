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
// =============================================================================

use anchor_lang::prelude::*;

use crate::events::CertificateRead;
use crate::state::HealthCertificate;

#[derive(Accounts)]
#[instruction(agent_wallet: Pubkey, epoch: u64)]
pub struct GetCertificate<'info> {
    /// The certificate PDA being read. Anchor's seed resolution proves it
    /// is exactly the ["cert", agent_wallet, epoch] account — a non-existent
    /// certificate makes the instruction fail at account resolution, which
    /// is the correct "not found" signal.
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
    ctx:          Context<GetCertificate>,
    _agent_wallet: Pubkey,
    _epoch:       u64,
) -> Result<()> {
    let cert = &ctx.accounts.certificate;

    // Surface the certificate as a structured event. The PDA seed
    // constraint already guarantees `cert` is the certificate for the
    // requested (agent_wallet, epoch) — Anchor would have failed
    // resolution otherwise — so no extra equality check is needed.
    emit!(CertificateRead {
        agent_wallet:  cert.agent_wallet,
        epoch:         cert.epoch,
        score:         cert.score,
        alert_tier:    cert.alert_tier,
        flags:         cert.flags,
        confidence:    cert.confidence,
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
