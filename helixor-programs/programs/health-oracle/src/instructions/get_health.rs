// =============================================================================
// programs/health-oracle/src/instructions/get_health.rs
//
// get_health — read an agent's current trust standing.
//
// THE DAY-19 CHANGE
// -----------------
// The MVP's get_health read a single overwritten score account. V2 keys
// certificates by epoch on the certificate-issuer program, so "current
// health" is the HealthCertificate for the CURRENT epoch:
//
//     latest cert = certificate-issuer  ["cert", agent, epoch_state.current_epoch]
//
// get_health resolves that account and surfaces it as a HealthRead event.
//
// As with certificate-issuer's get_certificate, an off-chain caller can
// also just fetch the cert PDA directly — this instruction is for the
// callers that want a transaction-shaped / CPI-able read, and it is the
// on-chain equivalent of the SDK's getScore().
//
// Read-only — no account is `mut`, nothing is written.
// =============================================================================

use anchor_lang::prelude::*;

use crate::events::HealthRead;
use crate::state::EpochState;

use certificate_issuer::state::HealthCertificate;

#[derive(Accounts)]
#[instruction(agent_wallet: Pubkey)]
pub struct GetHealth<'info> {
    /// The epoch counter — tells us which epoch's certificate is "current".
    #[account(
        seeds = [EpochState::SEED],
        bump  = epoch_state.bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// The current-epoch certificate, on the certificate-issuer program.
    /// Its seeds use epoch_state.current_epoch — so this account resolves
    /// to whatever the latest issued certificate for the agent is. If no
    /// certificate has been issued for the current epoch yet, account
    /// resolution fails — the correct "no current score" signal.
    ///
    /// `seeds::program` points the derivation at the certificate-issuer
    /// program, since the PDA is owned by that program, not this one.
    #[account(
        seeds = [
            HealthCertificate::SEED_PREFIX,
            agent_wallet.as_ref(),
            &epoch_state.current_epoch.to_le_bytes(),
        ],
        bump = certificate.bump,
        seeds::program = certificate_issuer::ID,
    )]
    pub certificate: Account<'info, HealthCertificate>,
}

pub fn handler(ctx: Context<GetHealth>, agent_wallet: Pubkey) -> Result<()> {
    let cert = &ctx.accounts.certificate;

    emit!(HealthRead {
        agent_wallet,
        epoch:         cert.epoch,
        score:         cert.score,
        alert_tier:    cert.alert_tier,
        flags:         cert.flags,
        confidence:    cert.confidence,
        immediate_red: cert.immediate_red,
        issued_at:     cert.issued_at,
    });

    msg!(
        "health read: agent={} epoch={} score={} tier={}",
        agent_wallet, cert.epoch, cert.score, cert.alert_tier,
    );
    Ok(())
}
