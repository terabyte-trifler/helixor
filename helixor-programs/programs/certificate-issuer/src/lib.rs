// =============================================================================
// programs/certificate-issuer/src/lib.rs
//
// certificate-issuer — Helixor V2's second on-chain program.
//
// Doc 2 splits the Helixor protocol from one program into three:
//   - health-oracle       (registration + baseline commitment + scores)
//   - certificate-issuer  (THIS — the on-chain trust certificates)
//   - slash-authority     (Phase-3 later)
//
// Day 18 scaffolds certificate-issuer:
//   - HealthCertificate PDA — epoch-keyed (["cert", agent, epoch]), so the
//     per-epoch scoring HISTORY lives on chain, not just the latest cert.
//   - BaselineStats PDA     — per-agent (["baseline", agent]).
//   - IssuerConfig          — the singleton authority config.
//   - initialize_config / record_baseline / issue_certificate /
//     get_certificate instructions.
//
// Separate program => separate program ID. Replace the placeholder ID
// below with the deployed key when this is published to devnet.
// =============================================================================

use anchor_lang::prelude::*;

pub mod errors;
pub mod events;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("Cert1xor11111111111111111111111111111111111");

#[program]
pub mod certificate_issuer {
    use super::*;

    /// One-time: create the IssuerConfig singleton, setting the oracle
    /// authority permitted to issue certificates.
    pub fn initialize_config(
        ctx:         Context<InitializeConfig>,
        issuer_node: Pubkey,
    ) -> Result<()> {
        instructions::initialize_config::handler(ctx, issuer_node)
    }

    /// Create or rotate an agent's BaselineStats record. A certificate
    /// stamps the baseline_hash it derives from, so the baseline must be
    /// recorded before a certificate can be issued.
    pub fn record_baseline(
        ctx:                   Context<RecordBaseline>,
        agent_wallet:          Pubkey,
        baseline_hash:         [u8; 32],
        baseline_algo_version: u8,
        epoch:                 u64,
    ) -> Result<()> {
        instructions::record_baseline::handler(
            ctx, agent_wallet, baseline_hash, baseline_algo_version, epoch,
        )
    }

    /// Issue a HealthCertificate for an (agent, epoch). Write-once: the
    /// epoch-keyed PDA cannot be re-issued or mutated once created.
    pub fn issue_certificate(
        ctx:           Context<IssueCertificate>,
        epoch:         u64,
        score:         u16,
        alert_tier:    u8,
        flags:         u32,
        immediate_red: bool,
    ) -> Result<()> {
        instructions::issue_certificate::handler(
            ctx, epoch, score, alert_tier, flags, immediate_red,
        )
    }

    /// Read a HealthCertificate, surfacing its contents as a structured
    /// `CertificateRead` event. (Off-chain callers can also just fetch the
    /// PDA directly — this instruction is for CPI / transaction-shaped reads.)
    pub fn get_certificate(
        ctx:          Context<GetCertificate>,
        agent_wallet: Pubkey,
        epoch:        u64,
    ) -> Result<()> {
        instructions::get_certificate::handler(ctx, agent_wallet, epoch)
    }
}
