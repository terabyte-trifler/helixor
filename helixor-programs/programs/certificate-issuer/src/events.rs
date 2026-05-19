// =============================================================================
// programs/certificate-issuer/src/events.rs
//
// Anchor events emitted by the certificate-issuer program. The off-chain
// indexer captures these so dashboards and the alert pipeline see a new
// certificate the moment it lands, without polling every cert PDA.
// =============================================================================

use anchor_lang::prelude::*;

/// Emitted when a HealthCertificate is issued for an (agent, epoch).
#[event]
pub struct CertificateIssued {
    /// The agent the certificate attests to.
    pub agent_wallet:  Pubkey,
    /// The epoch the certificate covers.
    pub epoch:         u64,
    /// The composite trust score, 0..=1000.
    pub score:         u16,
    /// The alert tier code (0 GREEN, 1 YELLOW, 2 RED).
    pub alert_tier:    u8,
    /// The aggregated detection flag bits.
    pub flags:         u32,
    /// Whether the IMMEDIATE_RED fast-path was tripped.
    pub immediate_red: bool,
    /// The oracle authority that issued the certificate.
    pub issuer:        Pubkey,
    /// Unix seconds at issuance.
    pub issued_at:     i64,
}

/// Emitted when a BaselineStats record is created or updated for an agent.
#[event]
pub struct BaselineRecorded {
    pub agent_wallet:          Pubkey,
    pub baseline_algo_version: u8,
    pub epoch_recorded:        u64,
    pub recorder:              Pubkey,
    pub recorded_at:           i64,
}

/// Emitted by `get_certificate` — the on-chain read instruction surfaces a
/// certificate's contents into the transaction log, so an off-chain caller
/// that prefers a transaction-shaped read (rather than a raw account fetch)
/// gets a structured event back.
#[event]
pub struct CertificateRead {
    pub agent_wallet: Pubkey,
    pub epoch:        u64,
    pub score:        u16,
    pub alert_tier:   u8,
    pub flags:        u32,
    pub immediate_red: bool,
    pub issued_at:    i64,
}
