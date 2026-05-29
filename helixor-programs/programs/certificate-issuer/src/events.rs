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
///
/// AW-03: carries the `baseline_commit_nonce` so indexers can derive the
/// on-chain `BaselineDataAccount` PDA (seeds `["baseline_data", agent,
/// nonce_le]`) without re-reading the BaselineStats account afterwards
/// (which may have already rotated to a newer nonce).
#[event]
pub struct BaselineRecorded {
    pub agent_wallet:          Pubkey,
    pub baseline_algo_version: u8,
    pub epoch_recorded:        u64,
    pub recorder:              Pubkey,
    pub recorded_at:           i64,
    pub baseline_commit_nonce: u64,
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

/// AW-01-EXT.6: emitted when `challenge_certificate` UPHOLDS a challenge —
/// the cert's slot anchor was provably wrong. Downstream consumers should
/// treat the cert as REPUDIATED. The slash-authority program reads this
/// event (off-chain plumbing) to slash the cert-signing cluster.
#[event]
pub struct CertificateRepudiated {
    /// The cert PDA — for cheap off-chain lookup.
    pub certificate:        Pubkey,
    pub agent_wallet:       Pubkey,
    pub epoch:              u64,
    pub challenger:         Pubkey,
    /// The cluster's pinned anchor (now provably wrong).
    pub cluster_anchor_slot: u64,
    pub cluster_anchor_hash: [u8; 32],
    /// The challenger's attested ground-truth hash.
    pub true_block_hash:    [u8; 32],
    /// How many distinct attester signatures the handler counted.
    pub attester_count:     u8,
    pub filed_at:           i64,
}

/// AW-01-EXT.6: emitted when `challenge_certificate` REJECTS a challenge —
/// the challenger's `true_block_hash` equalled the cert's
/// `slot_anchor_hash`, meaning the cert is provably honest at the slot-
/// anchor layer. The challenger's stake (rent on the ChallengeRecord
/// PDA) is consumed — this is the spam-deterrence cost.
#[event]
pub struct ChallengeRejected {
    pub certificate:        Pubkey,
    pub agent_wallet:       Pubkey,
    pub epoch:              u64,
    pub challenger:         Pubkey,
    pub claimed_block_hash: [u8; 32],
    pub filed_at:           i64,
}

/// DBP-2: emitted when a partner mints the VerifiedConsumer badge via
/// `register_verified_consumer`. Downstream indexers / leaderboards watch
/// this event to surface the new Verified Integrator without having to poll
/// the full PDA set.
#[event]
pub struct VerifiedConsumerRegistered {
    /// The partner's pubkey — denormalised PDA seed.
    pub partner_wallet:     Pubkey,
    /// The PDA account address for cheap lookup.
    pub verified_consumer:  Pubkey,
    /// The DBP-1 canonical manifest hash this badge attests to.
    pub integration_hash:   [u8; 32],
    /// Solana slot at registration time.
    pub registered_at_slot: u64,
    /// Unix seconds at registration time.
    pub registered_at_unix: i64,
}

/// M-06: emitted when `rotate_cluster_keys` completes. Carries the
/// before/after snapshot versions so off-chain verifiers replaying
/// historical certs know which snapshot to fetch (paired with the cert's
/// `issuer_config_version` stamp from M-05). The new cluster set itself
/// is NOT in the event payload — readers fetch the post-rotation
/// `IssuerConfig` directly; the event is just the audit trail of WHEN
/// the rotation happened and by whom.
#[event]
pub struct ClusterKeysRotated {
    /// The admin authority that effected the rotation. Must equal
    /// `issuer_config.authority` at the time of the call.
    pub authority:          Pubkey,
    /// The config_version BEFORE the rotation (the snapshot being retired).
    pub old_config_version: u32,
    /// The config_version AFTER the rotation (= old + 1).
    pub new_config_version: u32,
    /// The new cluster size — operationally useful so an off-chain
    /// indexer can flag accidental shrink/grow without parsing the
    /// post-rotation account.
    pub new_cluster_size:   u8,
    /// The new threshold.
    pub new_threshold:      u8,
    /// Unix seconds at rotation time.
    pub rotated_at_unix:    i64,
}

/// DBP-2: emitted when a VerifiedConsumer badge is revoked, via either a
/// partner self-revoke (`PartnerSelfRevoke`) or an admin revoke
/// (`AdminBadFaith` / `AdminTerminated`). Downstream lending contracts that
/// gate on `state == Active` need this event to flip their internal cache
/// promptly without polling.
#[event]
pub struct VerifiedConsumerRevoked {
    pub partner_wallet:    Pubkey,
    pub verified_consumer: Pubkey,
    /// The signer who effected the revoke — either `partner_wallet` (self-
    /// revoke) or the issuer_config authority (admin).
    pub revoked_by:        Pubkey,
    /// The reason byte — `RevokeReason::from_u8` to decode.
    pub revoke_reason:     u8,
    pub revoked_at_unix:   i64,
}
