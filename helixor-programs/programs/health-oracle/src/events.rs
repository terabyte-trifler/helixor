// =============================================================================
// programs/health-oracle/src/events.rs
//
// Anchor events emitted by commit_baseline. The off-chain indexer captures
// these into the append-only `baseline_commit_log` table — that gives us a
// full HISTORY of every commit even though the on-chain account only stores
// the latest.
// =============================================================================

use anchor_lang::prelude::*;

#[event]
pub struct BaselineCommitted {
    /// The monitored agent's wallet.
    pub agent_wallet:           Pubkey,
    /// The committer pubkey (oracle node or agent owner).
    pub committer:              Pubkey,
    /// The new committed hash.
    pub baseline_hash:          [u8; 32],
    /// Algorithm version that produced this hash.
    pub baseline_algo_version:  u8,
    /// New nonce value (= previous + 1, by the monotonicity rule).
    pub commit_nonce:           u64,
    /// Unix seconds (Clock::get().unix_timestamp).
    pub committed_at:           i64,
    /// True if this is the first commit for this agent.
    pub first_commit:           bool,
    /// "oracle" or "owner". Convenience for downstream indexers.
    pub committer_kind:         CommitterKind,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitterKind {
    Oracle,
    Owner,
}

// =============================================================================
// VULN-10: BaselineRotated — fired on every NON-FIRST commit so an agent
// owner's off-chain monitor can page on a rotation.
//
// `BaselineCommitted` is the canonical commit event; `BaselineRotated` is
// the SUPERSET-of-info event tailored to "the baseline that the network
// has been using just changed". It carries the FULL previous state so
// the monitor can show a diff without joining the indexer log.
//
// The owner detects an unexpected rotation (e.g. a compromised oracle
// node rotating to a stale-favorable hash) within seconds of the event
// landing, and uses the owner-override path on commit_baseline to
// re-rotate to the correct hash immediately (the owner path bypasses
// the oracle cooldown).
// =============================================================================

#[event]
pub struct BaselineRotated {
    pub agent_wallet:                 Pubkey,
    pub committer:                    Pubkey,
    pub committer_kind:               CommitterKind,
    /// The hash AFTER this commit.
    pub new_baseline_hash:            [u8; 32],
    /// The hash this rotation REPLACED.
    pub previous_baseline_hash:       [u8; 32],
    /// Who wrote the previous baseline.
    pub previous_committer:           Pubkey,
    /// Unix seconds the previous baseline was committed.
    pub previous_committed_at:        i64,
    /// The previous commit_nonce — pairs with the new one in this event.
    pub previous_commit_nonce:        u64,
    /// The new commit_nonce.
    pub new_commit_nonce:             u64,
    /// Seconds between the previous and current commit. The owner's
    /// monitor uses this to spot a too-fast rotation (a real rotation
    /// is typically 30 days; one a few seconds after the last is the
    /// smoking gun).
    pub seconds_since_previous:       i64,
    pub rotated_at:                   i64,
}

#[event]
pub struct RegistrationMigrated {
    pub agent_wallet:    Pubkey,
    pub from_version:    u8,
    pub to_version:      u8,
    pub migrated_at:     i64,
}

// ── Day 19: epoch + score submission events ─────────────────────────────────

/// Emitted when the epoch counter ticks at the end of a 24h cycle.
#[event]
pub struct EpochAdvanced {
    pub from_epoch:  u64,
    pub to_epoch:    u64,
    pub advanced_at: i64,
}

/// Emitted when the oracle submits an agent's epoch score. The certificate
/// itself is written by the CPI into certificate-issuer; this is the
/// oracle-side record of the submission.
#[event]
pub struct ScoreSubmitted {
    pub agent_wallet:  Pubkey,
    pub epoch:         u64,
    pub score:         u16,
    pub alert_tier:    u8,
    pub flags:         u32,
    pub immediate_red: bool,
    pub oracle:        Pubkey,
    pub submitted_at:  i64,
}

/// Emitted by get_health — surfaces an agent's current-epoch certificate.
#[event]
pub struct HealthRead {
    pub agent_wallet:  Pubkey,
    pub epoch:         u64,
    pub score:         u16,
    pub alert_tier:    u8,
    pub flags:         u32,
    pub immediate_red: bool,
    pub issued_at:     i64,
}

/// Emitted when the liveness-fallback path triggers an epoch advance.
/// Emitted IN ADDITION TO `EpochAdvanced` so consumers can distinguish
/// normal oracle advances from fallback-cluster advances.
#[event]
pub struct EpochAdvancedByFallback {
    pub from_epoch:  u64,
    pub to_epoch:    u64,
    pub advanced_at: i64,
    /// The cluster key that triggered the fallback advance.
    pub cluster_key: Pubkey,
}

/// Emitted when the admin rotates the advance_authority key.
#[event]
pub struct AdvanceAuthorityRotated {
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
    pub rotated_by:    Pubkey,
    pub rotated_at:    i64,
}
