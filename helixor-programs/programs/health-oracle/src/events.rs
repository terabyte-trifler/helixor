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
    pub agent_wallet: Pubkey,
    /// The committer pubkey (oracle node or agent owner).
    pub committer: Pubkey,
    /// The new committed hash.
    pub baseline_hash: [u8; 32],
    /// Algorithm version that produced this hash.
    pub baseline_algo_version: u8,
    /// New nonce value (= previous + 1, by the monotonicity rule).
    pub commit_nonce: u64,
    /// Unix seconds (Clock::get().unix_timestamp).
    pub committed_at: i64,
    /// True if this is the first commit for this agent.
    pub first_commit: bool,
    /// "oracle" or "owner". Convenience for downstream indexers.
    pub committer_kind: CommitterKind,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitterKind {
    Oracle,
    Owner,
}

#[event]
pub struct RegistrationMigrated {
    pub agent_wallet: Pubkey,
    pub from_version: u8,
    pub to_version: u8,
    pub migrated_at: i64,
}
