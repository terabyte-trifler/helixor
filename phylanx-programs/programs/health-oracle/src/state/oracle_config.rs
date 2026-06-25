// =============================================================================
// programs/health-oracle/src/state/oracle_config.rs
//
// OracleConfig — the singleton PDA holding the oracle authority.
//
// This existed in the Doc-3 MVP as a SINGLE-key config. Day 23 (Phase 4)
// extends it for the oracle CLUSTER: the protocol moves from one trusted
// node to a 3-5 node Byzantine-fault-tolerant cluster.
//
// THE DAY-23 CHANGE
// -----------------
//   - `oracle_keys: Vec<Pubkey>` -- the cluster's node pubkeys (3-5 of them).
//   - `min_confidence: u16`      -- the confidence floor a submission must
//                                  clear to count toward consensus.
//   - `oracle_node` is RETAINED -- a single node is just a degenerate
//     1-node cluster, and keeping the field means nothing that read it
//     breaks during the transition. It now means "the primary node".
//
// SIZING A Vec IN AN ANCHOR ACCOUNT
// ---------------------------------
// A Borsh-serialised Vec is a 4-byte length prefix followed by its
// elements. An account's size is FIXED at creation, so the account must
// reserve room for the MAXIMUM cluster size. We allocate for
// MAX_ORACLE_KEYS (5) pubkeys whether or not all slots are filled -- the
// 4-byte prefix records how many are actually in use.
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct OracleConfig {
    /// Program upgrade / admin authority -- the key that may update this
    /// OracleConfig itself (e.g. rotate the cluster membership).
    pub authority:      Pubkey,
    /// The PRIMARY oracle node pubkey. Retained from the MVP so existing
    /// readers do not break. In a multi-node cluster this is conventionally
    /// `oracle_keys[0]`; in a 1-node deployment it is the only node.
    pub oracle_node:    Pubkey,
    /// The oracle CLUSTER -- the 3-5 node pubkeys that participate in
    /// commit-reveal consensus. A 1-node cluster holds exactly one key
    /// (equal to `oracle_node`), which is the backward-compatible default.
    pub oracle_keys:    Vec<Pubkey>,
    /// The minimum confidence (0..=1000, mirroring ScoreResult.confidence)
    /// a node's submission must reach to be counted toward consensus. A
    /// submission below this floor is treated as an abstention.
    pub min_confidence: u16,
    /// Canonical PDA bump.
    pub bump:           u8,
}

impl OracleConfig {
    /// The maximum oracle cluster size. The account reserves room for this
    /// many pubkeys; the Vec's length prefix records how many are in use.
    pub const MAX_ORACLE_KEYS: usize = 5;

    /// The minimum cluster size for meaningful Byzantine fault tolerance.
    /// A 1-node cluster is permitted as the explicit single-node
    /// deployment; a 2-node cluster is not (no majority is possible).
    pub const MIN_BFT_CLUSTER: usize = 3;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    ///
    ///   8  discriminator
    /// + 32 authority
    /// + 32 oracle_node
    /// + 4  oracle_keys Vec length prefix
    /// + 32 * MAX_ORACLE_KEYS   (reserved element slots)
    /// + 2  min_confidence
    /// + 1  bump
    pub const SPACE: usize =
        8 + 32 + 32 + 4 + (32 * Self::MAX_ORACLE_KEYS) + 2 + 1;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"oracle_config";

    /// Whether `key` is a member of the oracle cluster.
    pub fn is_cluster_member(&self, key: &Pubkey) -> bool {
        self.oracle_keys.contains(key)
    }

    /// The Byzantine-fault-tolerant consensus threshold for the current
    /// cluster size -- a strict majority: floor(n/2) + 1.
    ///   1 node  -> 1   (degenerate single-node)
    ///   3 nodes -> 2   (tolerates 1 fault)
    ///   5 nodes -> 3   (tolerates 2 faults)
    pub fn consensus_threshold(&self) -> usize {
        self.oracle_keys.len() / 2 + 1
    }
}
