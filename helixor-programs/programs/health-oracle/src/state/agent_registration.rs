// =============================================================================
// programs/health-oracle/src/state/agent_registration.rs
//
// AgentRegistration v2 — adds the baseline commitment fields.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet                32   (Pubkey)
//   owner_wallet                32   (Pubkey)
//   registered_at                8   (i64, unix seconds)
//   active                       1   (bool)
//   bump                         1   (u8)
//   --- v2 ADDITIONS (Day 3) ----------
//   baseline_committed           1   (bool — "has any baseline been committed?")
//   baseline_hash               32   ([u8; 32] — SHA-256 of canonical baseline)
//   baseline_algo_version        1   (u8 — algorithm version that produced the hash)
//   baseline_committer          32   (Pubkey — authority that committed; oracle or owner)
//   baseline_committed_at        8   (i64 — unix seconds at commit)
//   commit_nonce                 8   (u64 — monotonic counter; replay protection)
//   layout_version               1   (u8 — account-layout version for future migrations)
//   --- reserved ----------------
//   _reserved                   64   (zeroed; for future fields without realloc)
//
//   TOTAL DATA SIZE (without discriminator): 229 bytes
//
// The reserved 64 bytes are a deliberate cushion: small future additions can be
// "carved out" of reserved without another realloc.
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Debug)]
pub struct AgentRegistration {
    /// The wallet whose behaviour is being scored.
    pub agent_wallet:           Pubkey,
    /// The wallet that registered this agent (signs ownership-gated ixs).
    pub owner_wallet:           Pubkey,
    /// When the agent was registered (unix seconds).
    pub registered_at:          i64,
    /// True while the agent is monitored. Deactivation flips this.
    pub active:                 bool,
    /// Canonical PDA bump.
    pub bump:                   u8,

    // ── v2 / Day 3 ──────────────────────────────────────────────────────────
    /// True iff at least one baseline has been committed.
    pub baseline_committed:     bool,
    /// SHA-256 commitment of the canonical baseline (from baseline.hashing).
    pub baseline_hash:          [u8; 32],
    /// Algorithm version that produced the hash. Carried for audit.
    pub baseline_algo_version:  u8,
    /// Authority that wrote the latest commit (oracle pubkey OR owner pubkey).
    pub baseline_committer:     Pubkey,
    /// Timestamp of the latest commit (unix seconds).
    pub baseline_committed_at:  i64,
    /// Monotonically-increasing commit counter. Replay protection.
    /// Starts at 0; first commit sets it to 1; every commit must be > current.
    pub commit_nonce:           u64,
    /// Account-layout version. Bumped if AgentRegistration is ever migrated again.
    pub layout_version:         u8,
    /// Zero-padded reserve for small future fields (avoids realloc on minor changes).
    pub _reserved:              [u8; 64],
}

impl Default for AgentRegistration {
    fn default() -> Self {
        Self {
            agent_wallet:          Pubkey::default(),
            owner_wallet:          Pubkey::default(),
            registered_at:         0,
            active:                false,
            bump:                  0,
            baseline_committed:    false,
            baseline_hash:         [0u8; 32],
            baseline_algo_version: 0,
            baseline_committer:    Pubkey::default(),
            baseline_committed_at: 0,
            commit_nonce:          0,
            layout_version:        0,
            _reserved:             [0u8; 64],
        }
    }
}

impl AgentRegistration {
    /// The current layout version. Anything older than this needs migration.
    pub const CURRENT_LAYOUT_VERSION: u8 = 2;

    /// Total account size in bytes (NOT including the 8-byte Anchor discriminator).
    ///   32 + 32 + 8 + 1 + 1  =  74    (v1 fields)
    /// + 1 + 32 + 1 + 32 + 8 + 8 + 1   =  83    (v2 fields)
    /// + 64                            =  64    (reserved)
    ///   = 221
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize = 32 + 32 + 8 + 1 + 1
                                                 + 1 + 32 + 1 + 32 + 8 + 8 + 1
                                                 + 64;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// Bytes the v1 (MVP) account occupied. Used to detect "needs migration".
    /// 32 + 32 + 8 + 1 + 1 = 74; + 8 discriminator = 82.
    pub const V1_SPACE: usize = 8 + 32 + 32 + 8 + 1 + 1;
}
