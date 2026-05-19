// =============================================================================
// Helixor State — Day 7 additions
//
// New: OracleConfig PDA (singleton), updated ScorePayload, updated
// TrustCertificate to carry baseline_hash for on-chain audit.
// =============================================================================

use anchor_lang::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// AgentRegistration PDA — unchanged from Day 2
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct AgentRegistration {
    pub agent_wallet: Pubkey,       // 32
    pub owner_wallet: Pubkey,       // 32
    pub registered_at: i64,         // 8
    pub escrow_lamports: u64,       // 8
    pub active: bool,               // 1
    pub bump: u8,                   // 1
    pub vault_bump: u8,             // 1
    pub baseline_committed: bool,   // 1
    pub baseline_hash: [u8; 32],    // 32
    pub baseline_algo_version: u8,  // 1
    pub baseline_committer: Pubkey, // 32
    pub baseline_committed_at: i64, // 8
    pub commit_nonce: u64,          // 8
    pub layout_version: u8,         // 1
    pub _reserved: [u8; 64],        // 64
}

impl AgentRegistration {
    pub const CURRENT_LAYOUT_VERSION: u8 = 2;
    pub const V1_SPACE: usize = 8 + 83;
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize = 83 + 1 + 32 + 1 + 32 + 8 + 8 + 1 + 64;
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;
    pub const INIT_SPACE: usize = Self::SIZE_WITHOUT_DISCRIMINATOR;
    pub const MIN_ESCROW_LAMPORTS: u64 = 10_000_000;
    pub const MAX_NAME_BYTES: usize = 64;
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustCertificate PDA — EXTENDED for Day 7
//
// Added: baseline_hash (16 bytes — first 16 of sha256 baseline)
//        scoring_algo_version (1 byte)
//        weights_version (1 byte)
// New total: 51 + 18 = 69 bytes data, +8 disc = 77 bytes
//
// Why baseline_hash on-chain: lets DeFi protocols verify which off-chain
// baseline produced this score. With this, anyone can fetch the baseline
// from public history and recompute the score deterministically.
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct TrustCertificate {
    pub agent_wallet: Pubkey,           // 32
    pub score: u16,                     // 2
    pub alert: AlertLevel,              // 1
    pub success_rate: u16,              // 2  (basis points)
    pub tx_count_7d: u32,               // 4
    pub anomaly_flag: bool,             // 1
    pub updated_at: i64,                // 8
    pub bump: u8,                       // 1
    pub baseline_hash_prefix: [u8; 16], // 16 (first 16 bytes of full hash)
    pub scoring_algo_version: u8,       // 1
    pub weights_version: u8,            // 1
                                        // Total: 32+2+1+2+4+1+8+1+16+1+1 = 69 bytes
}

impl TrustCertificate {
    pub const INIT_SPACE: usize = 69;
    pub const MAX_AGE_SECONDS: i64 = 172_800; // 48h
    pub const MAX_SCORE_DELTA: u16 = 200;
    pub const MIN_UPDATE_GAP: i64 = 82_800; // 23h
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleConfig PDA — singleton
// Seeds: ["oracle_config"]
//
// Phase 4 extends the MVP's single oracle key into a 1 / 3 / 5 node cluster.
// A 1-node config is the explicit backward-compatible deployment; 3-5 nodes
// are the BFT deployments used by the off-chain median aggregator.
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct OracleConfig {
    pub authority: Pubkey,
    pub oracle_node: Pubkey,
    pub oracle_keys: Vec<Pubkey>,
    pub min_confidence: u16,
    pub bump: u8,
}

impl OracleConfig {
    pub const MAX_ORACLE_KEYS: usize = 5;
    pub const MIN_BFT_CLUSTER: usize = 3;
    pub const SEED: &'static [u8] = b"oracle_config";
    pub const SPACE: usize = 8 + 32 + 32 + 4 + (32 * Self::MAX_ORACLE_KEYS) + 2 + 1;
    pub const INIT_SPACE: usize = Self::SPACE - 8;

    pub fn consensus_threshold(&self) -> u8 {
        (self.oracle_keys.len() as u8 / 2) + 1
    }

    pub fn is_cluster_member(&self, key: &Pubkey) -> bool {
        self.oracle_keys.contains(key)
    }
}

#[account]
pub struct EpochState {
    pub current_epoch: u64,
    pub last_advanced_at: i64,
    pub epoch_duration_seconds: i64,
    pub advance_authority: Pubkey,
    pub bump: u8,
    pub _reserved: [u8; 32],
}

impl EpochState {
    pub const FIRST_EPOCH: u64 = 1;
    pub const DEFAULT_DURATION_SECONDS: i64 = 86_400;
    pub const SPACE: usize = 8 + 8 + 8 + 8 + 32 + 1 + 32;
    pub const SEED: &'static [u8] = b"epoch_state";

    pub fn may_advance(&self, now: i64) -> bool {
        now - self.last_advanced_at >= self.epoch_duration_seconds
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertLevel — repr(u8) stable byte encoding
// ─────────────────────────────────────────────────────────────────────────────
#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertLevel {
    Green = 1,
    Yellow = 2,
    Red = 3,
}

impl AlertLevel {
    pub fn from_score(score: u16) -> Self {
        match score {
            700..=1000 => Self::Green,
            400..=699 => Self::Yellow,
            _ => Self::Red,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterParams — Day 2
// ─────────────────────────────────────────────────────────────────────────────
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RegisterParams {
    pub name: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// ScorePayload — EXTENDED for Day 7
// Spec only had score, success_rate, tx_count_7d, anomaly_flag.
// We add baseline_hash + version stamps for on-chain audit.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ScorePayload {
    pub score: u16,
    pub success_rate: u16, // basis points
    pub tx_count_7d: u32,
    pub anomaly_flag: bool,
    pub baseline_hash_prefix: [u8; 16], // first 16 bytes of off-chain SHA-256
    pub scoring_algo_version: u8,
    pub weights_version: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustScore — return type of get_health (Day 3, unchanged here)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct TrustScore {
    pub agent: Pubkey,
    pub score: u16,
    pub alert: AlertLevel,
    pub success_rate: u16,
    pub anomaly_flag: bool,
    pub updated_at: i64,
    pub is_fresh: bool,
    pub source: ScoreSource,
}

#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScoreSource {
    Live = 1,
    Stale = 2,
    Provisional = 3,
    Deactivated = 4,
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialize / update params for OracleConfig (Day 7 NEW)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitOracleConfigParams {
    pub oracle_key: Pubkey,
    pub admin_key: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdateOracleConfigParams {
    pub new_oracle_key: Option<Pubkey>,
    pub new_admin_key: Option<Pubkey>,
    pub new_paused: Option<bool>,
}
