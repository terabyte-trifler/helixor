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
    pub agent_wallet: Pubkey, // 32
    pub owner_wallet: Pubkey, // 32
    pub registered_at: i64,   // 8
    pub escrow_lamports: u64, // 8
    pub active: bool,         // 1
    pub bump: u8,             // 1
    pub vault_bump: u8,       // 1
}

impl AgentRegistration {
    pub const INIT_SPACE: usize = 83;
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
// OracleConfig PDA — singleton (Day 7 NEW)
// Seeds: ["oracle_config"]
// Created once via initialize_oracle_config; mutated by update_oracle_config.
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct OracleConfig {
    pub oracle_key: Pubkey, // 32 — currently authorised oracle node
    pub admin_key: Pubkey,  // 32 — only this key can rotate oracle_key
    pub bump: u8,           // 1
    pub paused: bool,       // 1 — emergency stop, blocks all writes
    pub epoch: u64,         // 8 — total scoring epochs run
                            // Total: 74 bytes
}

impl OracleConfig {
    pub const INIT_SPACE: usize = 74;
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
