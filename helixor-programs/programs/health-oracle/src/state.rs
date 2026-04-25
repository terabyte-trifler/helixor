// =============================================================================
// Helixor State — health-oracle program
//
// All structs frozen on Day 2. Day 3 only adds helper methods on the existing
// types (no field changes — that would require a migration).
// =============================================================================

use anchor_lang::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// AgentRegistration PDA
// Seeds: ["agent", agent_wallet_pubkey]   Created: register_agent (Day 2)
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct AgentRegistration {
    pub agent_wallet:    Pubkey,  // 32
    pub owner_wallet:    Pubkey,  // 32
    pub registered_at:   i64,     // 8
    pub escrow_lamports: u64,     // 8
    pub active:          bool,    // 1
    pub bump:            u8,      // 1
    pub vault_bump:      u8,      // 1
    // Total: 83 bytes
}

impl AgentRegistration {
    pub const INIT_SPACE:          usize = 83;
    pub const MIN_ESCROW_LAMPORTS: u64   = 10_000_000;
    pub const MAX_NAME_BYTES:      usize = 64;
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustCertificate PDA
// Seeds: ["score", agent_wallet_pubkey]   Created: update_score (Day 7)
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct TrustCertificate {
    pub agent_wallet: Pubkey,      // 32
    pub score:        u16,         // 2
    pub alert:        AlertLevel,  // 1
    pub success_rate: u16,         // 2
    pub tx_count_7d:  u32,         // 4
    pub anomaly_flag: bool,        // 1
    pub updated_at:   i64,         // 8
    pub bump:         u8,          // 1
    // Total: 51 bytes
}

impl TrustCertificate {
    pub const INIT_SPACE:      usize = 51;
    pub const MAX_AGE_SECONDS: i64   = 172_800; // 48h
    pub const MAX_SCORE_DELTA: u16   = 200;
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertLevel — repr(u8) so byte representation is stable across SDKs
// ─────────────────────────────────────────────────────────────────────────────
#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertLevel {
    Green  = 1,
    Yellow = 2,
    Red    = 3,
}

impl AlertLevel {
    pub fn from_score(score: u16) -> Self {
        match score {
            700..=1000 => Self::Green,
            400..=699  => Self::Yellow,
            _          => Self::Red,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterParams — input to register_agent (Day 2)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RegisterParams {
    pub name: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustScore — return value of get_health (Day 3)
//
// This struct is the entire on-chain API surface that DeFi protocols depend on.
// CHANGES TO THIS STRUCT ARE BREAKING. New fields can ONLY be added at the end,
// never reordered, never removed. Bump scoring_version (TrustCertificate) when
// the meaning of fields changes.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct TrustScore {
    /// The agent the score is for (mirrors input for safe routing in CPI).
    pub agent: Pubkey,

    /// 0-1000. Higher is more trustworthy.
    pub score: u16,

    /// Convenience tri-state derived from score.
    pub alert: AlertLevel,

    /// Success rate in basis points (9750 = 97.50%).
    pub success_rate: u16,

    /// True if scoring engine flagged anomalous behaviour in this epoch.
    pub anomaly_flag: bool,

    /// Unix timestamp of last oracle write. 0 means "no cert yet".
    pub updated_at: i64,

    /// True if cert was written within the last 48h.
    /// Consumers SHOULD reject actions when is_fresh = false.
    pub is_fresh: bool,

    /// Why this score was returned. See ScoreSource for enum values.
    /// Consumers can use this to apply different policies (e.g. allow PROVISIONAL
    /// agents to do small-volume reads but block large-volume actions).
    pub source: ScoreSource,
}

/// Why a particular TrustScore value was returned.
/// Consumers inspect this to decide their policy.
#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScoreSource {
    /// Cert exists, fresh (< 48h), agent active. The normal happy path.
    Live = 1,

    /// Cert exists, but > 48h old. Score returned is the last known value;
    /// is_fresh = false. Consumers should treat as untrusted.
    Stale = 2,

    /// Agent is registered but no cert exists yet (first 24h, oracle hasn't
    /// run). Score = 500 (neutral), alert = Yellow, is_fresh = false.
    Provisional = 3,

    /// Agent has been deactivated by owner (active = false in registration).
    /// Score = 0, alert = Red, is_fresh = true (this *is* the truth).
    Deactivated = 4,
}

// ─────────────────────────────────────────────────────────────────────────────
// ScorePayload — input to update_score (Day 7)
// ─────────────────────────────────────────────────────────────────────────────
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ScorePayload {
    pub score:        u16,
    pub success_rate: u16,
    pub tx_count_7d:  u32,
    pub anomaly_flag: bool,
}
