// =============================================================================
// Helixor State — health-oracle program
//
// All account types defined on Day 1 so Days 2-7 only write instruction logic.
// Field sizes annotated on every line — no guessing when computing INIT_SPACE.
//
// Day 2 uses: AgentRegistration, RegisterParams
// Day 3 uses: TrustCertificate, TrustScore
// Day 7 uses: OracleConfig, ScorePayload
// =============================================================================

use anchor_lang::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// AgentRegistration PDA
// Seeds: ["agent", agent_wallet_pubkey]
// Created: register_agent (Day 2)
// Never mutated after creation for MVP
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct AgentRegistration {
    pub agent_wallet:    Pubkey,  // 32 — the monitored wallet (agent's hot key)
    pub owner_wallet:    Pubkey,  // 32 — who registered it (operator)
    pub registered_at:   i64,     // 8  — unix timestamp
    pub escrow_lamports: u64,     // 8  — SOL locked as skin-in-the-game
    pub active:          bool,    // 1  — false after deregister
    pub bump:            u8,      // 1  — canonical PDA bump
    // ── Total: 32+32+8+8+1+1 = 82 bytes ─────────────────────────────────────
}

impl AgentRegistration {
    pub const INIT_SPACE:        usize = 82;
    pub const MIN_ESCROW:        u64   = 10_000_000; // 0.01 SOL
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustCertificate PDA
// Seeds: ["score", agent_wallet_pubkey]
// Created/overwritten: update_score (Day 7) every 24h
// Read by: get_health() (Day 3) via CPI from DeFi protocols
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct TrustCertificate {
    pub agent_wallet:  Pubkey,    // 32 — links cert to agent
    pub score:         u16,       // 2  — 0-1000
    pub alert:         AlertLevel,// 1  — GREEN / YELLOW / RED
    pub success_rate:  u16,       // 2  — basis points (9750 = 97.50%)
    pub tx_count_7d:   u32,       // 4  — transaction count in rolling 7-day window
    pub anomaly_flag:  bool,      // 1  — true if success rate dropped >15% from baseline
    pub updated_at:    i64,       // 8  — unix timestamp of last oracle write
    pub bump:          u8,        // 1  — canonical PDA bump
    // ── Total: 32+2+1+2+4+1+8+1 = 51 bytes ──────────────────────────────────
}

impl TrustCertificate {
    pub const INIT_SPACE:       usize = 51;
    pub const MAX_AGE_SECONDS:  i64   = 172_800; // 48h — stale after this
    pub const MAX_SCORE_DELTA:  u16   = 200;      // guard rail — max change per epoch
}

// ─────────────────────────────────────────────────────────────────────────────
// OracleConfig PDA
// Seeds: ["oracle_config"]
// Created: initialize_oracle (deploy script, Day 7)
// Stores the public key of the one trusted oracle node
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct OracleConfig {
    pub oracle_key:   Pubkey, // 32 — the one oracle node keypair
    pub authority:    Pubkey, // 32 — who can rotate the oracle key
    pub bump:         u8,     // 1
    // ── Total: 32+32+1 = 65 bytes ────────────────────────────────────────────
}

impl OracleConfig {
    pub const INIT_SPACE: usize = 65;
}

// ─────────────────────────────────────────────────────────────────────────────
// Enums
// ─────────────────────────────────────────────────────────────────────────────

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertLevel {
    Green  = 1, // 700-1000 — healthy, full access
    Yellow = 2, // 400-699  — caution, reduced access
    Red    = 3, // 0-399    — critical, access denied
}

impl AlertLevel {
    pub fn from_score(score: u16) -> Self {
        match score {
            700..=1000 => Self::Green,
            400..=699  => Self::Yellow,
            _          => Self::Red,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Green  => "GREEN",
            Self::Yellow => "YELLOW",
            Self::Red    => "RED",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction parameter types
// ─────────────────────────────────────────────────────────────────────────────

/// Input for register_agent (Day 2)
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RegisterParams {
    /// Display name for this agent — max 64 bytes UTF-8
    pub name: String,
}

/// Returned by get_health() — what DeFi protocols receive via CPI (Day 3)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct TrustScore {
    pub agent_wallet:  Pubkey,
    pub score:         u16,        // 0-1000
    pub alert:         AlertLevel,
    pub success_rate:  u16,        // basis points (e.g. 9750 = 97.50%)
    pub anomaly_flag:  bool,
    pub updated_at:    i64,        // unix timestamp of last oracle update
    pub is_fresh:      bool,       // false if cert is older than 48h
}

/// Input for update_score — sent by oracle node (Day 7)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ScorePayload {
    pub score:        u16,   // 0-1000 computed by Python scoring engine
    pub success_rate: u16,   // basis points
    pub tx_count_7d:  u32,   // transactions in rolling 7-day window
    pub anomaly_flag: bool,  // true if success rate dropped >15% from baseline
}
