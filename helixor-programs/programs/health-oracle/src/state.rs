// =============================================================================
// Helixor State — health-oracle program
//
// All account structs defined here. Fields annotated with:
//   - byte count (for computing INIT_SPACE)
//   - purpose (why this field exists)
//   - who writes it (which instruction mutates it)
//
// Design principles:
//   - Every field has a specific purpose. If a field is never read, remove it.
//   - Fixed-size data only. No Vec<u8>, no String inside #[account] structs.
//     (String in RegisterParams is fine — it's instruction input, not storage.)
//   - Canonical bumps stored at init. Re-deriving bumps on every CPI wastes CU.
// =============================================================================

use anchor_lang::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// AgentRegistration PDA
//
// One per registered agent. Written once by register_agent (Day 2).
// Read by get_health (Day 3) and update_score (Day 7).
//
// Seeds: ["agent", agent_wallet_pubkey]
// Space: 8 discriminator + 82 INIT_SPACE = 90 bytes
// Rent:  ~0.00163 SOL (rent-exempt minimum for 90 bytes)
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct AgentRegistration {
    /// The agent's hot wallet — the one that signs the agent's transactions.
    /// This is the key that Helius webhooks monitor for incoming transactions.
    pub agent_wallet: Pubkey,          // 32

    /// The operator who registered the agent and owns the escrow.
    /// Only this wallet can deactivate the registration (Day 5+).
    pub owner_wallet: Pubkey,          // 32

    /// Unix timestamp of registration. Used to compute provisioning window
    /// (< 24h since registered_at → no score available yet).
    pub registered_at: i64,            // 8

    /// Exact lamports held in the escrow_vault PDA.
    /// Stored on-chain so off-chain services don't need a separate RPC call
    /// to fetch the vault's lamports. Updated only if/when escrow amount changes.
    pub escrow_lamports: u64,          // 8

    /// Lifecycle flag. Day 2: always true after registration.
    /// Day 5+: can flip to false via deactivate_agent (owner-only).
    /// get_health() returns RED immediately if active == false.
    pub active: bool,                  // 1

    /// Canonical PDA bump for the registration account itself.
    /// Stored so future instructions verify with `bump = agent_registration.bump`
    /// instead of re-deriving (saves ~1500 CU per CPI).
    pub bump: u8,                      // 1

    /// Canonical PDA bump for the escrow vault.
    /// Required for update_score guard rail (verifies vault is correctly derived)
    /// and for future withdraw_escrow instruction (signer seeds).
    pub vault_bump: u8,                // 1
    // ── Total: 32 + 32 + 8 + 8 + 1 + 1 + 1 = 83 bytes ────────────────────────
}

impl AgentRegistration {
    pub const INIT_SPACE: usize = 83;

    /// Minimum escrow: 0.01 SOL = 10_000_000 lamports.
    /// Low enough that operators can register without meaningful friction.
    /// High enough that a spammer creating 10_000 fake registrations
    /// costs them 100 SOL (~$14k) in locked capital.
    pub const MIN_ESCROW_LAMPORTS: u64 = 10_000_000;

    /// Maximum agent name length in bytes (not characters — UTF-8 aware).
    /// Kept short to avoid bloating event logs + Helius webhook payloads.
    pub const MAX_NAME_BYTES: usize = 64;
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustCertificate PDA
//
// One per agent, overwritten every 24h by update_score (Day 7).
// The single source of truth consumed by DeFi protocols via get_health() CPI.
//
// Seeds: ["score", agent_wallet_pubkey]
// Space: 8 discriminator + 51 INIT_SPACE = 59 bytes
// ─────────────────────────────────────────────────────────────────────────────
#[account]
pub struct TrustCertificate {
    pub agent_wallet:  Pubkey,     // 32 — mirrors the agent this cert belongs to
    pub score:         u16,        // 2  — 0-1000
    pub alert:         AlertLevel, // 1  — enum repr as u8
    pub success_rate:  u16,        // 2  — basis points (9750 = 97.50%)
    pub tx_count_7d:   u32,        // 4  — tx count in rolling 7-day window
    pub anomaly_flag:  bool,       // 1  — true if success rate dropped >15% vs baseline
    pub updated_at:    i64,        // 8  — unix timestamp of oracle write
    pub bump:          u8,         // 1  — canonical PDA bump
    // ── Total: 32 + 2 + 1 + 2 + 4 + 1 + 8 + 1 = 51 bytes ─────────────────────
}

impl TrustCertificate {
    pub const INIT_SPACE: usize = 51;

    /// Certificate is considered stale after 48h.
    /// get_health() returns `is_fresh: false` — consuming protocols SHOULD
    /// refuse to act on stale scores (this is their decision, not ours).
    pub const MAX_AGE_SECONDS: i64 = 172_800;

    /// Guard rail: max score change allowed per epoch.
    /// Prevents oracle bugs or compromise from causing catastrophic score swings.
    pub const MAX_SCORE_DELTA: u16 = 200;
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertLevel — tri-state summary of the score
//
// explicit #[repr(u8)] so the on-chain byte representation is stable;
// TypeScript SDK clients rely on these exact numbers.
// ─────────────────────────────────────────────────────────────────────────────
#[repr(u8)]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertLevel {
    Green  = 1, // 700-1000 — safe to transact
    Yellow = 2, // 400-699  — caution, reduced limits recommended
    Red    = 3, // 0-399    — do not transact
}

impl AlertLevel {
    /// Pure function: score → alert level. No dependencies on state.
    /// Callers in both register_agent (N/A) and update_score (Day 7) use this.
    pub fn from_score(score: u16) -> Self {
        match score {
            700..=1000 => Self::Green,
            400..=699  => Self::Yellow,
            _          => Self::Red,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction parameter structs
//
// These are arguments passed by clients — NOT stored on-chain.
// Keeping params separate from state structs lets us evolve the API
// (add new fields to ScorePayload) without breaking on-chain layout.
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments to register_agent (Day 2)
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RegisterParams {
    /// Human-readable agent name. Validated to be ≤ MAX_NAME_BYTES in handler.
    /// Not stored on-chain — only included in AgentRegistered event for indexers.
    pub name: String,
}

/// Returned by get_health() (Day 3) to calling DeFi protocols via CPI
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct TrustScore {
    pub agent:        Pubkey,
    pub score:        u16,
    pub alert:        AlertLevel,
    pub success_rate: u16,
    pub anomaly_flag: bool,
    pub updated_at:   i64,
    /// True if cert < 48h old. Consumers should reject actions if false.
    pub is_fresh:     bool,
}

/// Input to update_score (Day 7) — submitted by oracle node
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ScorePayload {
    pub score:        u16,
    pub success_rate: u16,
    pub tx_count_7d:  u32,
    pub anomaly_flag: bool,
}
