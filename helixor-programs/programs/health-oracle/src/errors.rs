// =============================================================================
// Helixor Error Codes — health-oracle program
//
// All error codes defined Day 1 so Days 2-7 reference them by name.
// Numbers are stable — don't re-order or TypeScript SDK breaks.
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum HelixorError {
    // ── Registration (6000-6002) ──────────────────────────────────────────────
    /// register_agent: name.len() > 64
    #[msg("Agent name exceeds 64 characters")]
    NameTooLong,                                    // 6000

    /// register_agent: owner lamports < MIN_ESCROW
    #[msg("Escrow below minimum of 0.01 SOL (10_000_000 lamports)")]
    InsufficientEscrow,                             // 6001

    /// register_agent: agent_wallet == owner_wallet
    #[msg("Agent wallet and owner wallet must be different accounts")]
    AgentSameAsOwner,                               // 6002

    // ── Scoring / Query (6003-6006) ───────────────────────────────────────────
    /// get_health: agent PDA does not exist
    #[msg("Agent is not registered with Helixor")]
    NotRegistered,                                  // 6003

    /// requireMinScore: called by consuming protocol when score is too low
    #[msg("Agent trust score is below the required minimum")]
    ScoreTooLow,                                    // 6004

    /// get_health: certificate exists but is older than 48h
    #[msg("Trust certificate is stale — oracle has not updated in 48h")]
    StaleCertificate,                               // 6005

    /// update_score: caller is not the registered oracle key
    #[msg("Caller is not the authorised oracle node")]
    UnauthorizedOracle,                             // 6006

    // ── Guard Rails (6007-6008) ───────────────────────────────────────────────
    /// update_score: |new_score - old_score| > 200
    #[msg("Score change exceeds 200-point guard rail per epoch")]
    ScoreDeltaTooLarge,                             // 6007

    /// update_score: called again within 23h cooldown window
    #[msg("Score already updated within the last 23 hours")]
    UpdateTooFrequent,                              // 6008

    // ── Safety (6009) ─────────────────────────────────────────────────────────
    /// Any checked arithmetic that would overflow
    #[msg("Integer arithmetic overflow")]
    MathOverflow,                                   // 6009
}
