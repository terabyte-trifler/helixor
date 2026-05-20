// =============================================================================
// programs/health-oracle/src/errors.rs
//
// Typed errors. Anchor maps these to numeric codes >= 6000.
// Every error has a clear, attributable cause — no generic "ConstraintViolation".
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum HelixorError {
    // ── Authority / authentication ──────────────────────────────────────────
    #[msg("signer is not the configured oracle node")]
    NotOracleAuthority = 6000,
    #[msg("signer is not the agent owner")]
    NotAgentOwner = 6001,
    #[msg("signer is neither the oracle node nor the agent owner")]
    NotAuthorisedCommitter = 6002,

    // ── State preconditions ─────────────────────────────────────────────────
    #[msg("agent is not active; activate before committing")]
    AgentInactive = 6010,
    #[msg("agent registration layout version is incompatible — run migrate_registration")]
    LayoutMigrationRequired = 6011,

    // ── Replay / monotonicity ───────────────────────────────────────────────
    #[msg("commit_nonce must be strictly greater than the current on-chain nonce")]
    NonMonotonicNonce = 6020,
    #[msg("baseline_hash is all zeros — refusing to commit an empty commitment")]
    ZeroHash = 6021,
    #[msg("baseline_algo_version is zero — refusing to commit an unversioned hash")]
    ZeroAlgoVersion = 6022,

    // ── Migration ───────────────────────────────────────────────────────────
    #[msg("registration is already at the current layout version")]
    AlreadyMigrated = 6030,

    // ── Day 19: epoch + score submission ────────────────────────────────────
    #[msg("epoch cannot advance yet — the epoch duration has not elapsed")]
    EpochNotElapsed = 6040,
    #[msg("score exceeds the maximum (1000)")]
    ScoreOutOfRange = 6041,
    #[msg("confidence exceeds the maximum (1000)")]
    ConfidenceOutOfRange = 6044,
    #[msg("no baseline has been committed for this agent — commit one before scoring")]
    BaselineNotCommitted = 6042,
    #[msg("the supplied epoch does not match the current on-chain epoch")]
    EpochMismatch = 6043,

    // ── Day 23: oracle cluster ──────────────────────────────────────────────
    #[msg("oracle cluster size invalid — must be 1 (single-node) or 3..=5 (BFT)")]
    InvalidClusterSize = 6050,
    #[msg("duplicate pubkey in the oracle cluster key set")]
    DuplicateOracleKey = 6051,
    #[msg("min_confidence out of range — must be 0..=1000")]
    InvalidMinConfidence = 6052,
}
