// =============================================================================
// programs/certificate-issuer/src/errors.rs
//
// Typed errors for the certificate-issuer program. Anchor maps these to
// numeric codes >= 6000. Every error names a specific, attributable cause.
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum CertificateError {
    // ── Authority ───────────────────────────────────────────────────────────
    #[msg("signer is not the configured certificate-issuer authority")]
    NotIssuerAuthority = 6000,

    // ── Input validation ────────────────────────────────────────────────────
    #[msg("score exceeds the maximum (1000)")]
    ScoreOutOfRange = 6010,
    #[msg("alert_tier is not a valid AlertTier code (0 GREEN, 1 YELLOW, 2 RED)")]
    InvalidAlertTier = 6011,
    #[msg("epoch is zero — epochs are 1-indexed")]
    ZeroEpoch = 6012,
    #[msg("baseline_hash is all zeros — refusing to issue against an empty baseline")]
    ZeroBaselineHash = 6013,

    // ── State preconditions ─────────────────────────────────────────────────
    #[msg("the score / alert pair is inconsistent: a RED alert needs immediate_red \
           or a low score; a GREEN alert needs a high score")]
    InconsistentScoreAlert = 6020,
    #[msg("no baseline has been recorded for this agent — record one before issuing")]
    BaselineNotRecorded = 6021,
    #[msg("issuer config account is malformed or too small for migration")]
    MalformedIssuerConfig = 6022,

    // ── Day 27: 3-of-5 threshold signing ────────────────────────────────────
    #[msg("issuer cluster size invalid — must be 1 (single-key) or 3..=5 (BFT)")]
    InvalidClusterSize = 6030,
    #[msg("duplicate pubkey in the issuer cluster key set")]
    DuplicateClusterKey = 6031,
    #[msg("threshold invalid — must be 1..=cluster_size and a strict majority for BFT")]
    InvalidThreshold = 6032,
    #[msg("certificate write carries fewer valid cluster signatures than the threshold")]
    InsufficientSignatures = 6033,
    #[msg("supplied instructions sysvar does not match the expected sysvar pubkey")]
    WrongInstructionsSysvar = 6034,
    #[msg("Ed25519 precompile instruction is malformed or truncated")]
    MalformedEd25519Instruction = 6035,
    #[msg("Ed25519 instruction references another instruction's data — refused")]
    CrossInstructionReference = 6036,
    #[msg("Ed25519 signed message length is not the expected 32-byte digest")]
    WrongDigestLength = 6037,
}
