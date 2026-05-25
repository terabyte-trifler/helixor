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

    // ── VULN-06: baseline write gating ──────────────────────────────────────
    #[msg("signer is not authorised to write this agent's baseline — must be \
           the agent itself or a cluster signing key")]
    UnauthorizedBaselineWriter = 6040,
    #[msg("baseline rotation refused — a baseline for this agent was already \
           recorded at this epoch; rotate at a later epoch")]
    BaselineRotationTooSoon = 6041,
    #[msg("baseline epoch is not strictly greater than the previously recorded \
           epoch — baseline records are appendable only and monotonic")]
    BaselineEpochNotMonotonic = 6042,

    // ── VULN-16: CPI caller allow-list ──────────────────────────────────────
    #[msg("issue_certificate was CPI-invoked by an unrecognised program — \
           only a direct top-level call or a CPI from the configured \
           health_oracle program is permitted")]
    UntrustedCpiCaller = 6050,
    #[msg("issue_certificate could not read the top-level instruction from \
           the Instructions sysvar — refusing to issue a cert without \
           caller attribution")]
    CallerIntrospectionFailed = 6051,
}
