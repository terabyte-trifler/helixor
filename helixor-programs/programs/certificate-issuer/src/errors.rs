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
}
