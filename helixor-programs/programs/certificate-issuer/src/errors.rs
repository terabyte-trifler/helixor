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

    // ── AW-01: input-provenance commitment ──────────────────────────────────
    #[msg("input_commitment is all zeros — the cluster must agree on the \
           input-provenance commitment before issuing a cert (AW-01); a \
           zero commitment indicates the off-chain submitter skipped the \
           per-node + cross-node input binding")]
    MissingInputCommitment = 6060,

    // ── AW-01-EXT: Solana slot-anchor verification ──────────────────────────
    #[msg("slot_anchor is all zeros — the cluster must pin a Solana slot \
           anchor (AW-01-EXT) so the cert can be verified against the \
           SlotHashes sysvar")]
    MissingSlotAnchor = 6070,
    #[msg("supplied SlotHashes sysvar does not match the expected sysvar pubkey")]
    WrongSlotHashesSysvar = 6071,
    #[msg("slot_anchor.slot is older than the SlotHashes sysvar window \
           (~512 slots / ~3.4 min) — submit the cert closer to the scoring \
           time so the anchor is still verifiable on chain")]
    SlotAnchorTooOld = 6072,
    #[msg("slot_anchor.block_hash does not match Solana's recorded hash for \
           that slot — the cluster pinned an anchor Solana does not recognise; \
           either every cluster node reads from a poisoned upstream, or the \
           submitter forged the anchor (AW-01-EXT defence-in-depth caught it)")]
    SlotAnchorHashMismatch = 6073,

    // ── AW-01-EXT.6: certificate challenge instruction ──────────────────────
    #[msg("challenge cluster not configured — issuer_config has zero attester \
           keys or zero threshold; rotate the attester cluster in before \
           filing challenges")]
    NoAttesterCluster = 6080,
    #[msg("certificate predates AW-01-EXT (layout_version < 4) and has no slot \
           anchor to challenge")]
    PreV4CertNotChallengeable = 6081,
    #[msg("a challenge has already been filed against this certificate — \
           outcome is permanent (Upheld or Rejected)")]
    ChallengeAlreadyFiled = 6082,
    #[msg("certificate is too old to challenge — challenge window is the \
           configured CHALLENGE_WINDOW_SECONDS (default 90 days) from \
           issued_at")]
    ChallengeExpired = 6083,
    #[msg("challenge carries fewer valid attester signatures than the \
           challenge_threshold")]
    InsufficientChallengeAttesters = 6084,
    #[msg("challenge invalid cluster size — must be 1..=MAX_CHALLENGE_ATTESTER_KEYS")]
    InvalidAttesterClusterSize = 6086,
    #[msg("duplicate pubkey in the challenge-attester key set")]
    DuplicateAttesterKey = 6087,
    #[msg("challenge-attester key overlaps the cert-signing cluster — the \
           attester cluster must be DISJOINT (independent re-checkers)")]
    AttesterOverlapsCluster = 6088,
    #[msg("challenge_threshold invalid — must be 1..=challenge_attester_keys.len()")]
    InvalidChallengeThreshold = 6089,

    // ── AW-03: on-chain baseline data-availability proof ────────────────────
    #[msg("baseline_commit_nonce is zero — record_baseline now requires the \
           AgentRegistration.commit_nonce that the baseline_hash was committed \
           at on health-oracle (AW-03); pass it through so the cert can locate \
           the on-chain DA account")]
    ZeroBaselineCommitNonce = 6090,
    #[msg("baseline_commit_nonce is not strictly greater than the previously \
           recorded nonce — baseline-data nonces are appendable only and \
           monotonic; a same/lower nonce would mask a stale DA account")]
    BaselineCommitNonceNotMonotonic = 6091,
}
