// =============================================================================
// programs/slash-authority/src/errors.rs
//
// Typed errors for the slash-authority program. Anchor maps these to codes
// >= 6000. Every error names a specific, attributable cause.
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum SlashError {
    // ── Authority ───────────────────────────────────────────────────────────
    #[msg("signer is not the configured slash executor")]
    NotSlashAuthority = 6000,
    #[msg("signer is not the config admin")]
    NotAdmin = 6001,
    #[msg("signer is not the configured appeal resolver (VULN-04: separate from executor)")]
    NotAppealResolver = 6002,
    #[msg("signer is not the configured pause authority")]
    NotPauseAuthority = 6003,
    #[msg("slash_executor, appeal_resolver and pause_authority must all be distinct keys")]
    AuthoritiesMustDiffer = 6004,
    #[msg("an appeal_resolver may not resolve a slash they also executed")]
    ResolverIsExecutor = 6005,
    #[msg("a role key may not be the all-zero default Pubkey")]
    DefaultPubkey = 6006,

    // ── Input validation ────────────────────────────────────────────────────
    #[msg("offense tier is not a valid OffenseTier code (0 Minor, 1 Major, 2 Compromise)")]
    InvalidOffenseTier = 6010,
    #[msg("evidence_hash is all zeros — a slash must cite evidence")]
    ZeroEvidence = 6011,
    #[msg("stake is below the minimum required to open a vault")]
    StakeBelowMinimum = 6012,

    // ── State preconditions ─────────────────────────────────────────────────
    #[msg("the escrow vault is not active — it has already been terminally slashed")]
    VaultInactive = 6020,
    #[msg("the escrow vault has no remaining stake to slash")]
    NothingToSlash = 6021,
    #[msg("the supplied SlashRecord index does not match the vault's slash_count")]
    SlashIndexMismatch = 6022,
    #[msg("the supplied destination account does not match the offense tier")]
    WrongDestination = 6023,

    // ── Arithmetic / safety ─────────────────────────────────────────────────
    #[msg("lamport arithmetic overflow")]
    MathOverflow = 6030,
    #[msg("vault lamport balance would drop below its rent-exempt minimum")]
    RentViolation = 6031,

    // ── Day 21: appeals ─────────────────────────────────────────────────────
    #[msg("the slash is not in the required lifecycle state for this action")]
    WrongSlashStatus = 6040,
    #[msg("the appeal window for this slash has closed")]
    AppealWindowClosed = 6041,
    #[msg("the appeal window is still open — the slash cannot be settled yet")]
    AppealWindowStillOpen = 6042,
    #[msg("signer is not the owner of the slashed agent")]
    NotAgentOwner = 6043,
    #[msg("appeal justification hash is all zeros — an appeal must cite a reason")]
    ZeroJustification = 6044,
    #[msg("appeal cooldown has not elapsed — too soon since the last appeal")]
    AppealCooldownActive = 6045,
    #[msg("the slash record does not belong to this escrow vault")]
    RecordVaultMismatch = 6046,

    // ── VULN-04: pause + timelock ───────────────────────────────────────────
    #[msg("slash actions are paused by the pause authority")]
    SettlementsPaused = 6060,
    #[msg("slash actions are not paused")]
    NotPaused = 6061,
    #[msg("slash actions are already paused")]
    AlreadyPaused = 6062,
    #[msg("post-uphold settlement timelock has not elapsed yet")]
    SettlementTimelockNotElapsed = 6063,
    #[msg("settlement timelock is shorter than the protocol minimum (72h)")]
    SettlementTimelockTooShort = 6064,

    // ── Day 21: oracle challenges ───────────────────────────────────────────
    #[msg("challenge proof hash is all zeros — a challenge must cite evidence")]
    ZeroProof = 6050,
    #[msg("challenge proof type is not a recognised ProofType code")]
    InvalidProofType = 6051,
    #[msg("the two cited submissions are not actually in conflict")]
    NotInConflict = 6052,
    #[msg("the accused oracle and the challenger must differ")]
    SelfChallenge = 6053,
}
