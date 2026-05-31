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
    #[msg("M-01: this vault already has an Appealed slash in flight — only one \
           appeal per vault may be open at a time. Wait for resolve_appeal \
           on the existing appeal before filing another.")]
    AppealAlreadyInFlight = 6047,

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
    #[msg("H-04: pause duration must be > 0 and <= MAX_PAUSE_SECONDS (7 days) — \
           indefinite pauses are not permitted, the pause_authority must re-pause")]
    PauseDurationInvalid = 6065,
    #[msg("H-04 (absolute cap): pause cooldown has not elapsed — \
           PAUSE_COOLDOWN_SECONDS must pass between the END of the previous \
           pause window (paused_until) and the START of the next, even if the \
           previous pause was manually unpaused early. This caps the worst-case \
           duty cycle a compromised pause_authority can sustain.")]
    PauseCooldownActive = 6066,

    // ── VULN-08: settle_slash timing gates ──────────────────────────────────
    #[msg("minimum execute to settle gap (48h) has not elapsed — defence in \
           depth against immediate settlement griefing")]
    ExecuteToSettleGapTooShort = 6070,
    #[msg("post-appeal-window grace period has not elapsed — protects an \
           appeal that landed in the same slot as the deadline")]
    AppealGraceWindowActive = 6071,
    #[msg("M-07: settle-timing parameter out of permitted bounds — \
           execute_to_settle_seconds must lie in [12h, 7d] and \
           settle_grace_seconds in [5m, 24h]")]
    SettleTimingOutOfBounds = 6072,

    // ── Day 21: oracle challenges ───────────────────────────────────────────
    #[msg("challenge proof hash is all zeros — a challenge must cite evidence")]
    ZeroProof = 6050,
    #[msg("challenge proof type is not a recognised ProofType code")]
    InvalidProofType = 6051,
    #[msg("the two cited submissions are not actually in conflict")]
    NotInConflict = 6052,
    #[msg("the accused oracle and the challenger must differ")]
    SelfChallenge = 6053,

    // ── SPOF-#2: time-locked, 2-of-3-attested authority rotation ───────────
    #[msg("signer is not admin or a current role key — cannot propose a rotation")]
    NotRotationProposer = 6080,
    #[msg("signer is not a current role key — only executor / resolver / \
           pauser may attest. Admin attestations do not count by design.")]
    NotRoleKeyAttester = 6081,
    #[msg("this role key has already attested to the open proposal")]
    DuplicateAuthorityAttestation = 6082,
    #[msg("authority rotation timelock has not elapsed — wait 48h+ from \
           proposed_at before enacting")]
    RotationTimelockNotElapsed = 6083,
    #[msg("authority rotation has fewer than 2 attestations from the 3 \
           current role keys")]
    InsufficientAuthorityAttestations = 6084,
    #[msg("authority rotation timelock floor is 48h — propose with a \
           larger timelock_seconds")]
    RotationTimelockTooShort = 6085,
    #[msg("proposed authority set is identical to the current authority \
           set — no-op rotation rejected")]
    NoopAuthorityRotation = 6086,
    #[msg("signer is not admin or a current role key — cannot cancel a \
           pending rotation")]
    NotRotationCanceller = 6087,
    #[msg("single-admin update_authorities is removed — use the \
           propose/attest/enact ceremony")]
    SingleAdminUpdateRemoved = 6088,

    // ── M-08: authority-epoch counter overflow ──────────────────────────────
    #[msg("M-08: slash_config_version would overflow u32 — refuse to wrap. \
           This is operationally unreachable (would require 4 billion \
           authority rotations) but is guarded to keep the audit invariant \
           strict-monotonic forever.")]
    SlashConfigVersionOverflow = 6089,

    // ── M-11: lamport-audit invariant on direct mutation ────────────────────
    #[msg("M-11: post-mutation lamport balances do not balance against \
           the slashed_lamports amount. The vault was either over-debited / \
           under-debited, or the destination over-credited / under-credited. \
           This indicates a partial-update bug or an intervening account-info \
           aliasing problem. Refusing to commit the tx so the audit trail \
           never carries an inconsistent SlashSettled event.")]
    LamportAuditMismatch = 6090,

    // ── M-14: defence-in-depth System Program ID pin on open_vault ──────────
    // The audit flagged a hypothetical "fake system_program" attack on
    // open_vault and concluded it is NOT a real finding: Anchor's
    // `Program<'info, System>` constraint enforces the account's pubkey
    // against `solana_program::system_program::ID` at the deserialize gate,
    // before the handler runs. The finding is listed as informational
    // hardening only.
    //
    // M-14 still earns its keep by adding a REDUNDANT in-handler
    // `require_keys_eq!` against the same canonical ID. The check is a
    // tripwire for a future refactor that weakens the account type to
    // `UncheckedAccount<'info>` or `AccountInfo<'info>` (e.g. to add a
    // shim or wrap the program in a custom verifier) and forgets to
    // re-add the pubkey check. The defense-in-depth layer fails the tx
    // with this code if the System Program ID drifts, instead of letting
    // a System-CPI transfer route through an attacker-controlled program.
    #[msg("M-14: system_program account passed to open_vault is not the \
           canonical 11111111111111111111111111111111 System Program ID. \
           Anchor's `Program<'info, System>` constraint already enforces \
           this at deserialize — this redundant in-handler check is a \
           defence-in-depth tripwire for a future refactor that weakens \
           the account type. Refusing to CPI into an attacker-controlled \
           program for the staker -> vault transfer.")]
    SystemProgramIdMismatch = 6100,
}
