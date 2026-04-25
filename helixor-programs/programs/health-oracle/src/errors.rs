use anchor_lang::prelude::*;

#[error_code]
pub enum HelixorError {
    // Registration 6000-6003
    #[msg("Agent name exceeds 64 bytes. Use a shorter name.")]
    NameTooLong,
    #[msg("Agent name cannot be empty.")]
    NameEmpty,
    #[msg("Owner balance is below the minimum required (0.01 SOL escrow + rent).")]
    InsufficientEscrow,
    #[msg("Agent wallet must be different from the owner wallet.")]
    AgentSameAsOwner,

    // Scoring / Query 6004-6008
    #[msg("Agent is not registered with Helixor.")]
    NotRegistered,
    #[msg("Agent trust score is below the required minimum.")]
    ScoreTooLow,
    #[msg("Trust certificate is stale (>48h since last oracle update).")]
    StaleCertificate,
    #[msg("Caller is not the authorized Helixor oracle node.")]
    UnauthorizedOracle,
    #[msg("Trust certificate account address does not match the canonical PDA.")]
    InvalidCertificateAddress,

    // Guard rails 6009-6010
    #[msg("Score change exceeds the 200-point per-epoch guard rail.")]
    ScoreDeltaTooLarge,
    #[msg("Score already updated within the last 23 hours.")]
    UpdateTooFrequent,

    // Safety 6011
    #[msg("Integer arithmetic overflow — please report this bug.")]
    MathOverflow,
}
