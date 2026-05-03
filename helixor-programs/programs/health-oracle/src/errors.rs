use anchor_lang::prelude::*;

#[error_code]
pub enum HelixorError {
    // Registration 6000-6003
    #[msg("Agent name exceeds 64 bytes. Use a shorter name.")]
    NameTooLong,
    #[msg("Agent name cannot be empty.")]
    NameEmpty,
    #[msg("Owner balance is below the minimum required.")]
    InsufficientEscrow,
    #[msg("Agent wallet must be different from the owner wallet.")]
    AgentSameAsOwner,

    // Scoring/Query 6004-6008
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

    // Guard rails 6009-6012
    #[msg("Score change exceeds the 200-point per-epoch guard rail.")]
    ScoreDeltaTooLarge,
    #[msg("Score updates must be at least 23 hours apart.")]
    UpdateTooFrequent,
    #[msg("Cannot update score for a deactivated agent.")]
    AgentDeactivated,
    #[msg("Score must be in range 0-1000.")]
    ScoreOutOfRange,

    // Oracle config 6013-6016
    #[msg("Caller is not the authorized Helixor admin.")]
    UnauthorizedAdmin,
    #[msg("Oracle is currently paused — no score updates accepted.")]
    OraclePaused,
    #[msg("Oracle key cannot equal admin key.")]
    OracleKeyEqualsAdmin,
    #[msg("Success rate basis points must be 0-10000.")]
    SuccessRateOutOfRange,

    // Safety 6017
    #[msg("Integer arithmetic overflow — please report this bug.")]
    MathOverflow,

    #[msg("Caller is not the hard-coded bootstrap authority.")]
    UnauthorizedBootstrap,
}
