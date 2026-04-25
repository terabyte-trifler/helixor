// =============================================================================
// Helixor Error Codes — health-oracle program
//
// Stable, numbered error codes. DO NOT re-order: TypeScript clients address
// errors by code number (6000 + index), not by name.
//
// Each error should answer: "what did the caller do wrong, and what should
// they do to fix it?" in the message text. These messages appear in the
// operator's logs at 2am when something breaks.
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum HelixorError {
    // ── Registration — 6000-6003 ─────────────────────────────────────────────
    /// Cause: RegisterParams.name.len() > 64 bytes
    /// Fix:   Use a shorter agent name (UTF-8 bytes, not characters)
    #[msg("Agent name exceeds 64 bytes. Use a shorter name.")]
    NameTooLong,                                    // 6000

    /// Cause: RegisterParams.name is empty
    /// Fix:   Provide a non-empty agent name (at least 1 byte)
    #[msg("Agent name cannot be empty.")]
    NameEmpty,                                      // 6001

    /// Cause: owner balance < MIN_ESCROW_LAMPORTS + rent for PDAs
    /// Fix:   Fund the owner wallet with at least 0.02 SOL before registering
    #[msg("Owner balance is below the minimum required (0.01 SOL escrow + rent).")]
    InsufficientEscrow,                             // 6002

    /// Cause: agent_wallet and owner are the same pubkey
    /// Fix:   Use a separate wallet for the agent (hot wallet) from owner (cold wallet)
    #[msg("Agent wallet must be different from the owner wallet.")]
    AgentSameAsOwner,                               // 6003

    // ── Scoring / Query — 6004-6007 ──────────────────────────────────────────
    /// Cause: AgentRegistration PDA does not exist for this agent_wallet
    /// Fix:   Call register_agent first
    #[msg("Agent is not registered with Helixor.")]
    NotRegistered,                                  // 6004

    /// Cause: Consuming protocol called requireMinScore and score < minimum
    /// Fix:   Agent must accumulate good on-chain behaviour to raise score
    #[msg("Agent trust score is below the required minimum.")]
    ScoreTooLow,                                    // 6005

    /// Cause: Certificate updated_at is more than 48h ago
    /// Fix:   Oracle has stalled — operator should alert Helixor team
    #[msg("Trust certificate is stale (>48h since last oracle update).")]
    StaleCertificate,                               // 6006

    /// Cause: update_score called by a non-oracle signer
    /// Fix:   Only the registered oracle key can submit score updates
    #[msg("Caller is not the authorized Helixor oracle node.")]
    UnauthorizedOracle,                             // 6007

    // ── Guard Rails — 6008-6009 ──────────────────────────────────────────────
    /// Cause: New score differs from previous by more than 200 points
    /// Fix:   Oracle bug — scores should change gradually, not jump
    #[msg("Score change exceeds the 200-point per-epoch guard rail.")]
    ScoreDeltaTooLarge,                             // 6008

    /// Cause: update_score called within 23h of previous update
    /// Fix:   Wait until 23h have elapsed since last update
    #[msg("Score already updated within the last 23 hours.")]
    UpdateTooFrequent,                              // 6009

    // ── Safety — 6010 ────────────────────────────────────────────────────────
    /// Cause: Checked arithmetic overflow. Should never fire in correct code.
    /// Fix:   File a bug report with the transaction signature
    #[msg("Integer arithmetic overflow — please report this bug.")]
    MathOverflow,                                   // 6010
}
