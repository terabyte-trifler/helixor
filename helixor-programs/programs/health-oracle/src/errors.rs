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
    #[msg("oracle baseline rotation is in cooldown — wait at least one epoch \
           since the previous commit, or use the owner override path")]
    OracleCommitCooldownActive = 6023,
    #[msg("baseline timestamp arithmetic overflow")]
    BaselineTimestampOverflow = 6024,

    // ── Migration ───────────────────────────────────────────────────────────
    #[msg("registration is already at the current layout version")]
    AlreadyMigrated = 6030,

    // ── Day 19: epoch + score submission ────────────────────────────────────
    #[msg("epoch cannot advance yet — the epoch duration has not elapsed")]
    EpochNotElapsed = 6040,
    #[msg("score exceeds the maximum (1000)")]
    ScoreOutOfRange = 6041,
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
    #[msg("epoch counter overflow — protocol has been running long enough \
           to exceed u64; recreate the epoch state")]
    EpochCounterOverflow = 6053,
    #[msg("signer is not the advance authority, and the liveness-fallback \
           window (2× epoch duration) has not elapsed or the signer is not \
           a cluster member")]
    NotAuthorisedAdvancer = 6054,
    #[msg("new_authority is the zero pubkey — rotation to the default key is \
           not permitted")]
    ZeroAdvanceAuthority = 6055,
    #[msg("new_authority equals the current advance_authority — no-op rotation \
           is not permitted")]
    SameAdvanceAuthority = 6056,

    // ── VULN-13: oracle key rotation governance ────────────────────────────
    #[msg("signer is neither the OracleConfig admin nor a current cluster \
           member — only those two roles may propose or cancel a key rotation")]
    NotRotationProposer = 6060,
    #[msg("signer is not a current cluster member — only members of the \
           live OracleConfig.oracle_keys may attest to a rotation proposal")]
    NotClusterMemberAttester = 6061,
    #[msg("timelock_seconds is below the protocol minimum (48h)")]
    TimelockTooShort = 6062,
    #[msg("a key rotation proposal is already in flight — enact or cancel \
           it before proposing another")]
    PendingRotationExists = 6063,
    #[msg("the proposed new_keys equal the current cluster — no-op \
           rotation is not permitted")]
    NoopRotation = 6064,
    #[msg("the rotation timelock has not elapsed — proposal is not yet \
           enactable")]
    TimelockNotElapsed = 6065,
    #[msg("insufficient attestations from the current cluster — a strict \
           majority of the live OracleConfig.oracle_keys must attest")]
    InsufficientAttestations = 6066,
    #[msg("this cluster member has already attested to the current \
           proposal — double-voting is not permitted")]
    DuplicateAttestation = 6067,
    #[msg("the OracleConfig PDA passed to enact does not match the one \
           referenced by the pending rotation — refusing to apply to a \
           different cluster")]
    OracleConfigMismatch = 6068,
}
