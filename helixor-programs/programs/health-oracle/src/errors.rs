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
    #[msg("commit_nonce must be strictly greater than the current on-chain nonce \
           (rollback rejected)")]
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
    #[msg("M-03: commit_nonce must be EXACTLY previous + 1 (strict successor) — \
           skips would let a compromised oracle key jump nonces and break the \
           gap-free audit chain consumers walk to verify baseline history")]
    NonceNotStrictSuccessor = 6025,
    #[msg("M-03: baseline nonce space exhausted at u64::MAX — no successor \
           exists. This is a defence-in-depth guard against a compromised \
           oracle key that committed at u64::MAX to burn the nonce space and \
           lock all future baseline rotations")]
    NonceSpaceExhausted = 6026,

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

    // ── AW-02: M-of-N threshold-attested epoch advance ──────────────────────
    #[msg("insufficient cluster Ed25519 attestations for advance_epoch — \
           the transaction must carry ≥ consensus_threshold(cluster) \
           signatures over the canonical advance digest")]
    InsufficientAdvanceAttestations = 6070,
    #[msg("Ed25519 precompile instruction passed to advance_epoch is \
           malformed — header, offsets, or buffer lengths are invalid")]
    MalformedAdvanceEd25519Instruction = 6071,
    #[msg("Ed25519 precompile passed to advance_epoch references signature \
           or message data outside its own instruction — refusing to \
           verify cross-instruction data")]
    AdvanceCrossInstructionReference = 6072,
    #[msg("Ed25519 precompile passed to advance_epoch carries a signed \
           message whose length is not the expected 32-byte digest")]
    WrongAdvanceDigestLength = 6073,
    #[msg("the instructions sysvar account passed to advance_epoch is not \
           the canonical Sysvar1nstructions1111111111111111111111111 pubkey")]
    WrongAdvanceInstructionsSysvar = 6074,

    // ── AW-03: on-chain baseline data-availability proof ────────────────────
    #[msg("baseline payload is empty — refusing to commit a zero-byte canonical \
           payload (the off-chain serializer dropped its body)")]
    BaselinePayloadEmpty = 6080,
    #[msg("baseline payload exceeds MAX_BASELINE_PAYLOAD_LEN (8192 bytes) — \
           the canonical-payload contract has drifted; tighten the serializer \
           and re-commit, the on-chain DA account must stay rent-bounded")]
    BaselinePayloadTooLarge = 6081,
    #[msg("sha256(baseline_payload) does not equal the committed baseline_hash — \
           the on-chain DA invariant (AW-03) refuses to bind a hash to bytes \
           that do not produce it; check the off-chain canonical serializer \
           for drift from baseline.hashing")]
    BaselinePayloadHashMismatch = 6082,
    #[msg("the BaselineDataAccount account passed to commit_baseline is keyed \
           on a commit_nonce that does not match args.commit_nonce — the DA \
           account PDA seed and the commit_nonce arg must agree")]
    BaselineDataNonceMismatch = 6083,
    #[msg("the BaselineDataAccount account passed to commit_baseline is keyed \
           on an agent_wallet that does not match the AgentRegistration agent — \
           the DA account PDA seed and the registration must agree")]
    BaselineDataAgentMismatch = 6084,
}
