// =============================================================================
// programs/slash-authority/src/state/oracle_challenge.rs
//
// OracleChallenge — a watchdog accusation against an oracle node.
//
//     seeds = ["challenge", accused_oracle, count]
//
// THE WATCHDOG MECHANISM
// ----------------------
// challenge_oracle lets ANYONE accuse an oracle node of a bad submission.
// But "provably bad" is a hard claim, and an unverified accusation cannot
// be allowed to slash an oracle unilaterally — that would itself be an
// attack vector. So a challenge is recorded with a PROOF, and the proof
// type determines what happens:
//
//   ConflictingScores — the accused oracle submitted a score that conflicts
//                        with the anchored cluster median for the same
//                        (agent, epoch). Until the instruction accepts the
//                        referenced median/certificate artifacts as accounts,
//                        this is recorded Pending for review rather than
//                        auto-Verified.
//
//   PhantomAgent      — the accused oracle scored an agent that was never
//                        registered. Also recorded Pending until the
//                        registration PDA is checked by the resolver.
//
//   EvidenceHash      — an off-chain-only claim (e.g. the oracle's score
//                        contradicts public data). NOT verifiable on chain
//                        — the challenge is recorded as Pending for the
//                        governance authority to review and resolve.
//
// HONEST SCOPE: on-chain code can only verify what is on chain. The
// No challenge is an automatic slash. challenge_oracle records the
// accusation and evidence hash; slash-authority review verifies the cited
// artifacts before any oracle-side slashing path is executed.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   accused_oracle    32   (Pubkey — the oracle node being challenged)
//   challenger        32   (Pubkey — whoever filed the challenge)
//   index              8   (u64 — per-oracle challenge counter; seed component)
//   proof_type         1   (u8  — ProofType code)
//   status             1   (u8  — ChallengeStatus code)
//   proof_hash        32   ([u8;32] — hash of the cited evidence)
//   subject_agent     32   (Pubkey — the agent the bad submission concerned)
//   subject_epoch      8   (u64 — the epoch of the bad submission)
//   filed_at           8   (i64 — unix seconds the challenge was filed)
//   resolved_at        8   (i64 — unix seconds it was resolved; 0 if not)
//   bump               1   (u8)
//   layout_version     1   (u8)
//   _reserved         32   (zeroed cushion)
//   TOTAL (without discriminator): 196 bytes
// =============================================================================

use anchor_lang::prelude::*;

/// What KIND of proof a challenge cites — and therefore whether the program
/// can verify it on chain.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[borsh(use_discriminant = true)]
pub enum ProofType {
    /// The oracle signed two conflicting scores for one (agent, epoch).
    /// Pending until referenced median/certificate artifacts are verified.
    ConflictingScores = 0,
    /// The oracle scored an unregistered (phantom) agent.
    /// Pending until registration state is checked.
    PhantomAgent = 1,
    /// An off-chain-only claim — recorded for governance review.
    /// NOT on-chain verifiable.
    EvidenceHash = 2,
}

impl ProofType {
    pub fn from_u8(value: u8) -> Option<ProofType> {
        match value {
            0 => Some(ProofType::ConflictingScores),
            1 => Some(ProofType::PhantomAgent),
            2 => Some(ProofType::EvidenceHash),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this proof type is self-verifying in this instruction.
    pub fn is_onchain_verifiable(self) -> bool {
        false
    }
}

/// The lifecycle state of an oracle challenge.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[borsh(use_discriminant = true)]
pub enum ChallengeStatus {
    /// Recorded, awaiting governance review (the EvidenceHash path).
    Pending = 0,
    /// Proof checked and confirmed by a resolver — grounds for oracle slashing.
    Verified = 1,
    /// Reviewed and dismissed — the accusation did not hold.
    Dismissed = 2,
}

impl ChallengeStatus {
    pub fn from_u8(value: u8) -> Option<ChallengeStatus> {
        match value {
            0 => Some(ChallengeStatus::Pending),
            1 => Some(ChallengeStatus::Verified),
            2 => Some(ChallengeStatus::Dismissed),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[account]
#[derive(Debug)]
pub struct OracleChallenge {
    /// The oracle node being challenged.
    pub accused_oracle: Pubkey,
    /// Whoever filed the challenge (the watchdog).
    pub challenger:     Pubkey,
    /// Per-oracle challenge index — part of the PDA seed, append-only.
    pub index:          u64,
    /// The proof type (ProofType code).
    pub proof_type:     u8,
    /// The challenge status (ChallengeStatus code).
    pub status:         u8,
    /// Hash of the cited evidence.
    pub proof_hash:     [u8; 32],
    /// The agent the disputed submission concerned.
    pub subject_agent:  Pubkey,
    /// The epoch of the disputed submission.
    pub subject_epoch:  u64,
    /// Unix seconds the challenge was filed.
    pub filed_at:       i64,
    /// Unix seconds the challenge was resolved (0 while unresolved).
    pub resolved_at:    i64,
    /// Canonical PDA bump.
    pub bump:           u8,
    /// Account-layout version.
    pub layout_version: u8,
    /// Zero-padded reserve.
    pub _reserved:      [u8; 32],
}

impl OracleChallenge {
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 32 + 8 + 1 + 1 + 32 + 32 + 8 + 8 + 8 + 1 + 1 = 164
    /// + 32 reserved                                        =  32
    ///   = 196
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 32 + 8 + 1 + 1 + 32 + 32 + 8 + 8 + 8 + 1 + 1 + 32;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"challenge";
}

/// An oracle-node challenge counter — one per accused oracle, so each new
/// OracleChallenge PDA has a fresh, append-only index.
///
/// PDA seeds: `["challenge_counter", accused_oracle]`.
#[account]
#[derive(Default, Debug)]
pub struct ChallengeCounter {
    /// The oracle this counter tracks.
    pub accused_oracle: Pubkey,
    /// How many challenges have been filed against it. Monotonic.
    pub count:          u64,
    /// Canonical PDA bump.
    pub bump:           u8,
}

impl ChallengeCounter {
    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + 32 + 8 + 1;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"challenge_counter";
}
