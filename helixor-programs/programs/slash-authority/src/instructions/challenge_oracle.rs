// =============================================================================
// programs/slash-authority/src/instructions/challenge_oracle.rs
//
// challenge_oracle — the watchdog mechanism. ANYONE may accuse an oracle
// node of a bad submission.
//
//   challenge_oracle(ctx, proof_type, proof_hash, subject_epoch,
//                    score_a, score_b)
//
// A challenge is recorded as an OracleChallenge PDA. What happens next
// depends on the proof type — and, honestly, on what on-chain code can
// actually verify:
//
//   ConflictingScores — the watchdog claims the oracle signed a score that
//                        conflicts with the anchored cluster median for
//                        the same (agent, epoch). This instruction can
//                        reject non-conflicts (equal scores), but it does
//                        NOT yet load and verify the referenced median /
//                        signature artifacts. Therefore the challenge is
//                        recorded PENDING for slash-authority review.
//
//   PhantomAgent      — the watchdog claims the oracle scored an
//                        unregistered agent. The registration check is a
//                        cross-program lookup left to the resolution step,
//                        so the challenge is recorded PENDING.
//
//   EvidenceHash      — an off-chain-only claim. On-chain code CANNOT
//                        verify it, so the challenge is recorded PENDING
//                        for the governance authority to review. The
//                        program does not pretend to auto-verify it.
//
// EVIDENCE REQUIREMENT: every challenge must cite a non-zero proof_hash.
// SELF-CHALLENGE GUARD: the challenger and the accused oracle must differ.
//
// A challenge is only grounds for oracle-side slashing after the
// slash-authority review verifies the referenced artifacts. This instruction
// records the evidence; it does not itself move or slash funds.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::OracleChallenged;
use crate::state::{
    ChallengeCounter, ChallengeStatus, OracleChallenge, ProofType,
};

#[derive(Accounts)]
pub struct ChallengeOracle<'info> {
    /// The per-oracle challenge counter. Created on the first challenge
    /// against this oracle, incremented thereafter — gives each
    /// OracleChallenge a fresh append-only index.
    #[account(
        init_if_needed,
        payer = challenger,
        space = ChallengeCounter::SPACE,
        seeds = [ChallengeCounter::SEED_PREFIX, accused_oracle.key().as_ref()],
        bump,
    )]
    pub challenge_counter: Account<'info, ChallengeCounter>,

    /// The challenge record — created here, write-once, keyed by the
    /// counter's current value.
    #[account(
        init,
        payer = challenger,
        space = OracleChallenge::SPACE,
        seeds = [
            OracleChallenge::SEED_PREFIX,
            accused_oracle.key().as_ref(),
            &challenge_counter.count.to_le_bytes(),
        ],
        bump,
    )]
    pub challenge: Account<'info, OracleChallenge>,

    /// The oracle node being accused.
    /// CHECK: an arbitrary pubkey — the accused. It is only RECORDED as the
    /// challenge subject; it neither signs nor is mutated here.
    pub accused_oracle: UncheckedAccount<'info>,

    /// The agent the disputed submission concerned — recorded as context.
    /// CHECK: recorded only; not mutated.
    pub subject_agent: UncheckedAccount<'info>,

    /// The watchdog filing the challenge — anyone may do this. Pays rent.
    #[account(mut)]
    pub challenger: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:           Context<ChallengeOracle>,
    proof_type:    u8,
    proof_hash:    [u8; 32],
    subject_epoch: u64,
    score_a:       u16,
    score_b:       u16,
) -> Result<()> {
    // ── Evidence requirement ────────────────────────────────────────────────
    require!(proof_hash != [0u8; 32], SlashError::ZeroProof);

    let tier = ProofType::from_u8(proof_type)
        .ok_or(SlashError::InvalidProofType)?;

    // ── Self-challenge guard ────────────────────────────────────────────────
    require!(
        ctx.accounts.challenger.key() != ctx.accounts.accused_oracle.key(),
        SlashError::SelfChallenge,
    );

    // ── Determine the challenge's initial status by proof type ──────────────
    let status = match tier {
        ProofType::ConflictingScores => {
            // The two cited scores must genuinely differ. Identical scores
            // are not a conflict — reject the challenge outright. The
            // referenced median/certificate artifacts are not yet supplied
            // to this instruction, so this remains Pending.
            require!(score_a != score_b, SlashError::NotInConflict);
            ChallengeStatus::Pending
        }
        ProofType::PhantomAgent => {
            // Registration cross-program check is performed at resolution.
            ChallengeStatus::Pending
        }
        ProofType::EvidenceHash => {
            // NOT on-chain verifiable — recorded for governance review.
            ChallengeStatus::Pending
        }
    };

    // ── Write the challenge record ──────────────────────────────────────────
    let clock = Clock::get()?;
    let index = ctx.accounts.challenge_counter.count;

    let challenge = &mut ctx.accounts.challenge;
    challenge.accused_oracle = ctx.accounts.accused_oracle.key();
    challenge.challenger     = ctx.accounts.challenger.key();
    challenge.index          = index;
    challenge.proof_type     = tier.as_u8();
    challenge.status         = status.as_u8();
    challenge.proof_hash     = proof_hash;
    challenge.subject_agent  = ctx.accounts.subject_agent.key();
    challenge.subject_epoch  = subject_epoch;
    challenge.filed_at       = clock.unix_timestamp;
    challenge.resolved_at    = if status == ChallengeStatus::Pending {
        0
    } else {
        clock.unix_timestamp
    };
    challenge.bump           = ctx.bumps.challenge;
    challenge.layout_version = OracleChallenge::CURRENT_LAYOUT_VERSION;

    // ── Advance the per-oracle counter ──────────────────────────────────────
    let counter = &mut ctx.accounts.challenge_counter;
    counter.accused_oracle = ctx.accounts.accused_oracle.key();
    counter.count          = index
        .checked_add(1)
        .ok_or(SlashError::MathOverflow)?;
    counter.bump           = ctx.bumps.challenge_counter;

    emit!(OracleChallenged {
        accused_oracle:       challenge.accused_oracle,
        challenger:           challenge.challenger,
        index,
        proof_type:           tier.as_u8(),
        status:               status.as_u8(),
        onchain_verifiable:   tier.is_onchain_verifiable(),
        subject_epoch,
        filed_at:             clock.unix_timestamp,
    });

    msg!(
        "oracle challenged: accused={} proof_type={:?} status={:?} index={}",
        challenge.accused_oracle, tier, status, index,
    );
    Ok(())
}
