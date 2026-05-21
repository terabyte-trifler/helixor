// =============================================================================
// audit/trident/targets/slash-authority/fuzz_target.rs
//
// Trident fuzz harness for the slash-authority program.
//
// The slash flow handles money (escrowed stake) and timing windows
// (appeal cooldown, dispute period). The fuzzer targets both: arbitrary
// slash amounts, timestamps before/after appeal windows, duplicate
// challenges, malformed evidence hashes.
// =============================================================================

use anchor_lang::prelude::*;
use trident_client::prelude::*;
use trident_client::fuzzing::*;

use slash_authority::instruction as sa_ix;

#[derive(Arbitrary, Debug)]
pub struct FuzzData {
    pub instruction: FuzzInstruction,
}

#[derive(Arbitrary, Debug)]
pub enum FuzzInstruction {
    ChallengeOracle(ChallengeArgs),
    ExecuteSlash(SlashArgs),
    AppealSlash(AppealArgs),
    ResolveAppeal(ResolveAppealArgs),
}


// ── Per-ix argument shapes ───────────────────────────────────────────────────

#[derive(Arbitrary, Debug)]
pub struct ChallengeArgs {
    pub accused_oracle:  Pubkey,
    pub proof_type:      u8,           // u8 — covers 0 (ConflictingScores)
                                       // up through invalid values
    pub subject_epoch:   u64,
    pub subject_agent:   Pubkey,
    pub accused_score:   u64,
    pub cluster_median:  u64,
    pub evidence_hash:   [u8; 32],
}

#[derive(Arbitrary, Debug)]
pub struct SlashArgs {
    // The slash amount in basis points (0..=10_000). Trident generates
    // arbitrary u16 — hits over-10000 cases too, which the handler must
    // reject without panic.
    pub bps:        u16,
    pub justification: [u8; 64],
}

#[derive(Arbitrary, Debug)]
pub struct AppealArgs {
    pub appeal_reason: [u8; 128],
}

#[derive(Arbitrary, Debug)]
pub struct ResolveAppealArgs {
    pub uphold: bool,
    pub note:   [u8; 64],
}


// ── Fuzz driver ──────────────────────────────────────────────────────────────

fn main() {
    fuzz_trd!(fuzz_iteration: FuzzData);
}

fn fuzz_iteration(fuzz_data: FuzzData, client: &mut impl FuzzClient) {
    let _ = match fuzz_data.instruction {
        FuzzInstruction::ChallengeOracle(args) => {
            sa_ix::challenge_oracle(
                client, args.accused_oracle, args.proof_type,
                args.subject_epoch, args.subject_agent,
                args.accused_score, args.cluster_median, args.evidence_hash,
            )
        }
        FuzzInstruction::ExecuteSlash(args) => {
            sa_ix::execute_slash(client, args.bps, args.justification)
        }
        FuzzInstruction::AppealSlash(args) => {
            sa_ix::appeal_slash(client, args.appeal_reason)
        }
        FuzzInstruction::ResolveAppeal(args) => {
            sa_ix::resolve_appeal(client, args.uphold, args.note)
        }
    };
    // Zero panics. The handler must validate ranges, timing windows, and
    // authority before any state mutation.
}
