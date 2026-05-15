// =============================================================================
// programs/health-oracle/src/instructions/commit_baseline.rs
//
// commit_baseline — write the 32-byte canonical baseline hash to the agent's
// AgentRegistration PDA. This is the value that makes every subsequent score
// PROVABLY derived from a fixed, public commitment.
//
// AUTHORITY MODEL (intentional, not "either-or" sloppy):
//
//   - The CANONICAL committer is the oracle. It runs the baseline engine,
//     produces the canonical hash, and signs the commit every 30 days.
//
//   - The owner can override IN AN EMERGENCY — e.g. the oracle is unavailable
//     and the owner wants to lock in a recomputed baseline so scoring resumes.
//     The owner override is a separate flag, NOT a hidden second authority.
//     Every commit records which kind wrote it (`baseline_committer` + the
//     `BaselineCommitted` event carries `committer_kind`).
//
// REPLAY PROTECTION:
//   commit_nonce is monotonically increasing. A replayed transaction (same
//   signature, different fee payer) hits the same account, sees the bumped
//   nonce, and reverts.
//
// IMMUTABILITY:
//   The CURRENT baseline_hash is mutable (baselines rotate every 30 days),
//   but each commit emits a BaselineCommitted event. The off-chain indexer
//   captures these into an append-only log — that is the HISTORY of every
//   commit, even though the on-chain account only holds the latest.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::HelixorError;
use crate::events::{BaselineCommitted, CommitterKind};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct CommitBaselineArgs {
    /// 32-byte SHA-256 commitment computed by the off-chain baseline engine.
    pub baseline_hash: [u8; 32],
    /// Algorithm version that produced the hash. Non-zero.
    pub baseline_algo_version: u8,
    /// Strictly greater than the agent's current commit_nonce. Replay defence.
    pub commit_nonce: u64,
    /// Whether this commit is from the oracle (canonical) or the owner (override).
    pub committer_kind: CommitterKind,
}

pub fn handler(ctx: Context<crate::CommitBaseline>, args: CommitBaselineArgs) -> Result<()> {
    let reg = &mut ctx.accounts.agent_registration;
    let config = &ctx.accounts.oracle_config;
    let signer = &ctx.accounts.signer;

    // 1. Authority check — depends on committer_kind. Distinct paths, distinct
    //    errors, so we always know which authority "type" failed.
    match args.committer_kind {
        CommitterKind::Oracle => {
            require_keys_eq!(
                signer.key(),
                config.oracle_key,
                HelixorError::NotOracleAuthority
            );
        }
        CommitterKind::Owner => {
            require_keys_eq!(signer.key(), reg.owner_wallet, HelixorError::NotAgentOwner);
        }
    }

    // 2. Hash sanity — all-zero hash means the committer didn't actually
    //    compute anything. Refuse silently-empty commitments.
    require!(
        args.baseline_hash.iter().any(|&b| b != 0),
        HelixorError::ZeroHash
    );

    // 3. Algo version sanity — zero means "unversioned", which makes the
    //    commitment unauditable. Refuse.
    require!(
        args.baseline_algo_version > 0,
        HelixorError::ZeroAlgoVersion
    );

    // 4. Replay protection — strict monotonicity.
    require!(
        args.commit_nonce > reg.commit_nonce,
        HelixorError::NonMonotonicNonce
    );

    let clock = Clock::get()?;
    let first_commit = !reg.baseline_committed;

    // 5. Write the new commitment. The previous values flow into the event
    //    (and thus the off-chain append-only history).
    reg.baseline_committed = true;
    reg.baseline_hash = args.baseline_hash;
    reg.baseline_algo_version = args.baseline_algo_version;
    reg.baseline_committer = signer.key();
    reg.baseline_committed_at = clock.unix_timestamp;
    reg.commit_nonce = args.commit_nonce;

    // 6. Emit the event for the indexer.
    emit!(BaselineCommitted {
        agent_wallet: reg.agent_wallet,
        committer: signer.key(),
        baseline_hash: args.baseline_hash,
        baseline_algo_version: args.baseline_algo_version,
        commit_nonce: args.commit_nonce,
        committed_at: clock.unix_timestamp,
        first_commit,
        committer_kind: args.committer_kind,
    });

    Ok(())
}
