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
//
// VULN-10 — BASELINE-ROLLBACK HARDENING
// -------------------------------------
// The audit raised a baseline-rollback / nonce-gap attack: a compromised
// oracle-node key could rotate the baseline to a stale-favorable hash
// using only nonce > current. Three layered mitigations now apply:
//
//   1. MIN_SECONDS_BETWEEN_ORACLE_COMMITS — the Oracle path may not
//      rotate the baseline more than once per 24h (one epoch). A
//      compromised oracle key cannot machine-gun rotations.
//
//   2. Owner override has NO cooldown — the owner is the EMERGENCY
//      RESET path. If a rotation is detected as malicious, the owner
//      can immediately commit the correct hash without waiting for the
//      oracle cooldown to release.
//
//   3. BaselineRotated event — emitted IN ADDITION to BaselineCommitted
//      on every non-first commit. Carries the FULL previous state
//      (hash, committer, timestamp, nonce) plus `seconds_since_previous`
//      so the owner's off-chain monitor can page on suspicious rotations.
//
// FIRST COMMIT is unaffected — the cooldown only fires once a baseline
// has been established. The event-only-on-non-first rule means the
// monitor sees a quiet first commit and noisy rotations.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::HelixorError;
use crate::events::{BaselineCommitted, BaselineRotated, CommitterKind};
use crate::state::{AgentRegistration, OracleConfig};


// =============================================================================
// VULN-10 — pure helpers (unit-testable without a runtime)
// =============================================================================

/// The cooldown floor between TWO Oracle-path baseline commits.
/// 86_400 seconds == 24 hours == one epoch. A real baseline rotation
/// cycle is 30 days; this floor is well below that, so a normal
/// schedule is never blocked. A compromised oracle key, however, is
/// gated to AT MOST one rotation per 24h, giving the owner a guaranteed
/// detection-and-override window.
pub const MIN_SECONDS_BETWEEN_ORACLE_COMMITS: i64 = 86_400;

/// Pure VULN-10 timing check — extracted so it is unit-testable.
///
/// Rules (in order of evaluation):
///   - FIRST COMMIT (baseline_committed == false): always allowed.
///   - OWNER PATH:  always allowed; the owner is the emergency reset.
///   - ORACLE PATH on a non-first commit: must be at least
///     MIN_SECONDS_BETWEEN_ORACLE_COMMITS seconds after the previous
///     commit timestamp. Earlier commits fail with
///     OracleCommitCooldownActive.
///
/// `previous_committed_at` is `reg.baseline_committed_at` BEFORE this
/// write. `now` is `Clock::get()?.unix_timestamp`.
pub fn check_oracle_commit_cooldown(
    baseline_committed:     bool,
    previous_committed_at:  i64,
    committer_kind:         CommitterKind,
    now:                    i64,
) -> Result<()> {
    if !baseline_committed {
        return Ok(());
    }
    if committer_kind == CommitterKind::Owner {
        return Ok(());
    }
    let earliest = previous_committed_at
        .checked_add(MIN_SECONDS_BETWEEN_ORACLE_COMMITS)
        .ok_or(HelixorError::BaselineTimestampOverflow)?;
    require!(now >= earliest, HelixorError::OracleCommitCooldownActive);
    Ok(())
}

#[derive(Accounts)]
#[instruction(args: CommitBaselineArgs)]
pub struct CommitBaseline<'info> {
    /// The agent registration we are committing on. Must be active and at
    /// the current layout version (older layouts need migrate_registration).
    #[account(
        mut,
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump  = agent_registration.bump,
        constraint = agent_registration.active                                  @ HelixorError::AgentInactive,
        constraint = agent_registration.layout_version == AgentRegistration::CURRENT_LAYOUT_VERSION
            @ HelixorError::LayoutMigrationRequired,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    /// OracleConfig — read to determine the canonical oracle authority.
    /// We never hard-code the oracle pubkey; OracleConfig is the source of truth
    /// so the eventual 3-of-5 multisig rotation is one config write away.
    #[account(
        seeds = [b"oracle_config"],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The signer claiming the right to commit. Validated in the handler:
    ///   - if args.committer_kind == Oracle, signer must equal oracle_config.oracle_node
    ///   - if args.committer_kind == Owner,  signer must equal agent_registration.owner_wallet
    pub signer: Signer<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct CommitBaselineArgs {
    /// 32-byte SHA-256 commitment computed by the off-chain baseline engine.
    pub baseline_hash:          [u8; 32],
    /// Algorithm version that produced the hash. Non-zero.
    pub baseline_algo_version:  u8,
    /// Strictly greater than the agent's current commit_nonce. Replay defence.
    pub commit_nonce:           u64,
    /// Whether this commit is from the oracle (canonical) or the owner (override).
    pub committer_kind:         CommitterKind,
}

pub fn handler(ctx: Context<CommitBaseline>, args: CommitBaselineArgs) -> Result<()> {
    let reg    = &mut ctx.accounts.agent_registration;
    let config = &ctx.accounts.oracle_config;
    let signer = &ctx.accounts.signer;

    // 1. Authority check — depends on committer_kind. Distinct paths, distinct
    //    errors, so we always know which authority "type" failed.
    match args.committer_kind {
        CommitterKind::Oracle => {
            require_keys_eq!(
                signer.key(),
                config.oracle_node,
                HelixorError::NotOracleAuthority
            );
        }
        CommitterKind::Owner => {
            require_keys_eq!(
                signer.key(),
                reg.owner_wallet,
                HelixorError::NotAgentOwner
            );
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
    let now   = clock.unix_timestamp;
    let first_commit = !reg.baseline_committed;

    // VULN-10: Oracle-path cooldown. First commit is unaffected; the
    // Owner path is the emergency reset and is also unaffected. Only an
    // Oracle-path ROTATION is gated to a minimum 24h gap from the
    // previous commit, so a compromised oracle key cannot rotate the
    // baseline more than once per epoch.
    check_oracle_commit_cooldown(
        reg.baseline_committed,
        reg.baseline_committed_at,
        args.committer_kind,
        now,
    )?;

    // Capture the pre-write state so the rotation event below carries
    // an accurate diff. These reads are no-ops on a first commit.
    let previous_hash:         [u8; 32] = reg.baseline_hash;
    let previous_committer:    Pubkey   = reg.baseline_committer;
    let previous_committed_at: i64      = reg.baseline_committed_at;
    let previous_nonce:        u64      = reg.commit_nonce;

    // 5. Write the new commitment. The previous values flow into the event
    //    (and thus the off-chain append-only history).
    reg.baseline_committed     = true;
    reg.baseline_hash          = args.baseline_hash;
    reg.baseline_algo_version  = args.baseline_algo_version;
    reg.baseline_committer     = signer.key();
    reg.baseline_committed_at  = now;
    reg.commit_nonce           = args.commit_nonce;

    // 6. Emit the event for the indexer.
    emit!(BaselineCommitted {
        agent_wallet:           reg.agent_wallet,
        committer:              signer.key(),
        baseline_hash:          args.baseline_hash,
        baseline_algo_version:  args.baseline_algo_version,
        commit_nonce:           args.commit_nonce,
        committed_at:           now,
        first_commit,
        committer_kind:         args.committer_kind,
    });

    // VULN-10: ROTATION event — only on non-first commits. Carries the
    // FULL previous state so the owner's monitor can show the diff and
    // compute `seconds_since_previous` without joining the indexer log.
    if !first_commit {
        let seconds_since_previous = now.saturating_sub(previous_committed_at);
        emit!(BaselineRotated {
            agent_wallet:             reg.agent_wallet,
            committer:                signer.key(),
            committer_kind:           args.committer_kind,
            new_baseline_hash:        args.baseline_hash,
            previous_baseline_hash:   previous_hash,
            previous_committer,
            previous_committed_at,
            previous_commit_nonce:    previous_nonce,
            new_commit_nonce:         args.commit_nonce,
            seconds_since_previous,
            rotated_at:               now,
        });
    }

    Ok(())
}
