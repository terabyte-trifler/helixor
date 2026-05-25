// =============================================================================
// programs/health-oracle/src/instructions/advance_epoch.rs
//
// advance_epoch — tick the epoch counter at the end of a 24h cycle.
//
// The oracle calls this once per cycle. It increments current_epoch, so the
// next round of certificates is issued under a fresh epoch number — a fresh
// set of ["cert", agent, epoch] PDAs. The previous epoch's certificates are
// untouched: epoch history accumulates on chain.
//
// AUTHORITY (VULN-02 FIX — TWO-TIER ADVANCEMENT)
// -----------------------------------------------
// A single advance_authority key was the only path to tick the epoch. Losing
// or compromising that key would permanently freeze the protocol:
// no new certs could ever be issued.
//
// The fix adds a liveness-fallback tier:
//
//   Tier 1 (normal):  advance_authority may advance at any point after
//                     1 × epoch_duration_seconds has elapsed.
//
//   Tier 2 (fallback): ANY cluster oracle key may advance once
//                     2 × epoch_duration_seconds has elapsed — i.e., the
//                     advance_authority has been silent for a full extra
//                     epoch. This lets the cluster self-heal without admin
//                     intervention if the advance key is lost, compromised,
//                     or held hostage.
//
// The 2× window means a cluster member cannot race the advance_authority
// (they must wait an extra epoch), but it guarantees the protocol is never
// permanently halted by a single key.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::HelixorError;
use crate::events::{EpochAdvanced, EpochAdvancedByFallback};
use crate::state::{EpochState, OracleConfig};

#[derive(Accounts)]
pub struct AdvanceEpoch<'info> {
    /// The epoch counter.
    #[account(
        mut,
        seeds = [EpochState::SEED],
        bump  = epoch_state.bump,
    )]
    pub epoch_state: Account<'info, EpochState>,

    /// OracleConfig — needed to verify cluster membership in the
    /// liveness-fallback path (Tier 2). Always required so the handler
    /// can check the fallback condition without an Option account.
    #[account(
        seeds = [OracleConfig::SEED],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The signer. Authority is validated in the handler (not via a
    /// constraint) because the valid set is conditional on elapsed time:
    ///   - At 1× duration: advance_authority only.
    ///   - At 2× duration: advance_authority OR any cluster key.
    pub advancer: Signer<'info>,
}

pub fn handler(ctx: Context<AdvanceEpoch>) -> Result<()> {
    let clock       = Clock::get()?;
    let now         = clock.unix_timestamp;
    let advancer    = ctx.accounts.advancer.key();

    // Snapshot epoch_state fields before the mutable borrow.
    let advance_authority = ctx.accounts.epoch_state.advance_authority;
    let may_advance       = ctx.accounts.epoch_state.may_advance(now);
    let fallback_open     = ctx.accounts.epoch_state.liveness_fallback_elapsed(now);

    // ── Guard 1: epoch duration must have elapsed ────────────────────────────
    require!(may_advance, HelixorError::EpochNotElapsed);

    // ── Guard 2: authority check (two-tier) ──────────────────────────────────
    let is_advance_authority = advancer == advance_authority;
    let is_cluster_member    = ctx.accounts.oracle_config.is_cluster_member(&advancer);

    // Tier 1: advance_authority can always advance (once duration elapsed).
    // Tier 2: any cluster key can advance only after 2× duration — the
    //         fallback window. A cluster key trying before the fallback opens
    //         gets NotAuthorisedAdvancer, not NotOracleAuthority, so
    //         operators see a precise error.
    require!(
        is_advance_authority || (fallback_open && is_cluster_member),
        HelixorError::NotAuthorisedAdvancer,
    );

    let by_fallback = !is_advance_authority;

    // ── Advance ──────────────────────────────────────────────────────────────
    let epoch_state = &mut ctx.accounts.epoch_state;
    let from        = epoch_state.current_epoch;

    epoch_state.current_epoch    = from
        .checked_add(1)
        .ok_or(HelixorError::EpochCounterOverflow)?;
    epoch_state.last_advanced_at = now;

    emit!(EpochAdvanced {
        from_epoch:  from,
        to_epoch:    epoch_state.current_epoch,
        advanced_at: now,
    });

    // Emit the supplemental fallback event so off-chain monitoring can
    // detect that the liveness fallback fired — an operator should
    // investigate and rotate or restore the advance_authority.
    if by_fallback {
        emit!(EpochAdvancedByFallback {
            from_epoch:  from,
            to_epoch:    epoch_state.current_epoch,
            advanced_at: now,
            cluster_key: advancer,
        });
        msg!(
            "epoch advanced via liveness fallback: {} -> {} by cluster key {}",
            from, epoch_state.current_epoch, advancer,
        );
    } else {
        msg!("epoch advanced: {} -> {}", from, epoch_state.current_epoch);
    }

    Ok(())
}
