// =============================================================================
// programs/slash-authority/src/instructions/update_settle_timing.rs
//
// M-07 — Retune the VULN-08 settle_slash timing gates IN-FLIGHT.
//
// Before M-07 the 48h execute->settle floor and the 1h post-appeal-window
// grace were `pub const` in `settle_slash.rs`. Tuning them required a
// program redeploy + a full IDL roll-out — operationally brittle. The
// audit finding asked for the two values to be admin-tunable so an
// incident response can extend the floor (or shorten the grace) without
// touching the binary.
//
// THIS HANDLER:
//   1. Authority-gates against `slash_config.admin` (same key that
//      seeded the values at init).
//   2. Validates both proposed values against the on-chain bounds
//      (`MIN_/MAX_EXECUTE_TO_SETTLE_BOUND` and
//      `MIN_/MAX_SETTLE_GRACE_BOUND`) — a compromised admin key still
//      cannot disable the floor (drop below 12h) or make it permanent
//      (push above 7d), nor collapse the grace beneath 5m.
//   3. Rejects the no-op write (both new values equal to current).
//   4. Writes the two i64 fields, emits `SettleTimingUpdated`.
//
// DELIBERATELY OUT OF SCOPE:
//   * Rotation ceremony. The SPOF-#2 propose/attest/enact flow rotates
//     the THREE role keys + the settlement timelock — the high-stakes
//     authority shape. M-07 is operational tuning of a defence-in-depth
//     timer; gating it behind a 48h-timelock ceremony would defeat the
//     purpose ("retune fast during an incident"). The on-chain BOUNDS
//     are what protect the protocol from a hostile admin key, not the
//     ceremony.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::SettleTimingUpdated;
use crate::state::{
    validate_settle_timing_seconds, SettleTimingBoundsError, SlashConfig,
};

#[derive(Accounts)]
pub struct UpdateSettleTiming<'info> {
    /// The SlashConfig singleton being retuned.
    #[account(
        mut,
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// Admin signer — must equal `slash_config.admin`. The same key that
    /// seeded the defaults at `initialize_config` is the only key that
    /// may retune them. Authority rotation goes through the SPOF-#2
    /// ceremony, not this ix.
    #[account(
        constraint = admin.key() == slash_config.admin
            @ SlashError::NotAdmin,
    )]
    pub admin: Signer<'info>,
}

pub fn handler(
    ctx:                            Context<UpdateSettleTiming>,
    new_execute_to_settle_seconds:  i64,
    new_settle_grace_seconds:       i64,
) -> Result<()> {
    // ── 1. Bound validation ────────────────────────────────────────────────
    // Single helper, shared with the unit tests. The per-field variant
    // disambiguates which bound was violated; both map to the same on-chain
    // error code (the on-chain monitor doesn't need per-field granularity —
    // the unit tests do).
    match validate_settle_timing_seconds(
        new_execute_to_settle_seconds,
        new_settle_grace_seconds,
    ) {
        Ok(()) => {}
        Err(SettleTimingBoundsError::ExecuteToSettleOutOfBounds)
        | Err(SettleTimingBoundsError::SettleGraceOutOfBounds) => {
            return err!(SlashError::SettleTimingOutOfBounds);
        }
    }

    // ── 2. No-op rejection ─────────────────────────────────────────────────
    // Compare against the EFFECTIVE values (not the raw fields) — for a
    // pre-M-07 account whose fields are still 0, "no change" means
    // "rewrite to the defaults", which IS a change and should succeed.
    let cfg = &mut ctx.accounts.slash_config;
    let old_execute_to_settle_seconds = cfg.effective_execute_to_settle_seconds();
    let old_settle_grace_seconds      = cfg.effective_settle_grace_seconds();
    require!(
        old_execute_to_settle_seconds != new_execute_to_settle_seconds
            || old_settle_grace_seconds != new_settle_grace_seconds
            // also fire-through if the raw field is currently 0 even though
            // the effective value matches — explicitly committing the
            // default to storage is operationally distinct from leaving it
            // implicit (cleaner for audit-log replay).
            || cfg.execute_to_settle_seconds == 0
            || cfg.settle_grace_seconds == 0,
        // Reuse the rotation-style no-op error from the SPOF-#2 family —
        // it's the closest semantic match and avoids a new error code for
        // a corner the audit didn't separately call out.
        SlashError::NoopAuthorityRotation,
    );

    // ── 3. Commit + emit ───────────────────────────────────────────────────
    cfg.execute_to_settle_seconds = new_execute_to_settle_seconds;
    cfg.settle_grace_seconds      = new_settle_grace_seconds;

    let clock = Clock::get()?;
    emit!(SettleTimingUpdated {
        admin:                         ctx.accounts.admin.key(),
        old_execute_to_settle_seconds,
        new_execute_to_settle_seconds,
        old_settle_grace_seconds,
        new_settle_grace_seconds,
        updated_at:                    clock.unix_timestamp,
    });

    msg!(
        "settle timing retuned: execute_to_settle {} -> {}, grace {} -> {}",
        old_execute_to_settle_seconds, new_execute_to_settle_seconds,
        old_settle_grace_seconds,      new_settle_grace_seconds,
    );
    Ok(())
}
