// =============================================================================
// programs/slash-authority/src/instructions/settle_slash.rs
//
// settle_slash — finalise a Pending slash after its appeal window closes.
//
// This is the second half of the slash lifecycle that Day 21 split out of
// Day 20's execute_slash. execute_slash ENCUMBERED the funds (held them in
// the vault); settle_slash MOVES them — to the treasury for a Minor/Major
// penalty, or to the incinerator (burned) for a Compromise.
//
// PRECONDITIONS
//   - the SlashRecord is still Pending (an Appealed slash must be resolved
//     first; an Overturned/Settled slash is terminal),
//   - the appeal window has CLOSED — `now >= appeal_deadline`. A slash can
//     never be settled while the agent could still appeal it,
//   - VULN-04: the post-uphold settlement timelock has elapsed,
//   - VULN-08: the minimum execute->settle gap (48h) has elapsed, AND
//     the post-appeal-window grace period (1h) has elapsed.
//
// HOW LAMPORTS LEAVE THE VAULT — same direct-mutation pattern as Day 20:
// the vault is program-owned, so we cannot System-transfer out of it; we
// debit the vault's lamports and credit the destination's directly. Only
// the `encumbered_lamports` for THIS slash is moved, and the vault stays
// at or above its rent-exempt minimum.
//
// A Compromise settlement also DEACTIVATES the vault — the terminal step
// Day 20 did inline, now deferred here so an appeal could have rescued it.
//
// VULN-08 — TIMING-ATTACK HARDENING
// ---------------------------------
// The audit raised three attack patterns that, while not directly
// realisable against the prior Day-21/VULN-04 design (settle_slash was
// already signer-gated to the executor and appeal-window-gated), needed
// stronger defence in depth:
//
//   1. MEV front-running an appeal — a bot races settle_slash against
//      an appeal landing in the same block as the deadline. Mitigation:
//      a post-appeal grace period — refuse to settle until N seconds
//      AFTER the appeal window closes, so an appeal that *almost*
//      landed has time to actually land.
//
//   2. Same-block griefing — an executor whose role key is compromised
//      executes + settles in the same tx, before any human notices.
//      Mitigation: an execute->settle FLOOR — refuse to settle until M
//      seconds after execute_slash, REGARDLESS of appeal status. A
//      SECOND, independent timer on top of the appeal window (which is
//      72h, so this floor never blocks a normal flow).
//
//   3. Invisible spray attacks — repeated settle_slash attempts can
//      probe an appeal's mempool timing. Mitigation: emit
//      SettleSlashAttempted on EVERY call, BEFORE the gates run, so the
//      off-chain monitor sees rejected attempts and can alert on
//      patterns clustering around an appeal.
//
// All three of these are pure-defensive additions: a clean,
// well-spaced-out slash lifecycle passes through them with no behavioural
// change.
//
// M-07 — TIMING IS ON-CHAIN-TUNABLE
// ---------------------------------
// The VULN-08 fix originally hard-coded the floor (M = 48h) and grace
// (N = 1h) as `pub const`. The M-07 audit follow-up flagged that any
// real incident demanding a different M/N would require a full program
// redeploy. M-07 therefore:
//   * keeps the existing 48h / 1h numbers as `DEFAULT_*`,
//   * moves the live values onto `SlashConfig.execute_to_settle_seconds`
//     and `SlashConfig.settle_grace_seconds`,
//   * changes `check_settle_timing` to TAKE the timing values as args
//     instead of reading consts — the handler now passes whatever
//     `SlashConfig.effective_*` accessors return,
//   * adds `update_settle_timing` as a separate admin-gated ix that
//     validates against on-chain bounds and emits an event.
// The transformation is layout-preserving (the two i64 fields are
// carved from `_reserved`), so pre-M-07 accounts keep working — their
// zeroed fields fall through to the defaults via `effective_*`.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::SlashError;
use crate::events::{SettleSlashAttempted, SlashSettled};
use crate::state::{
    EscrowVault, OffenseTier, SlashConfig, SlashDestination, SlashRecord,
    SlashStatus,
};

/// M-07: the DEFAULTS for the two VULN-08 timing gates. These match the
/// original VULN-08 hard-coded values exactly — M-07 is mobility, not a
/// re-tune. They are re-exported here so existing imports of the
/// per-instruction const names keep working (the test surface and the
/// `SlashConfig::effective_*` fallbacks both read from these).
pub use crate::state::{
    DEFAULT_EXECUTE_TO_SETTLE_SECONDS, DEFAULT_SETTLE_GRACE_SECONDS,
};

/// Pure VULN-08 timing check — extracted so it is unit-testable without
/// a runtime. Both gates must be satisfied; the order they are checked
/// is fixed for stable error attribution.
///
/// M-07: the two timing values are now PARAMETERS (read from
/// SlashConfig at the handler boundary), not file-level consts. This is
/// the on-chain-tunability surface. Callers MUST pass the values
/// returned by `SlashConfig::effective_*` so pre-M-07 accounts that
/// stored zero get the documented 48h/1h defaults instead of trivially
/// passing the gates.
pub fn check_settle_timing(
    executed_at:                   i64,
    appeal_deadline:               i64,
    now:                           i64,
    execute_to_settle_seconds:     i64,
    settle_grace_seconds:          i64,
) -> Result<()> {
    // Gate A: the execute->settle floor.
    let min_settle_at = executed_at
        .checked_add(execute_to_settle_seconds)
        .ok_or(SlashError::MathOverflow)?;
    require!(
        now >= min_settle_at,
        SlashError::ExecuteToSettleGapTooShort,
    );

    // Gate B: the appeal-window grace period.
    let earliest_settle = appeal_deadline
        .checked_add(settle_grace_seconds)
        .ok_or(SlashError::MathOverflow)?;
    require!(
        now >= earliest_settle,
        SlashError::AppealGraceWindowActive,
    );

    Ok(())
}

#[derive(Accounts)]
pub struct SettleSlash<'info> {
    /// The agent's escrow vault — the encumbered funds leave it here.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
    )]
    pub escrow_vault: Account<'info, EscrowVault>,

    /// The slash record being settled. Must belong to this vault and be
    /// Pending.
    #[account(
        mut,
        seeds = [
            SlashRecord::SEED_PREFIX,
            escrow_vault.agent_wallet.as_ref(),
            &slash_record.index.to_le_bytes(),
        ],
        bump = slash_record.bump,
        constraint = slash_record.agent_wallet == escrow_vault.agent_wallet
            @ SlashError::RecordVaultMismatch,
    )]
    pub slash_record: Account<'info, SlashRecord>,

    /// SlashConfig — verifies the signer and supplies the treasury key.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// Where the slashed lamports go: the treasury for a Minor/Major slash,
    /// the incinerator for a Compromise. Validated against the record's
    /// tier in the handler.
    /// CHECK: only RECEIVES lamports; validated against the offense tier.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    /// The slash executor — settlement is an executor-side action.
    #[account(
        constraint = slash_executor.key() == slash_config.slash_executor
            @ SlashError::NotSlashAuthority,
    )]
    pub slash_executor: Signer<'info>,
}

pub fn handler(ctx: Context<SettleSlash>) -> Result<()> {
    let clock = Clock::get()?;
    let now   = clock.unix_timestamp;

    // VULN-08 #3: emit the attempt event FIRST, before any gate fires, so
    // even rejected attempts surface on-chain. The off-chain monitor
    // alerts on suspicious patterns (e.g. attempts clustering around an
    // appeal's mempool window, or very-short seconds_since_execute).
    let executed_at     = ctx.accounts.slash_record.executed_at;
    let appeal_deadline = ctx.accounts.slash_record.appeal_deadline;
    emit!(SettleSlashAttempted {
        agent_wallet:          ctx.accounts.slash_record.agent_wallet,
        index:                 ctx.accounts.slash_record.index,
        executor:              ctx.accounts.slash_executor.key(),
        executed_at,
        appeal_deadline,
        attempted_at:          now,
        seconds_since_execute: now.saturating_sub(executed_at),
    });

    // ── Refuse while paused (VULN-04 kill switch) ───────────────────────────
    // H-04: time-aware check — an expired pause does not block settlement.
    require!(
        !ctx.accounts.slash_config.is_paused_now(now),
        SlashError::SettlementsPaused,
    );

    // ── Lifecycle preconditions ─────────────────────────────────────────────
    let status = SlashStatus::from_u8(ctx.accounts.slash_record.status)
        .ok_or(SlashError::WrongSlashStatus)?;
    require!(
        status == SlashStatus::Pending,
        SlashError::WrongSlashStatus,
    );
    // The appeal window must have CLOSED.
    require!(
        !ctx.accounts.slash_record.appeal_window_open(now),
        SlashError::AppealWindowStillOpen,
    );
    // VULN-04: the post-uphold settlement timelock must have ELAPSED. For
    // slashes that were never appealed `settlement_unlock_at` is zero and
    // this passes immediately — only an upheld appeal sets the timelock.
    require!(
        ctx.accounts.slash_record.settlement_timelock_elapsed(now),
        SlashError::SettlementTimelockNotElapsed,
    );

    // VULN-08 #1 + #2: the two independent timing gates. Defence in depth
    // on top of the appeal-window + post-uphold-timelock checks above.
    // M-07: the floor + grace values come from SlashConfig (admin-tunable),
    // not file-level consts. `effective_*` falls back to the documented
    // 48h / 1h defaults for any pre-M-07 account whose new i64 fields are
    // still zero (carved from the old _reserved cushion).
    let cfg_for_timing = &ctx.accounts.slash_config;
    check_settle_timing(
        executed_at,
        appeal_deadline,
        now,
        cfg_for_timing.effective_execute_to_settle_seconds(),
        cfg_for_timing.effective_settle_grace_seconds(),
    )?;

    let tier = OffenseTier::from_u8(ctx.accounts.slash_record.offense_tier)
        .ok_or(SlashError::InvalidOffenseTier)?;
    let amount = ctx.accounts.slash_record.slashed_lamports;

    // ── Verify the destination matches the tier ─────────────────────────────
    // H-03: Treasury payouts pin to slash_record.treasury_at_execute (the
    // snapshot captured at execute_slash time), NOT to the live
    // slash_config.treasury. A post-execute treasury rotation cannot
    // therefore redirect a Pending settlement. Burn payouts still pin
    // to the global INCINERATOR constant (which is not mutable).
    let required_destination = tier.destination();
    let destination_key = ctx.accounts.destination.key();
    match required_destination {
        SlashDestination::Treasury => require!(
            destination_key == ctx.accounts.slash_record.treasury_at_execute,
            SlashError::WrongDestination,
        ),
        SlashDestination::Burn => require!(
            destination_key == SlashConfig::INCINERATOR,
            SlashError::WrongDestination,
        ),
    }

    // ── Move the encumbered lamports OUT of the vault ───────────────────────
    // Direct lamport mutation — the vault is program-owned, so System::transfer
    // refuses the source. The pattern itself is safe, but the audit
    // (M-11) flagged that it produces NO System-program "Transfer" log:
    // an off-chain auditor that watches `Program 11111... invoke` lines
    // misses the movement. The fix is to capture the FULL balance
    // surface here, enforce a post-mutation balance invariant, and
    // stamp every piece into the SlashSettled event below so the on-
    // chain event log carries everything System::transfer would have.
    let vault_balance_before;
    let vault_balance_after;
    let destination_balance_before;
    let destination_balance_after;
    {
        let vault_ai = ctx.accounts.escrow_vault.to_account_info();
        let dest_ai  = ctx.accounts.destination.to_account_info();

        let rent = Rent::get()?;
        let rent_min = rent.minimum_balance(vault_ai.data_len());

        vault_balance_before       = vault_ai.lamports();
        destination_balance_before = dest_ai.lamports();

        let vault_after = vault_balance_before
            .checked_sub(amount)
            .ok_or(SlashError::MathOverflow)?;
        require!(vault_after >= rent_min, SlashError::RentViolation);

        **vault_ai.try_borrow_mut_lamports()? = vault_after;
        let dest_after = destination_balance_before
            .checked_add(amount)
            .ok_or(SlashError::MathOverflow)?;
        **dest_ai.try_borrow_mut_lamports()? = dest_after;

        // Re-read the live balances post-mutation. The values SHOULD match
        // `vault_after` / `dest_after` we just wrote — re-reading rather
        // than reusing the locals catches any future refactor that
        // introduces an intervening account-info aliasing problem (where
        // a second mutable borrow of one of these accounts inside the
        // scope above silently undoes the write).
        vault_balance_after       = vault_ai.lamports();
        destination_balance_after = dest_ai.lamports();
    }

    // ── M-11: post-mutation lamport-audit invariant ─────────────────────────
    // The SlashSettled event below stamps the pre/post balances on chain —
    // making the event-emit a TRUSTED record requires asserting the
    // balances actually balance against `amount` BEFORE we emit. If they
    // don't, abort the tx with `LamportAuditMismatch` rather than commit
    // an internally-inconsistent audit-trail event.
    require!(
        vault_balance_before
            .checked_sub(amount)
            .map(|expected_after| expected_after == vault_balance_after)
            .unwrap_or(false),
        SlashError::LamportAuditMismatch,
    );
    require!(
        destination_balance_before
            .checked_add(amount)
            .map(|expected_after| expected_after == destination_balance_after)
            .unwrap_or(false),
        SlashError::LamportAuditMismatch,
    );

    // ── Update vault bookkeeping ────────────────────────────────────────────
    let vault = &mut ctx.accounts.escrow_vault;
    vault.encumbered_lamports = vault.encumbered_lamports
        .checked_sub(amount)
        .ok_or(SlashError::MathOverflow)?;
    vault.total_slashed_lamports = vault.total_slashed_lamports
        .checked_add(amount)
        .ok_or(SlashError::MathOverflow)?;
    // A Compromise settlement is the terminal step — deactivate the vault.
    if tier.is_terminal() {
        vault.active = false;
    }

    // ── Mark the record Settled ─────────────────────────────────────────────
    let record = &mut ctx.accounts.slash_record;
    record.status = SlashStatus::Settled.as_u8();

    emit!(SlashSettled {
        agent_wallet:               record.agent_wallet,
        index:                      record.index,
        settled_lamports:           amount,
        destination:                required_destination.as_u8(),
        // M-11: full balance audit surface, byte-for-byte derivable from
        // what System::transfer would have logged.
        destination_key:            destination_key,
        vault_balance_before,
        vault_balance_after,
        destination_balance_before,
        destination_balance_after,
        terminal:                   tier.is_terminal(),
        settled_at:                 now,
        executed_at,
    });

    // M-11: stable, parseable audit-trail log modeled on the System Program's
    // Transfer log. Off-chain log scrapers that grep "Program 11111... invoke"
    // + "Transfer:" can grep this prefix the same way to catch
    // slash-authority's program-owned-source movements that System::transfer
    // CANNOT produce.
    //
    // Format: `slash-authority transfer: from={vault} to={dest} amount={lamports} \
    //          vault_before={n} vault_after={n} dest_before={n} dest_after={n}`
    msg!(
        "slash-authority transfer: from={} to={} amount={} \
         vault_before={} vault_after={} dest_before={} dest_after={}",
        ctx.accounts.escrow_vault.key(),
        destination_key,
        amount,
        vault_balance_before,
        vault_balance_after,
        destination_balance_before,
        destination_balance_after,
    );

    msg!(
        "slash settled: agent={} index={} amount={} destination={:?} terminal={}",
        record.agent_wallet, record.index, amount,
        required_destination, tier.is_terminal(),
    );
    Ok(())
}
