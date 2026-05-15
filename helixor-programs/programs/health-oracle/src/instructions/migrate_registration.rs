// =============================================================================
// programs/health-oracle/src/instructions/migrate_registration.rs
//
// migrate_registration — one-time per-agent migration from v1 -> v2 layout.
//
// WHY THIS EXISTS:
// The MVP's AgentRegistration occupies V1_SPACE bytes. Adding the Day-3
// baseline fields makes the account larger. Solana accounts are NOT auto-
// resized: the account's owner program must call System Program's `realloc`
// (or use Anchor's `#[account(realloc = ...)]` attribute) to grow it.
//
// AUTHORITY:
// Owner-only — the owner paid for the original account and must fund the
// extra rent. Oracle cannot migrate someone else's account (that would let
// the oracle drain rent from arbitrary owners).
//
// IDEMPOTENCY:
// If the account is already at the current layout version, this errors with
// AlreadyMigrated rather than silently no-op'ing. The off-chain caller can
// distinguish that error and skip cleanly.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::HelixorError;
use crate::events::RegistrationMigrated;
use crate::state::AgentRegistration;

pub fn handler(ctx: Context<crate::MigrateRegistration>) -> Result<()> {
    let reg = &mut ctx.accounts.agent_registration;

    // Already at current version → error, so callers see explicit duplicate-migrate.
    require!(
        reg.layout_version < AgentRegistration::CURRENT_LAYOUT_VERSION,
        HelixorError::AlreadyMigrated
    );

    let from_version = reg.layout_version;

    // realloc::zero = true means the new tail is already zero. That gives us:
    //   baseline_committed     = false
    //   baseline_hash          = [0; 32]
    //   baseline_algo_version  = 0
    //   baseline_committer     = Pubkey::default()
    //   baseline_committed_at  = 0
    //   commit_nonce           = 0
    //   layout_version         = 0  (we set it next)
    //   _reserved              = [0; 64]
    //
    // We then set the layout_version to the current version. Everything else
    // is intentionally zero — the next commit_baseline call populates the
    // baseline fields.
    reg.layout_version = AgentRegistration::CURRENT_LAYOUT_VERSION;

    let clock = Clock::get()?;
    emit!(RegistrationMigrated {
        agent_wallet: reg.agent_wallet,
        from_version,
        to_version: AgentRegistration::CURRENT_LAYOUT_VERSION,
        migrated_at: clock.unix_timestamp,
    });

    Ok(())
}
