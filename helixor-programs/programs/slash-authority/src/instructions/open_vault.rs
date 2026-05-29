// =============================================================================
// programs/slash-authority/src/instructions/open_vault.rs
//
// open_vault — create an agent's EscrowVault and fund it with real staked
// collateral.
//
// The vault is a program-owned data account. `init` creates it and funds
// its rent-exempt minimum from the staker. We then move the STAKE
// (`stake_lamports`, on top of rent) into the vault with a System-program
// transfer — a CPI signed by the staker.
//
// After this instruction the vault account's true lamport balance is
// `rent_exempt_minimum + stake_lamports`, and `staked_lamports` records the
// stake portion — the figure execute_slash deducts from.
// =============================================================================

use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer};

use crate::errors::SlashError;
use crate::events::VaultOpened;
use crate::state::EscrowVault;

#[derive(Accounts)]
#[instruction(agent_wallet: Pubkey)]
pub struct OpenVault<'info> {
    /// The escrow vault, created + owned by this program.
    #[account(
        init,
        payer = staker,
        space = EscrowVault::SPACE,
        seeds = [EscrowVault::SEED_PREFIX, agent_wallet.as_ref()],
        bump,
    )]
    pub escrow_vault: Account<'info, EscrowVault>,

    /// The staker — funds the vault rent AND the staked collateral.
    /// Typically the agent owner.
    #[account(mut)]
    pub staker: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:            Context<OpenVault>,
    agent_wallet:   Pubkey,
    stake_lamports: u64,
) -> Result<()> {
    // ── M-14: defence-in-depth System Program ID pin ────────────────────────
    // The audit flagged a hypothetical "fake system_program" attack on
    // open_vault — a caller passing a fake System Program account would
    // route the staker -> vault transfer through attacker-controlled code.
    // The audit concluded this is NOT a real finding: Anchor's
    // `Program<'info, System>` constraint above ALREADY enforces the
    // account's pubkey against `solana_program::system_program::ID` at
    // the deserialize gate, before this handler runs. The Solana VM
    // additionally enforces the program ID on the CPI itself.
    //
    // So why add this check? It is a tripwire for a future refactor.
    // If a contributor weakens `system_program: Program<'info, System>`
    // to `UncheckedAccount<'info>` / `AccountInfo<'info>` (e.g. to add a
    // shim, to support a custom verifier, or to "make the test setup
    // simpler") and forgets to re-add the pubkey check, this in-handler
    // `require_keys_eq!` still fails the tx with M-14's dedicated
    // SystemProgramIdMismatch code. The check is cheap, attributable,
    // and survives independently of the `Accounts` struct surface.
    require_keys_eq!(
        ctx.accounts.system_program.key(),
        anchor_lang::system_program::ID,
        SlashError::SystemProgramIdMismatch,
    );

    // ── Validate ────────────────────────────────────────────────────────────
    require!(
        stake_lamports >= EscrowVault::MIN_STAKE_LAMPORTS,
        SlashError::StakeBelowMinimum,
    );

    // ── Move the staked collateral into the vault ───────────────────────────
    // `init` already funded the vault's rent from the staker. This transfer
    // moves the STAKE on top — a System-program CPI signed by the staker.
    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.staker.to_account_info(),
                to:   ctx.accounts.escrow_vault.to_account_info(),
            },
        ),
        stake_lamports,
    )?;

    // ── Initialise the vault state ──────────────────────────────────────────
    let clock = Clock::get()?;
    let vault = &mut ctx.accounts.escrow_vault;
    vault.agent_wallet           = agent_wallet;
    vault.staked_lamports        = stake_lamports;
    vault.slash_count            = 0;
    vault.total_slashed_lamports = 0;
    vault.created_at             = clock.unix_timestamp;
    vault.active                 = true;
    vault.bump                   = ctx.bumps.escrow_vault;
    vault.layout_version         = EscrowVault::CURRENT_LAYOUT_VERSION;

    emit!(VaultOpened {
        agent_wallet,
        staked_lamports: stake_lamports,
        opened_at:       clock.unix_timestamp,
    });

    msg!(
        "escrow vault opened for agent {} with {} lamports staked",
        agent_wallet, stake_lamports,
    );
    Ok(())
}
