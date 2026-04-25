// =============================================================================
// register_agent — Day 2 COMPLETE
//
// Flow:
//   1. Validate name (non-empty, <= 64 bytes)
//   2. Validate agent_wallet != owner
//   3. Init AgentRegistration PDA       seeds: ["agent", agent_wallet]
//   4. Init EscrowVault (SystemAccount)  seeds: ["escrow", agent_wallet]
//   5. CPI system::transfer(owner → escrow_vault, 10_000_000 lamports)
//   6. Emit AgentRegistered event (indexers register Helius webhook from this)
//
// Why escrow is a SystemAccount, not a PDA-owned TokenAccount:
//   - MVP uses native SOL, not SPL tokens (no USDC mint setup needed)
//   - SystemAccount PDAs are simpler: no token program, no mint, no ATA
//   - Future withdrawal uses invoke_signed with escrow seeds — program-controlled
//
// What's different from the spec:
//   - Added NameEmpty validation (empty name breaks off-chain indexer queries)
//   - Escrow check uses `owner.lamports()` BEFORE init rent deduction is wrong;
//     Anchor's init constraints handle rent automatically, we validate the
//     escrow transfer amount only
//   - Store vault_bump in registration PDA — needed for future withdraw ix
//   - Event includes name + vault_bump + timestamp so indexer needs zero
//     additional RPC calls to set up Helius webhook
// =============================================================================

use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer as SystemTransfer};

use crate::{
    errors::HelixorError,
    state::{AgentRegistration, RegisterParams},
    RegisterAgent,
};

pub fn handler(ctx: Context<RegisterAgent>, params: RegisterParams) -> Result<()> {
    // ── 1. Input validation ──────────────────────────────────────────────────
    // Check name first — cheapest validation, most common error.
    let name_bytes = params.name.as_bytes();
    require!(!name_bytes.is_empty(),  HelixorError::NameEmpty);
    require!(
        name_bytes.len() <= AgentRegistration::MAX_NAME_BYTES,
        HelixorError::NameTooLong
    );

    // Same-wallet check — catches copy-paste errors where operator uses one
    // wallet for both owner and agent.
    require!(
        ctx.accounts.agent_wallet.key() != ctx.accounts.owner.key(),
        HelixorError::AgentSameAsOwner
    );

    // ── 2. Write AgentRegistration PDA ───────────────────────────────────────
    let clock = Clock::get()?;
    let registration_pda = ctx.accounts.agent_registration.key();
    let vault_pda = ctx.accounts.escrow_vault.key();
    let owner_key = ctx.accounts.owner.key();
    let agent_key = ctx.accounts.agent_wallet.key();
    let reg = &mut ctx.accounts.agent_registration;

    reg.agent_wallet    = agent_key;
    reg.owner_wallet    = owner_key;
    reg.registered_at   = clock.unix_timestamp;
    reg.escrow_lamports = AgentRegistration::MIN_ESCROW_LAMPORTS;
    reg.active          = true;
    reg.bump            = ctx.bumps.agent_registration;
    reg.vault_bump      = ctx.bumps.escrow_vault;

    // ── 3. Transfer escrow SOL into vault PDA via CPI ────────────────────────
    // The escrow_vault is a SystemAccount PDA. After this transfer:
    //   - Vault holds MIN_ESCROW_LAMPORTS
    //   - Owner is the runtime (system program), not a user
    //   - Only our program can transfer out (signed via PDA seeds)
    //
    // We don't need invoke_signed for this transfer — the FROM side is the
    // owner signer, not the PDA. Simple CPI works.
    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            SystemTransfer {
                from: ctx.accounts.owner.to_account_info(),
                to:   ctx.accounts.escrow_vault.to_account_info(),
            },
        ),
        AgentRegistration::MIN_ESCROW_LAMPORTS,
    )?;

    // ── 4. Emit event ────────────────────────────────────────────────────────
    // Event carries everything an off-chain indexer needs to register the
    // Helius webhook for this agent — no follow-up RPC calls required.
    emit!(AgentRegistered {
        agent:             reg.agent_wallet,
        owner:             reg.owner_wallet,
        name:              params.name.clone(),
        escrow_lamports:   AgentRegistration::MIN_ESCROW_LAMPORTS,
        registration_pda,
        vault_pda,
        timestamp:         clock.unix_timestamp,
    });

    // Log for devnet debugging — Anchor stripped in release builds
    msg!(
        "helixor::register_agent: agent={} owner={} escrow={}",
        reg.agent_wallet,
        reg.owner_wallet,
        AgentRegistration::MIN_ESCROW_LAMPORTS,
    );

    Ok(())
}

// =============================================================================
// Accounts context
// =============================================================================
// =============================================================================
// Events
// =============================================================================

/// Emitted once per successful registration.
///
/// Downstream consumers:
///   1. Off-chain indexer (Day 4) subscribes to this event, extracts
///      `agent`, and registers a Helius webhook for that wallet.
///   2. Operator dashboard (future) displays new registrations.
///   3. Public analytics (e.g. Dune) count registrations over time.
///
/// Event includes the PDA addresses so indexers can verify + cache without
/// re-deriving them client-side.
#[event]
pub struct AgentRegistered {
    pub agent:            Pubkey,
    pub owner:            Pubkey,
    pub name:             String,  // Max 64 bytes — validated in handler
    pub escrow_lamports:  u64,
    pub registration_pda: Pubkey,
    pub vault_pda:        Pubkey,
    pub timestamp:        i64,
}
