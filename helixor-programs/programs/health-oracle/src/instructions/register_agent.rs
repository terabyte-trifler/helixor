// =============================================================================
// register_agent — Day 1: stub that compiles
//                  Day 2: full implementation
//
// What Day 2 adds:
//   - 3 validations (name length, escrow minimum, agent != owner)
//   - Init AgentRegistration PDA   seeds: ["agent", agent_wallet]
//   - Init EscrowVault             seeds: ["escrow", agent_wallet]
//   - CPI system_program::transfer (owner → escrow_vault)
//   - Emit AgentRegistered event
//   - Register Helius webhook for this agent wallet
// =============================================================================

use anchor_lang::prelude::*;
use crate::state::{AgentRegistration, RegisterParams};

pub fn handler(_ctx: Context<RegisterAgent>, _params: RegisterParams) -> Result<()> {
    // TODO Day 2: full implementation
    msg!("helixor::register_agent stub — Day 2 implementation pending");
    Ok(())
}

#[derive(Accounts)]
pub struct RegisterAgent<'info> {
    /// The operator registering the agent and paying rent + escrow
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The agent's operational wallet being monitored
    /// CHECK: validated != owner in Day 2 handler
    pub agent_wallet: UncheckedAccount<'info>,

    /// AgentRegistration PDA — one per agent wallet
    /// TODO Day 2: replace UncheckedAccount with proper init + seeds
    /// CHECK: Day 2 wires proper init constraints
    #[account(mut)]
    pub agent_registration: UncheckedAccount<'info>,

    /// EscrowVault — SOL locked as collateral
    /// TODO Day 2: init as system-owned PDA
    /// CHECK: Day 2 wires escrow PDA
    #[account(mut)]
    pub escrow_vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

// ── Events defined now, emitted in Day 2 ──────────────────────────────────────
#[event]
pub struct AgentRegistered {
    pub agent:     Pubkey,
    pub owner:     Pubkey,
    pub timestamp: i64,
}
