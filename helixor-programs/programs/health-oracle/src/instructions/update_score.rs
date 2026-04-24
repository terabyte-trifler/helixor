// =============================================================================
// update_score — Day 1: stub that compiles
//                Day 7: full implementation
//
// What Day 7 adds:
//   - Verifies caller == OracleConfig.oracle_key
//   - 23h cooldown check (UpdateTooFrequent)
//   - 200pt guard rail check (ScoreDeltaTooLarge)
//   - Init_if_needed TrustCertificate PDA  seeds: ["score", agent_wallet]
//   - Writes all score fields
//   - Emit ScoreUpdated event
// =============================================================================

use anchor_lang::prelude::*;
use crate::state::ScorePayload;

pub fn handler(_ctx: Context<UpdateScore>, _payload: ScorePayload) -> Result<()> {
    // TODO Day 7: full implementation
    msg!("helixor::update_score stub — Day 7 implementation pending");
    Ok(())
}

#[derive(Accounts)]
pub struct UpdateScore<'info> {
    /// Oracle node — must match OracleConfig.oracle_key
    pub oracle: Signer<'info>,

    /// AgentRegistration PDA (read-only — verify agent is active)
    /// TODO Day 7: replace with proper seeds constraint
    /// CHECK: Day 7 wires seeds
    pub agent_registration: UncheckedAccount<'info>,

    /// TrustCertificate PDA — created here if first update
    /// TODO Day 7: init_if_needed with seeds
    /// CHECK: Day 7 wires init_if_needed
    #[account(mut)]
    pub trust_certificate: UncheckedAccount<'info>,

    /// OracleConfig PDA — stores the authorised oracle pubkey
    /// TODO Day 7: replace with proper seeds constraint
    /// CHECK: Day 7 wires seeds
    pub oracle_config: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

// ── Events ────────────────────────────────────────────────────────────────────
#[event]
pub struct ScoreUpdated {
    pub agent:     Pubkey,
    pub score:     u16,
    pub anomaly:   bool,
    pub timestamp: i64,
}
