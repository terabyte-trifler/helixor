// =============================================================================
// get_health — Day 1: stub that compiles
//              Day 3: full implementation
//
// What Day 3 adds:
//   - Reads AgentRegistration (active check)
//   - Reads TrustCertificate (score, alert, freshness)
//   - Returns TrustScore struct via CPI to calling DeFi protocol
//   - PROVISIONAL response for agents not yet scored (< 24h)
//   - Emit HealthQueried event
// =============================================================================

use crate::state::{TrustScore, AlertLevel};
use anchor_lang::prelude::*;

pub fn handler(_ctx: Context<GetHealth>) -> Result<()> {
    // TODO Day 3: full implementation
    msg!("helixor::get_health stub — Day 3 implementation pending");
    let _placeholder = TrustScore {
        agent_wallet: Pubkey::default(),
        score: 500,
        alert: AlertLevel::Yellow,
        success_rate: 10_000,
        anomaly_flag: false,
        updated_at: 0,
        is_fresh: false,
    };
    Ok(())
}

#[derive(Accounts)]
pub struct GetHealth<'info> {
    /// Any caller — public read-only endpoint (no signer required)
    /// CHECK: anyone can query health scores
    pub querier: UncheckedAccount<'info>,

    /// AgentRegistration PDA
    /// TODO Day 3: replace with proper seeds constraint
    /// CHECK: Day 3 wires seeds
    pub agent_registration: UncheckedAccount<'info>,

    /// TrustCertificate PDA — may not exist for new agents
    /// TODO Day 3: replace with proper seeds constraint
    /// CHECK: Day 3 handles missing cert (PROVISIONAL response)
    pub trust_certificate: UncheckedAccount<'info>,
}

// ── Events ────────────────────────────────────────────────────────────────────
#[event]
pub struct HealthQueried {
    pub agent:     Pubkey,
    pub querier:   Pubkey,
    pub score:     u16,
    pub timestamp: i64,
}
