// Day 3 full implementation — stub keeps the program compiling today.
use anchor_lang::prelude::*;
use crate::{
    state::{AlertLevel, TrustScore},
    GetHealth,
};

pub fn handler(_ctx: Context<GetHealth>) -> Result<TrustScore> {
    msg!("helixor::get_health — Day 3 implementation pending");
    Ok(TrustScore {
        agent:        Pubkey::default(),
        score:        500,
        alert:        AlertLevel::Yellow,
        success_rate: 10_000,
        anomaly_flag: false,
        updated_at:   0,
        is_fresh:     false,
    })
}
