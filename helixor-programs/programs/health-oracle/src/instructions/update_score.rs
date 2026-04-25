// Day 7 — stub to keep workspace compiling.
use anchor_lang::prelude::*;
use crate::{state::ScorePayload, UpdateScore};

pub fn handler(_ctx: Context<UpdateScore>, _payload: ScorePayload) -> Result<()> {
    msg!("helixor::update_score — Day 7 implementation pending");
    Ok(())
}
