// Day 7 full implementation — stub keeps the program compiling today.
use anchor_lang::prelude::*;
use crate::{state::ScorePayload, UpdateScore};

pub fn handler(_ctx: Context<UpdateScore>, _payload: ScorePayload) -> Result<()> {
    msg!("helixor::update_score — Day 7 implementation pending");
    Ok(())
}
