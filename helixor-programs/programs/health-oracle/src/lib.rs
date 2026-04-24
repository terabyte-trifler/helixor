use anchor_lang::prelude::*;

pub mod errors;
pub mod state;

pub use state::{RegisterParams, ScorePayload};

declare_id!("Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P");

#[program]
pub mod health_oracle {
    use super::*;

    pub fn register_agent(ctx: Context<RegisterAgent>, _params: RegisterParams) -> Result<()> {
        msg!(
            "helixor::register_agent Day 1 stub for owner {}",
            ctx.accounts.owner.key()
        );
        Ok(())
    }

    pub fn get_health(ctx: Context<GetHealth>) -> Result<()> {
        msg!(
            "helixor::get_health Day 1 stub for querier {}",
            ctx.accounts.querier.key()
        );
        Ok(())
    }

    pub fn update_score(ctx: Context<UpdateScore>, _payload: ScorePayload) -> Result<()> {
        msg!(
            "helixor::update_score Day 1 stub for oracle {}",
            ctx.accounts.oracle.key()
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RegisterAgent<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: Day 1 stub only; Day 2 will validate and constrain this PDA flow.
    pub agent_wallet: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: Day 1 stub only; Day 2 will initialize with seeds.
    pub agent_registration: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: Day 1 stub only; Day 2 will become the escrow PDA.
    pub escrow_vault: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GetHealth<'info> {
    /// CHECK: Public read surface for Day 1/3.
    pub querier: UncheckedAccount<'info>,
    /// CHECK: Day 1 stub only; Day 3 will use proper PDA constraints.
    pub agent_registration: UncheckedAccount<'info>,
    /// CHECK: Day 1 stub only; Day 3 will use proper PDA constraints.
    pub trust_certificate: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct UpdateScore<'info> {
    pub oracle: Signer<'info>,
    /// CHECK: Day 1 stub only; Day 7 will use proper PDA constraints.
    pub agent_registration: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK: Day 1 stub only; Day 7 will init or update this PDA.
    pub trust_certificate: UncheckedAccount<'info>,
    /// CHECK: Day 1 stub only; Day 7 will constrain this config PDA.
    pub oracle_config: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
