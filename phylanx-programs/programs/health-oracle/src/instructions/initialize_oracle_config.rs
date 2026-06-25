// =============================================================================
// programs/health-oracle/src/instructions/initialize_oracle_config.rs
//
// initialize_oracle_config — create the OracleConfig singleton for the
// oracle cluster.
//
// Day 23 (Phase 4) adds this instruction. The Doc-3 MVP treated OracleConfig
// as already-deployed state; Phase 4 needs an explicit, on-chain way to
// stand up the cluster config — the node pubkeys and the confidence floor.
//
// CLUSTER VALIDATION
//   - 1..=MAX_ORACLE_KEYS node pubkeys (a 1-node cluster is the explicit
//     single-node deployment; 2 is rejected — no majority is possible),
//   - no duplicate node keys,
//   - `oracle_node` (the primary) must be one of `oracle_keys`,
//   - `min_confidence` in 0..=1000.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::PhylanxError;
use crate::state::OracleConfig;

#[derive(Accounts)]
pub struct InitializeOracleConfig<'info> {
    /// The OracleConfig singleton, created here.
    #[account(
        init,
        payer = admin,
        space = OracleConfig::SPACE,
        seeds = [OracleConfig::SEED],
        bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    /// The admin — pays rent, becomes the config update authority.
    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:            Context<InitializeOracleConfig>,
    oracle_keys:    Vec<Pubkey>,
    min_confidence: u16,
) -> Result<()> {
    // ── Validate the cluster ────────────────────────────────────────────────
    require!(
        !oracle_keys.is_empty()
            && oracle_keys.len() <= OracleConfig::MAX_ORACLE_KEYS,
        PhylanxError::InvalidClusterSize,
    );
    // A 2-node cluster has no majority — reject it. 1 (single-node) and
    // 3..=5 (BFT) are valid.
    require!(
        oracle_keys.len() != 2,
        PhylanxError::InvalidClusterSize,
    );
    // No duplicate node keys.
    for i in 0..oracle_keys.len() {
        for j in (i + 1)..oracle_keys.len() { // audit: loop index over Vec.len(), no overflow possible
            require!(
                oracle_keys[i] != oracle_keys[j],
                PhylanxError::DuplicateOracleKey,
            );
        }
    }
    require!(
        min_confidence <= 1000,
        PhylanxError::InvalidMinConfidence,
    );

    // The primary node is, by convention, the first key.
    let primary = oracle_keys[0];

    let config = &mut ctx.accounts.oracle_config;
    config.authority      = ctx.accounts.admin.key();
    config.oracle_node    = primary;
    config.oracle_keys    = oracle_keys;
    config.min_confidence = min_confidence;
    config.bump           = ctx.bumps.oracle_config;

    msg!(
        "oracle config initialised: {}-node cluster, primary={}, \
         min_confidence={}, threshold={}",
        config.oracle_keys.len(), config.oracle_node,
        config.min_confidence, config.consensus_threshold(),
    );
    Ok(())
}
