// =============================================================================
// update_score — Day 7 COMPLETE
//
// Oracle-only: writes a fresh TrustCertificate for an agent.
//
// Validations (in this order — cheapest first):
//   1. Score in [0, 1000]                        → ScoreOutOfRange
//   2. Success rate basis points in [0, 10000]   → SuccessRateOutOfRange
//   3. Caller is the registered oracle key        → UnauthorizedOracle
//   4. Oracle is not paused                      → OraclePaused
//   5. Agent is still active                     → AgentDeactivated
//   6. ≥23h since last update (if cert exists)   → UpdateTooFrequent
//   7. Score delta ≤ 200pt (if cert exists)      → ScoreDeltaTooLarge
//
// Effects:
//   - Init or mutate TrustCertificate PDA
//   - Increment OracleConfig.epoch
//   - Emit ScoreUpdated event
//
// Why the guard rail is on-chain: even if our oracle Python is bugged or
// compromised, the program refuses to write a score that jumps >200 points.
// This is the last line of defense.
// =============================================================================

use anchor_lang::prelude::*;

use crate::{
    errors::HelixorError,
    state::{
        AgentRegistration, AlertLevel, OracleConfig, ScorePayload, TrustCertificate,
    },
};

pub fn handler(ctx: Context<UpdateScore>, payload: ScorePayload) -> Result<()> {
    // ── 1. Cheap validations first ───────────────────────────────────────────
    require!(payload.score <= 1000, HelixorError::ScoreOutOfRange);
    require!(
        payload.success_rate <= 10_000,
        HelixorError::SuccessRateOutOfRange
    );

    // ── 2. Oracle authorization ──────────────────────────────────────────────
    let cfg = &mut ctx.accounts.oracle_config;
    require_keys_eq!(
        ctx.accounts.oracle.key(),
        cfg.oracle_key,
        HelixorError::UnauthorizedOracle
    );

    // ── 3. Pause check ───────────────────────────────────────────────────────
    require!(!cfg.paused, HelixorError::OraclePaused);

    // ── 4. Agent must be active ──────────────────────────────────────────────
    let reg = &ctx.accounts.agent_registration;
    require!(reg.active, HelixorError::AgentDeactivated);

    let cert  = &mut ctx.accounts.trust_certificate;
    let clock = Clock::get()?;
    let now   = clock.unix_timestamp;

    // ── 5. Cooldown + guard rail (if not first update) ───────────────────────
    if cert.updated_at > 0 {
        // 23h cooldown
        let elapsed = now
            .checked_sub(cert.updated_at)
            .ok_or(HelixorError::MathOverflow)?;
        require!(
            elapsed >= TrustCertificate::MIN_UPDATE_GAP,
            HelixorError::UpdateTooFrequent
        );

        // 200pt delta cap. abs_diff is panic-free for u16.
        let delta = payload.score.abs_diff(cert.score);
        require!(
            delta <= TrustCertificate::MAX_SCORE_DELTA,
            HelixorError::ScoreDeltaTooLarge
        );
    }

    // ── 6. Write certificate ─────────────────────────────────────────────────
    cert.agent_wallet         = reg.agent_wallet;
    cert.score                = payload.score;
    cert.alert                = AlertLevel::from_score(payload.score);
    cert.success_rate         = payload.success_rate;
    cert.tx_count_7d          = payload.tx_count_7d;
    cert.anomaly_flag         = payload.anomaly_flag;
    cert.updated_at           = now;
    cert.bump                 = ctx.bumps.trust_certificate;
    cert.baseline_hash_prefix = payload.baseline_hash_prefix;
    cert.scoring_algo_version = payload.scoring_algo_version;
    cert.weights_version      = payload.weights_version;

    // ── 7. Bump epoch counter ────────────────────────────────────────────────
    cfg.epoch = cfg
        .epoch
        .checked_add(1)
        .ok_or(HelixorError::MathOverflow)?;

    // ── 8. Emit event ────────────────────────────────────────────────────────
    emit!(ScoreUpdated {
        agent:                reg.agent_wallet,
        score:                cert.score,
        alert:                cert.alert,
        anomaly_flag:         cert.anomaly_flag,
        success_rate:         cert.success_rate,
        tx_count_7d:          cert.tx_count_7d,
        baseline_hash_prefix: cert.baseline_hash_prefix,
        scoring_algo_version: cert.scoring_algo_version,
        weights_version:      cert.weights_version,
        epoch:                cfg.epoch,
        timestamp:            now,
    });

    msg!(
        "helixor::update_score: agent={} score={} alert={:?} epoch={}",
        reg.agent_wallet,
        cert.score,
        cert.alert,
        cfg.epoch,
    );

    Ok(())
}

// =============================================================================
// Accounts
// =============================================================================
#[derive(Accounts)]
pub struct UpdateScore<'info> {
    /// The oracle node submitting the score. Must match oracle_config.oracle_key.
    /// Pays rent for cert PDA on first update of each agent.
    #[account(mut)]
    pub oracle: Signer<'info>,

    /// AgentRegistration PDA — must exist (agent registered).
    #[account(
        seeds = [b"agent", agent_registration.agent_wallet.as_ref()],
        bump  = agent_registration.bump,
    )]
    pub agent_registration: Account<'info, AgentRegistration>,

    /// TrustCertificate PDA — created on first call, mutated on subsequent.
    ///
    /// init_if_needed is safe here because:
    ///   - Only the authorized oracle (verified above) can call this
    ///   - PDA seeds are deterministic from agent_wallet
    ///   - Anchor validates the cert PDA matches canonical derivation
    ///
    /// Rent: ~0.00128 SOL per agent on first cert. Oracle wallet pays.
    #[account(
        init_if_needed,
        payer  = oracle,
        space  = 8 + TrustCertificate::INIT_SPACE,
        seeds  = [b"score", agent_registration.agent_wallet.as_ref()],
        bump,
    )]
    pub trust_certificate: Account<'info, TrustCertificate>,

    /// OracleConfig singleton. Mutated to bump epoch counter.
    #[account(
        mut,
        seeds = [b"oracle_config"],
        bump  = oracle_config.bump,
    )]
    pub oracle_config: Account<'info, OracleConfig>,

    pub system_program: Program<'info, System>,
}

// =============================================================================
// Event
// =============================================================================

/// Emitted on every successful update. Off-chain indexers consume this to
/// build score timelines, alert dashboards, and anomaly notifications.
#[event]
pub struct ScoreUpdated {
    pub agent:                Pubkey,
    pub score:                u16,
    pub alert:                AlertLevel,
    pub anomaly_flag:         bool,
    pub success_rate:         u16,
    pub tx_count_7d:          u32,
    pub baseline_hash_prefix: [u8; 16],
    pub scoring_algo_version: u8,
    pub weights_version:      u8,
    pub epoch:                u64,
    pub timestamp:            i64,
}
