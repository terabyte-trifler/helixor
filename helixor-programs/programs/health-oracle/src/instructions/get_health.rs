// =============================================================================
// get_health — Day 3 COMPLETE
//
// Read-only public endpoint. Any caller — wallet, signer, or another program
// via CPI — calls this and gets back a TrustScore.
//
// What this function answers:
//   "Right now, what does Helixor say about this agent?"
//
// What it does NOT do:
//   - It does not enforce a minimum score. That's the caller's policy.
//   - It does not check fee payment. There's no fee.
//   - It does not modify state. It's a pure read.
//
// Four return paths (matched 1:1 with ScoreSource enum):
//
//   ┌─────────────────┬──────────────────────────────────────────────────────┐
//   │ ScoreSource     │ When it fires                                         │
//   ├─────────────────┼──────────────────────────────────────────────────────┤
//   │ Live            │ Active agent, cert exists, written < 48h ago         │
//   │ Stale           │ Active agent, cert exists, written > 48h ago         │
//   │ Provisional     │ Active agent, no cert (first 24h after register)     │
//   │ Deactivated     │ Agent registration.active = false                    │
//   └─────────────────┴──────────────────────────────────────────────────────┘
//
// Why the cert is passed as UncheckedAccount, not Account:
//   The cert PDA may not exist yet (Provisional case). Anchor's Account<T>
//   constraint requires the account to exist with valid discriminator —
//   it would fail before our handler runs. We accept it as UncheckedAccount,
//   verify the address matches the canonical PDA, then deserialize manually
//   only if the account has data.
// =============================================================================

use anchor_lang::prelude::*;
use anchor_lang::AccountDeserialize;

use crate::{
    errors::HelixorError,
    state::{AgentRegistration, AlertLevel, ScoreSource, TrustCertificate, TrustScore},
    GetHealth,
};

pub fn handler(ctx: Context<GetHealth>) -> Result<TrustScore> {
    let reg   = &ctx.accounts.agent_registration;
    let clock = Clock::get()?;
    let agent = reg.agent_wallet;

    // ── Fast path 1: agent deactivated ────────────────────────────────────────
    // If the operator has deactivated their own agent, no further checks
    // matter — the answer is RED, full stop. We mark this as is_fresh=true
    // because the deactivation IS the current state of truth.
    if !reg.active {
        let score = TrustScore {
            agent,
            score:        0,
            alert:        AlertLevel::Red,
            success_rate: 0,
            anomaly_flag: true,
            updated_at:   clock.unix_timestamp,
            is_fresh:     true,
            source:       ScoreSource::Deactivated,
        };
        log_query(&ctx, &score, ScoreSource::Deactivated);
        return Ok(score);
    }

    // ── Verify the cert account is the canonical PDA for this agent ───────────
    // Without this check, a malicious caller could pass any account here as
    // the "cert" and we'd return whatever score it claims. We verify that the
    // account address matches the program-derived address keyed on agent_wallet.
    let (expected_cert_pda, _expected_bump) = Pubkey::find_program_address(
        &[b"score", agent.as_ref()],
        ctx.program_id,
    );
    require_keys_eq!(
        ctx.accounts.trust_certificate.key(),
        expected_cert_pda,
        HelixorError::InvalidCertificateAddress
    );

    // ── Fast path 2: no cert yet (Provisional) ───────────────────────────────
    // The cert PDA hasn't been created yet — agent registered but oracle
    // hasn't run its first scoring pass. Cert account has zero data.
    let cert_account_info = ctx.accounts.trust_certificate.to_account_info();
    let cert_data         = cert_account_info.data.borrow();

    if cert_data.is_empty() || cert_account_info.lamports() == 0 {
        let score = TrustScore {
            agent,
            score:        500,                  // neutral midpoint
            alert:        AlertLevel::Yellow,   // caution by default
            success_rate: 10_000,               // 100% — no failures recorded
            anomaly_flag: false,
            updated_at:   0,
            is_fresh:     false,
            source:       ScoreSource::Provisional,
        };
        log_query(&ctx, &score, ScoreSource::Provisional);
        return Ok(score);
    }

    // ── Deserialize cert manually ─────────────────────────────────────────────
    // Drop the borrow before deserializing — TrustCertificate::try_deserialize
    // borrows the data slice itself.
    drop(cert_data);

    let cert: TrustCertificate = {
        let mut data: &[u8] = &cert_account_info.data.borrow();
        TrustCertificate::try_deserialize(&mut data)
            .map_err(|_| error!(HelixorError::InvalidCertificateAddress))?
    };

    // Defence-in-depth: cert must be for THIS agent. The address check above
    // already guarantees this, but we double-verify the in-data field matches.
    require_keys_eq!(
        cert.agent_wallet,
        agent,
        HelixorError::InvalidCertificateAddress
    );

    // ── Determine freshness ───────────────────────────────────────────────────
    let age = clock
        .unix_timestamp
        .checked_sub(cert.updated_at)
        .ok_or(HelixorError::MathOverflow)?;

    let is_fresh = age >= 0 && age < TrustCertificate::MAX_AGE_SECONDS;
    let source   = if is_fresh { ScoreSource::Live } else { ScoreSource::Stale };

    // ── Build response ────────────────────────────────────────────────────────
    let score = TrustScore {
        agent:        cert.agent_wallet,
        score:        cert.score,
        alert:        cert.alert,
        success_rate: cert.success_rate,
        anomaly_flag: cert.anomaly_flag,
        updated_at:   cert.updated_at,
        is_fresh,
        source,
    };

    log_query(&ctx, &score, source);
    Ok(score)
}

/// Emit observability event. Every health query is logged so off-chain
/// analytics can compute query volume per agent, per consumer protocol, etc.
fn log_query(ctx: &Context<GetHealth>, score: &TrustScore, source: ScoreSource) {
    emit!(HealthQueried {
        agent:     score.agent,
        querier:   ctx.accounts.querier.key(),
        score:     score.score,
        alert:     score.alert,
        is_fresh:  score.is_fresh,
        source,
        timestamp: Clock::get().map(|c| c.unix_timestamp).unwrap_or(0),
    });
}

// =============================================================================
// Events
// =============================================================================

/// Emitted on every successful query.
///
/// Indexers use this to build:
///   - Query volume per agent (popularity)
///   - Query volume per querier (which protocols use Helixor)
///   - Source distribution (how often is the answer Stale vs Live?)
///
/// CPI callers do NOT see these events directly — they're program logs of
/// the health_oracle program. Indexers reading the cluster's transaction logs
/// observe them.
#[event]
pub struct HealthQueried {
    pub agent:     Pubkey,
    pub querier:   Pubkey,
    pub score:     u16,
    pub alert:     AlertLevel,
    pub is_fresh:  bool,
    pub source:    ScoreSource,
    pub timestamp: i64,
}
