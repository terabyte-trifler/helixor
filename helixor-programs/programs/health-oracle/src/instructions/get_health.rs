use anchor_lang::prelude::*;
use anchor_lang::AccountDeserialize;

use crate::{
    errors::HelixorError,
    state::{AlertLevel, ScoreSource, TrustCertificate, TrustScore},
};

pub fn handler(ctx: Context<crate::GetHealth>) -> Result<TrustScore> {
    let reg   = &ctx.accounts.agent_registration;
    let clock = Clock::get()?;
    let agent = reg.agent_wallet;

    if !reg.active {
        let score = TrustScore {
            agent, score: 0, alert: AlertLevel::Red,
            success_rate: 0, anomaly_flag: true,
            updated_at: clock.unix_timestamp, is_fresh: true,
            source: ScoreSource::Deactivated,
        };
        emit!(HealthQueried {
            agent, querier: ctx.accounts.querier.key(),
            score: 0, alert: AlertLevel::Red, is_fresh: true,
            source: ScoreSource::Deactivated, timestamp: clock.unix_timestamp,
        });
        return Ok(score);
    }

    let (expected_cert_pda, _) = Pubkey::find_program_address(
        &[b"score", agent.as_ref()], ctx.program_id,
    );
    require_keys_eq!(
        ctx.accounts.trust_certificate.key(), expected_cert_pda,
        HelixorError::InvalidCertificateAddress
    );

    let cert_account_info = ctx.accounts.trust_certificate.to_account_info();
    let cert_data         = cert_account_info.data.borrow();

    if cert_data.is_empty() || cert_account_info.lamports() == 0 {
        let score = TrustScore {
            agent, score: 500, alert: AlertLevel::Yellow,
            success_rate: 10_000, anomaly_flag: false,
            updated_at: 0, is_fresh: false,
            source: ScoreSource::Provisional,
        };
        emit!(HealthQueried {
            agent, querier: ctx.accounts.querier.key(),
            score: 500, alert: AlertLevel::Yellow, is_fresh: false,
            source: ScoreSource::Provisional, timestamp: clock.unix_timestamp,
        });
        return Ok(score);
    }

    drop(cert_data);
    let cert: TrustCertificate = {
        let mut data: &[u8] = &cert_account_info.data.borrow();
        TrustCertificate::try_deserialize(&mut data)
            .map_err(|_| error!(HelixorError::InvalidCertificateAddress))?
    };
    require_keys_eq!(
        cert.agent_wallet, agent,
        HelixorError::InvalidCertificateAddress
    );

    let age = clock.unix_timestamp
        .checked_sub(cert.updated_at)
        .ok_or(HelixorError::MathOverflow)?;
    let is_fresh = (0..TrustCertificate::MAX_AGE_SECONDS).contains(&age);
    let source   = if is_fresh { ScoreSource::Live } else { ScoreSource::Stale };

    emit!(HealthQueried {
        agent: cert.agent_wallet,
        querier: ctx.accounts.querier.key(),
        score: cert.score, alert: cert.alert,
        is_fresh, source, timestamp: clock.unix_timestamp,
    });

    Ok(TrustScore {
        agent: cert.agent_wallet,
        score: cert.score, alert: cert.alert,
        success_rate: cert.success_rate, anomaly_flag: cert.anomaly_flag,
        updated_at: cert.updated_at, is_fresh, source,
    })
}

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
