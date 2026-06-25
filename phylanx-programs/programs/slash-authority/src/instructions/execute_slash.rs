// =============================================================================
// programs/slash-authority/src/instructions/execute_slash.rs
//
// execute_slash — record a tiered slash and ENCUMBER the collateral.
//
// DAY-21 REFINEMENT OF DAY 20
// ---------------------------
// Day 20's execute_slash moved lamports out of the vault IMMEDIATELY. Day
// 21 introduces appeals — and an appeal is meaningless if the funds (or,
// worse, a burn) already happened. So the lifecycle changes:
//
//   execute_slash  -> records a PENDING slash and ENCUMBERS the funds:
//                     they move from staked_lamports into
//                     encumbered_lamports, but stay PHYSICALLY in the vault
//                     account. Nothing is transferred out. Nothing is
//                     burned. The appeal window opens.
//
//   then either:
//     appeal_slash + resolve_appeal(overturned) -> encumbered funds are
//                     released back to staked_lamports. No loss.
//   or:
//     settle_slash (after the appeal window) -> the encumbered funds
//                     finally leave the vault (to treasury, or burned).
//
// So "funds held, not burned" is literally true: between execute_slash and
// settle_slash the lamports sit untouched in the vault, merely re-labelled.
//
// AUTHORITY: only the configured `slash_executor` may execute a slash
// (VULN-04 separated slash_executor from appeal_resolver). The slash is
// REFUSED when `slash_config.paused` is true — the pause_authority
// kill-switch.
// =============================================================================

use anchor_lang::prelude::*;
use solana_program::hash::hashv;

// H-1: the certificate-issuer's HealthCertificate is the ON-CHAIN proof that
// an agent is unhealthy. execute_slash deserializes it (read-only) to verify
// the slash is justified. `Account<'info, HealthCertificate>` enforces
// `owner == certificate_issuer::ID` at the deserialize gate — a forged /
// substituted evidence account cannot pass.
use certificate_issuer::state::{AlertTier, ChallengeState, HealthCertificate};

use crate::errors::SlashError;
use crate::events::SlashExecuted;
use crate::state::{
    compute_slash_amount, EscrowVault, OffenseTier, SlashConfig,
    SlashRecord, SlashStatus, APPEAL_WINDOW_SECONDS,
};

/// H-1: domain tag for the on-chain evidence digest. Distinct from every
/// other hashed payload in the protocol so an evidence digest can never be
/// confused with a cert-payload / challenge / rotation digest.
pub const SLASH_EVIDENCE_DOMAIN_TAG: &[u8] = b"phylanx:slash-evidence:v1";

/// H-1: recompute the canonical evidence digest from the certificate that
/// justifies a slash. The recorded `evidence_hash` MUST equal this, so the
/// SlashRecord carries a deterministic, auditable commitment to the exact
/// certificate (and its decision-relevant fields) that grounded the slash.
/// An off-chain auditor re-derives it from the on-chain cert and the cert PDA.
pub fn slash_evidence_digest(cert_key: &Pubkey, cert: &HealthCertificate) -> [u8; 32] {
    hashv(&[
        SLASH_EVIDENCE_DOMAIN_TAG,
        cert_key.as_ref(),
        cert.agent_wallet.as_ref(),
        &cert.epoch.to_le_bytes(),
        &cert.score.to_le_bytes(),
        &[cert.alert_tier],
        &[cert.immediate_red as u8],
        &cert.flags.to_le_bytes(),
        &cert.issued_at.to_le_bytes(),
    ])
    .to_bytes()
}

/// H-1: does this certificate justify the requested offense tier?
///
///   * GREEN  certificate → justifies NOTHING. A healthy agent cannot be
///     slashed at any tier. This is the core invariant the fix restores.
///   * YELLOW/RED         → justifies Minor / Major (a documented health
///     concern exists).
///   * Compromise (terminal, 100% burn) additionally requires a RED tier
///     OR the IMMEDIATE_RED security fast-path — matching the SlashRecord
///     doc-comment ("a CONFIRMED compromise (the security layer's
///     IMMEDIATE_RED, verified)").
pub fn certificate_justifies_tier(tier: OffenseTier, cert: &HealthCertificate) -> bool {
    let alert = AlertTier::from_u8(cert.alert_tier);
    let at_least_yellow =
        matches!(alert, Some(AlertTier::Yellow) | Some(AlertTier::Red));
    match tier {
        OffenseTier::Minor | OffenseTier::Major => at_least_yellow,
        OffenseTier::Compromise => {
            cert.immediate_red || alert == Some(AlertTier::Red)
        }
    }
}

#[derive(Accounts)]
#[instruction(index: u64)]
pub struct ExecuteSlash<'info> {
    /// The agent's escrow vault — its collateral is encumbered here.
    #[account(
        mut,
        seeds = [EscrowVault::SEED_PREFIX, escrow_vault.agent_wallet.as_ref()],
        bump  = escrow_vault.bump,
        constraint = escrow_vault.active @ SlashError::VaultInactive,
    )]
    pub escrow_vault: Account<'info, EscrowVault>,

    /// The SlashRecord for this slash — created here, write-once. `index`
    /// must equal the vault's current slash_count (checked in the handler).
    #[account(
        init,
        payer = slash_executor,
        space = SlashRecord::SPACE,
        seeds = [
            SlashRecord::SEED_PREFIX,
            escrow_vault.agent_wallet.as_ref(),
            &index.to_le_bytes(),
        ],
        bump,
    )]
    pub slash_record: Account<'info, SlashRecord>,

    /// SlashConfig — verifies the signer is the slash executor and the
    /// program is not paused.
    #[account(
        seeds = [SlashConfig::SEED],
        bump  = slash_config.bump,
    )]
    pub slash_config: Account<'info, SlashConfig>,

    /// H-1: the ON-CHAIN evidence that justifies this slash — the agent's
    /// HealthCertificate on the certificate-issuer program.
    ///
    /// SECURITY (the whole point of the H-1 fix):
    ///   * `Account<'info, HealthCertificate>` enforces the account is owned
    ///     by `certificate_issuer::ID` and carries the correct discriminator
    ///     — a forged or substituted evidence account is rejected at the
    ///     deserialize gate.
    ///   * The `seeds = ["cert", agent, epoch]` + `seeds::program` constraint
    ///     re-derives the canonical certificate PDA on the certificate-issuer
    ///     program and proves THIS account is the real certificate for the
    ///     vault's agent (the agent seed is the vault's agent_wallet, so the
    ///     cert cannot belong to a different agent). The epoch seed reads the
    ///     cert's own stored `epoch`, so any in-range epoch is accepted but it
    ///     must be the canonical cert for that (agent, epoch).
    ///   * The handler additionally checks freshness, repudiation, tier
    ///     justification, and binds `evidence_hash` to the cert digest.
    #[account(
        seeds = [
            HealthCertificate::SEED_PREFIX,
            escrow_vault.agent_wallet.as_ref(),
            &health_certificate.epoch.to_le_bytes(),
        ],
        bump = health_certificate.bump,
        seeds::program = certificate_issuer::ID,
        constraint = health_certificate.agent_wallet == escrow_vault.agent_wallet
            @ SlashError::SlashEvidenceAgentMismatch,
    )]
    pub health_certificate: Account<'info, HealthCertificate>,

    /// The slash executor — signs the slash and pays the SlashRecord rent.
    #[account(
        mut,
        constraint = slash_executor.key() == slash_config.slash_executor
            @ SlashError::NotSlashAuthority,
    )]
    pub slash_executor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:           Context<ExecuteSlash>,
    index:         u64,
    offense_tier:  u8,
    evidence_hash: [u8; 32],
) -> Result<()> {
    // -- Refuse while the pause kill-switch is active -----------------------
    // H-04: read the time-aware pause state so an EXPIRED pause does not
    // continue to block settlement after its auto-expiry window has run.
    let now = Clock::get()?.unix_timestamp;
    require!(
        !ctx.accounts.slash_config.is_paused_now(now),
        SlashError::SettlementsPaused,
    );

    // -- Validate inputs ----------------------------------------------------
    let tier = OffenseTier::from_u8(offense_tier)
        .ok_or(SlashError::InvalidOffenseTier)?;
    require!(evidence_hash != [0u8; 32], SlashError::ZeroEvidence);

    // -- H-1: VERIFY THE SLASH IS JUSTIFIED BY ON-CHAIN EVIDENCE ------------
    // Before this fix, `execute_slash` destroyed collateral on the executor's
    // word plus an opaque `evidence_hash` that nothing on chain checked. A
    // compromised/malicious slash_executor could slash any vault arbitrarily.
    //
    // Now the slash MUST cite a certificate-issuer-owned HealthCertificate
    // (account-level owner + canonical-PDA checks are in the Accounts struct)
    // and that certificate must actually justify destroying funds:
    let cert = &ctx.accounts.health_certificate;

    //   1. FRESHNESS — a slash cannot rest on a stale certificate. Uses the
    //      certificate's own published freshness ceiling (TA-6, 48h). A cert
    //      from the future also reads as stale (clock-skew safe).
    require!(
        cert.is_fresh_default(now),
        SlashError::SlashEvidenceStale,
    );

    //   2. NOT REPUDIATED — a certificate whose slot-anchor challenge was
    //      Upheld is invalid and cannot ground a slash.
    require!(
        ChallengeState::from_u8(cert.challenge_state) != Some(ChallengeState::Upheld),
        SlashError::SlashEvidenceRepudiated,
    );

    //   3. TIER JUSTIFICATION — the certificate's severity must support the
    //      requested tier. A GREEN (healthy) certificate justifies NOTHING;
    //      Compromise requires RED / IMMEDIATE_RED. This is the invariant
    //      that makes "slash any vault you like" impossible.
    require!(
        certificate_justifies_tier(tier, cert),
        SlashError::SlashEvidenceTierUnjustified,
    );

    //   4. EVIDENCE BINDING — the recorded `evidence_hash` must be the
    //      deterministic digest of THIS certificate, so the SlashRecord is a
    //      forensically meaningful, re-derivable commitment to the proof —
    //      not an arbitrary 32 bytes the executor invented.
    let expected_evidence = slash_evidence_digest(&cert.key(), cert);
    require!(
        evidence_hash == expected_evidence,
        SlashError::SlashEvidenceHashMismatch,
    );

    // The SlashRecord index must be the vault's NEXT slash index -- keeps
    // the ["slash", agent, count] history strictly append-only.
    require!(
        index == ctx.accounts.escrow_vault.slash_count,
        SlashError::SlashIndexMismatch,
    );

    let stake_before = ctx.accounts.escrow_vault.staked_lamports;
    require!(stake_before > 0, SlashError::NothingToSlash);

    // -- Compute the slash amount -------------------------------------------
    let slash_amount = compute_slash_amount(stake_before, tier);
    let stake_after = stake_before
        .checked_sub(slash_amount)
        .ok_or(SlashError::MathOverflow)?;

    // -- ENCUMBER the funds -- do NOT move them -----------------------------
    // The lamports stay physically in the vault account. We merely move the
    // bookkeeping figure from `staked_lamports` (free) to
    // `encumbered_lamports` (held, pending settlement). No transfer, no burn.
    let vault = &mut ctx.accounts.escrow_vault;
    vault.staked_lamports     = stake_after;
    vault.encumbered_lamports = vault.encumbered_lamports
        .checked_add(slash_amount)
        .ok_or(SlashError::MathOverflow)?;
    vault.slash_count         = vault.slash_count
        .checked_add(1)
        .ok_or(SlashError::MathOverflow)?;
    // NOTE: the vault is NOT deactivated here even for a Compromise -- that
    // happens at settlement, so an appeal can still rescue the agent.

    // -- Write the PENDING SlashRecord --------------------------------------
    let record = &mut ctx.accounts.slash_record;
    record.agent_wallet     = vault.agent_wallet;
    record.index            = index;
    record.offense_tier     = tier.as_u8();
    record.slashed_lamports = slash_amount;
    record.destination      = tier.destination().as_u8();
    record.evidence_hash    = evidence_hash;
    record.stake_before     = stake_before;
    record.stake_after      = stake_after;
    record.executed_at      = now;
    record.executor         = ctx.accounts.slash_executor.key();
    record.bump             = ctx.bumps.slash_record;
    record.layout_version   = SlashRecord::CURRENT_LAYOUT_VERSION;
    // Day-21 lifecycle: the slash starts PENDING with an open appeal window.
    record.status           = SlashStatus::Pending.as_u8();
    record.appeal_deadline  = now
        .checked_add(APPEAL_WINDOW_SECONDS)
        .ok_or(SlashError::MathOverflow)?;
    record.appeal_hash      = [0u8; 32];
    record.appealed_at      = 0;
    // VULN-04 fields default to zero — only resolve_appeal(uphold=true)
    // populates them.
    record.settlement_unlock_at = 0;
    record.appeal_resolved_by   = Pubkey::default();
    // H-03: snapshot the treasury key as it stands RIGHT NOW. settle_slash
    // pins a Treasury-destination payout against this snapshot, so a
    // subsequent treasury rotation cannot retarget this slash. Burn-tier
    // slashes don't go to the treasury at all — we leave the snapshot
    // zero for them; settle_slash uses the global INCINERATOR constant
    // for those.
    record.treasury_at_execute = match tier.destination() {
        crate::state::SlashDestination::Treasury => ctx.accounts.slash_config.treasury,
        crate::state::SlashDestination::Burn     => Pubkey::default(),
    };
    // M-08: snapshot the live SlashConfig authority epoch. Bound to
    // `executor` via the same write, this is the forensic anchor that
    // makes a post-rotation audit a single u32 lookup against the
    // `AuthorityRotationEnacted` log instead of an event-by-event replay.
    record.slash_config_version_at_execute = ctx.accounts.slash_config.slash_config_version;

    emit!(SlashExecuted {
        agent_wallet:     vault.agent_wallet,
        index,
        offense_tier:     tier.as_u8(),
        slashed_lamports: slash_amount,
        destination:      record.destination,
        stake_after,
        terminal:         tier.is_terminal(),
        executor:         ctx.accounts.slash_executor.key(),
        executed_at:      now,
        // M-08: surface the snapshot on the event too, so the off-chain
        // indexer doesn't need to round-trip the PDA to correlate this
        // slash with its authority epoch.
        slash_config_version_at_execute: ctx.accounts.slash_config.slash_config_version,
    });

    msg!(
        "slash recorded (PENDING): agent={} tier={:?} amount={} encumbered",
        vault.agent_wallet, tier, slash_amount,
    );
    Ok(())
}

// =============================================================================
// H-1 tests — the slash-evidence decision logic, runtime-free.
//
// The account-level guards (owner == certificate_issuer::ID, canonical cert
// PDA, agent binding) are enforced by Anchor at the deserialize gate and are
// exercised by the TypeScript integration suite. These tests pin the PURE
// decision helpers that gate whether a given certificate may ground a slash.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use certificate_issuer::state::AlertTier;

    /// Build a HealthCertificate with the fields the H-1 logic reads; every
    /// other field is a deterministic filler (no randomness — the digest
    /// tests rely on stable bytes).
    fn cert(alert_tier: AlertTier, immediate_red: bool) -> HealthCertificate {
        HealthCertificate {
            agent_wallet:          Pubkey::new_from_array([7u8; 32]),
            epoch:                 42,
            score:                 123,
            alert_tier:            alert_tier.as_u8(),
            flags:                 0xABCD,
            issued_at:             1_000_000,
            issuer:                Pubkey::new_from_array([9u8; 32]),
            baseline_hash:         [1u8; 32],
            immediate_red,
            bump:                  254,
            layout_version:        HealthCertificate::CURRENT_LAYOUT_VERSION,
            signer_count:          3,
            input_commitment:      [2u8; 32],
            slot_anchor_slot:      555,
            slot_anchor_hash:      [3u8; 32],
            challenge_state:       ChallengeState::None.as_u8(),
            baseline_commit_nonce: 11,
            scoring_code_hash:     [4u8; 32],
            issuer_config_version: 1,
            taxonomy_version:      1,
            failure_mode_bitmask:  0xABCD,
            remediation_codes:     0,
            diagnosis_payload_hash: [5u8; 32],
            _reserved:             [0u8; 1],
        }
    }

    #[test]
    fn green_certificate_justifies_no_tier() {
        let c = cert(AlertTier::Green, false);
        assert!(!certificate_justifies_tier(OffenseTier::Minor, &c));
        assert!(!certificate_justifies_tier(OffenseTier::Major, &c));
        assert!(!certificate_justifies_tier(OffenseTier::Compromise, &c));
    }

    #[test]
    fn yellow_justifies_minor_and_major_but_not_compromise() {
        let c = cert(AlertTier::Yellow, false);
        assert!(certificate_justifies_tier(OffenseTier::Minor, &c));
        assert!(certificate_justifies_tier(OffenseTier::Major, &c));
        assert!(!certificate_justifies_tier(OffenseTier::Compromise, &c));
    }

    #[test]
    fn red_justifies_every_tier_including_compromise() {
        let c = cert(AlertTier::Red, false);
        assert!(certificate_justifies_tier(OffenseTier::Minor, &c));
        assert!(certificate_justifies_tier(OffenseTier::Major, &c));
        assert!(certificate_justifies_tier(OffenseTier::Compromise, &c));
    }

    #[test]
    fn immediate_red_justifies_compromise_even_on_yellow() {
        // The IMMEDIATE_RED security fast-path can trip while the composite
        // tier is still YELLOW — it must still ground a terminal Compromise.
        let c = cert(AlertTier::Yellow, true);
        assert!(certificate_justifies_tier(OffenseTier::Compromise, &c));
    }

    #[test]
    fn evidence_digest_is_deterministic_and_field_sensitive() {
        let key = Pubkey::new_from_array([1u8; 32]);
        let c = cert(AlertTier::Red, false);
        // Deterministic for identical inputs.
        assert_eq!(slash_evidence_digest(&key, &c), slash_evidence_digest(&key, &c));
        // A different cert key changes the digest.
        let key2 = Pubkey::new_from_array([2u8; 32]);
        assert_ne!(slash_evidence_digest(&key, &c), slash_evidence_digest(&key2, &c));
        // A change to a decision-relevant field changes the digest.
        let mut c2 = cert(AlertTier::Red, false);
        c2.score = c.score + 1;
        assert_ne!(slash_evidence_digest(&key, &c), slash_evidence_digest(&key, &c2));
        let mut c3 = cert(AlertTier::Red, false);
        c3.alert_tier = AlertTier::Yellow.as_u8();
        assert_ne!(slash_evidence_digest(&key, &c), slash_evidence_digest(&key, &c3));
    }
}
