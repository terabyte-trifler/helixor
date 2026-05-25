// =============================================================================
// programs/slash-authority/tests/vuln04_authority_separation.rs
//
// Pure unit tests pinning the VULN-04 fix: role separation
// (slash_executor != appeal_resolver != pause_authority), the post-
// uphold settlement timelock helper, the pause flag on SlashConfig, and
// the layout-version bumps. Runtime-level enforcement of these gates is
// covered by the TypeScript integration test.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::state::{
    validate_authority_separation, AuthoritySeparationError, SlashConfig,
    SlashRecord, SlashStatus, MIN_SETTLEMENT_TIMELOCK_SECONDS,
    SLASH_CONFIG_LAYOUT_VERSION,
};

// ----------------------------------------------------------------------------
// SlashConfig layout + role-key model
// ----------------------------------------------------------------------------

#[test]
fn slash_config_layout_grew_for_role_separation() {
    // VULN-04 grew SlashConfig from 105 -> 217 bytes to hold the three
    // distinct role keys, the settlement timelock, the pause flag, the
    // layout version and a forward-compat reserve.
    assert_eq!(SlashConfig::SIZE_WITHOUT_DISCRIMINATOR, 209);
    assert_eq!(SlashConfig::SPACE, 217);
}

#[test]
fn slash_config_layout_version_pinned() {
    // Bumped to 2 by the VULN-04 layout change. Bump again on any future
    // on-disk shape change.
    assert_eq!(SLASH_CONFIG_LAYOUT_VERSION, 2);
}

#[test]
fn min_settlement_timelock_is_72_hours() {
    // The audit requires a 72h minimum post-uphold timelock.
    assert_eq!(MIN_SETTLEMENT_TIMELOCK_SECONDS, 72 * 3_600);
}

// ----------------------------------------------------------------------------
// validate_authority_separation — the three-role distinctness gate
// ----------------------------------------------------------------------------

fn p(n: u8) -> Pubkey {
    let mut b = [0u8; 32];
    b[0] = n;
    Pubkey::new_from_array(b)
}

#[test]
fn three_distinct_non_default_keys_accepted() {
    assert_eq!(
        validate_authority_separation(&p(1), &p(2), &p(3)),
        Ok(()),
    );
}

#[test]
fn executor_equal_to_resolver_rejected() {
    assert_eq!(
        validate_authority_separation(&p(1), &p(1), &p(3)),
        Err(AuthoritySeparationError::NotDistinct),
    );
}

#[test]
fn executor_equal_to_pauser_rejected() {
    assert_eq!(
        validate_authority_separation(&p(1), &p(2), &p(1)),
        Err(AuthoritySeparationError::NotDistinct),
    );
}

#[test]
fn resolver_equal_to_pauser_rejected() {
    assert_eq!(
        validate_authority_separation(&p(1), &p(2), &p(2)),
        Err(AuthoritySeparationError::NotDistinct),
    );
}

#[test]
fn default_executor_rejected() {
    assert_eq!(
        validate_authority_separation(&Pubkey::default(), &p(2), &p(3)),
        Err(AuthoritySeparationError::DefaultPubkey),
    );
}

#[test]
fn default_resolver_rejected() {
    assert_eq!(
        validate_authority_separation(&p(1), &Pubkey::default(), &p(3)),
        Err(AuthoritySeparationError::DefaultPubkey),
    );
}

#[test]
fn default_pauser_rejected() {
    assert_eq!(
        validate_authority_separation(&p(1), &p(2), &Pubkey::default()),
        Err(AuthoritySeparationError::DefaultPubkey),
    );
}

#[test]
fn all_three_default_rejected_for_zero_not_distinct() {
    // Even though the keys collide, the DefaultPubkey check fires first.
    assert_eq!(
        validate_authority_separation(
            &Pubkey::default(),
            &Pubkey::default(),
            &Pubkey::default(),
        ),
        Err(AuthoritySeparationError::DefaultPubkey),
    );
}

// ----------------------------------------------------------------------------
// SlashRecord — settlement-timelock semantics
// ----------------------------------------------------------------------------

fn record_with_timelock(unlock_at: i64) -> SlashRecord {
    SlashRecord {
        agent_wallet:         Default::default(),
        index:                0,
        offense_tier:         0,
        slashed_lamports:     0,
        destination:          0,
        evidence_hash:        [0u8; 32],
        stake_before:         0,
        stake_after:          0,
        executed_at:          0,
        executor:             Default::default(),
        bump:                 0,
        layout_version:       SlashRecord::CURRENT_LAYOUT_VERSION,
        status:               SlashStatus::Pending.as_u8(),
        appeal_deadline:      0,
        appeal_hash:          [0u8; 32],
        appealed_at:          0,
        settlement_unlock_at: unlock_at,
        appeal_resolved_by:   Default::default(),
        _reserved:            [0u8; 8],
    }
}

#[test]
fn timelock_zero_is_always_elapsed() {
    // Never-appealed slashes carry unlock_at == 0 — the appeal-window
    // gate is the only constraint for them.
    let r = record_with_timelock(0);
    assert!(r.settlement_timelock_elapsed(0));
    assert!(r.settlement_timelock_elapsed(i64::MAX));
}

#[test]
fn timelock_blocks_settlement_before_unlock() {
    let r = record_with_timelock(1_000_000);
    assert!(!r.settlement_timelock_elapsed(999_999));
}

#[test]
fn timelock_releases_exactly_at_unlock() {
    let r = record_with_timelock(1_000_000);
    // At exactly unlock_at the timelock has elapsed — settlement may
    // proceed. Mirrors the appeal-window semantics.
    assert!(r.settlement_timelock_elapsed(1_000_000));
}

#[test]
fn timelock_elapsed_after_unlock() {
    let r = record_with_timelock(1_000_000);
    assert!(r.settlement_timelock_elapsed(1_000_001));
}

#[test]
fn slash_record_layout_version_bumped() {
    // VULN-04 changed the on-disk shape — layout version must move.
    assert_eq!(SlashRecord::CURRENT_LAYOUT_VERSION, 2);
}
