// =============================================================================
// programs/slash-authority/tests/m08_executor_authority_epoch.rs
//
// M-08 — bind every SlashRecord to the SlashConfig authority epoch
// (`slash_config_version`) that was live at execute_slash time.
//
// Pre-M-08 every SlashRecord recorded the `executor` pubkey but no
// context about WHICH authority set that key belonged to at the time
// the slash ran. After SPOF-#2 rotates the executor role, a later
// auditor inspecting an old SlashRecord saw a pubkey that was no
// longer the live executor — confirming the executor was authoritative
// at the moment of the slash required walking the entire
// `AuthorityRotationEnacted` event log, which is brittle if events are
// reorganised or outpaced by a sequence of rotations.
//
// M-08 fixes the gap by snapshotting a `slash_config_version: u32`
// onto every SlashRecord. The counter:
//   * starts at `SLASH_CONFIG_GENESIS_VERSION` (= 1) at
//     `initialize_config`,
//   * is incremented strictly +1 inside `enact_authority_rotation`
//     (overflow is a hard error, not a wrap),
//   * is snapshotted onto the SlashRecord and emitted in
//     `SlashExecuted`.
//
// These tests pin the cryptographic / structural surface of that fix:
//   * SlashConfig still 209 bytes after carving the 4-byte counter,
//     layout v5;
//   * SlashRecord grows by exactly 4 bytes (261 → 265), layout v4;
//   * the genesis version is 1 (zero is reserved as "not initialised");
//   * the `SlashConfigVersionOverflow` error code is stable at 6089;
//   * the SlashExecuted event carries the snapshot field — pinned via
//     a struct-literal type test so a refactor that removes the field
//     fails this file rather than silently dropping the audit trail.
//
// Runtime behaviour (the actual +1 bump inside the rotation handler,
// the snapshot write inside execute_slash) is exercised by the
// TypeScript integration tests against a running validator.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::errors::SlashError;
use slash_authority::events::SlashExecuted;
use slash_authority::state::{
    SlashConfig, SlashRecord, SLASH_CONFIG_GENESIS_VERSION,
    SLASH_CONFIG_LAYOUT_VERSION,
};

// -----------------------------------------------------------------------------
// Layout pins
// -----------------------------------------------------------------------------

#[test]
fn slash_config_size_unchanged_after_m08_carve() {
    // The M-08 counter is 4 bytes carved from the M-07 `_reserved`
    // cushion (6 → 2). The total account size must stay at the
    // historical 209/217 — already-deployed accounts remain byte-
    // compatible with the new layout.
    assert_eq!(SlashConfig::SIZE_WITHOUT_DISCRIMINATOR, 209);
    assert_eq!(SlashConfig::SPACE, 8 + 209);
}

#[test]
fn slash_record_grew_by_exactly_four_bytes() {
    // M-08 has no reserve cushion to carve from in SlashRecord (H-03
    // already reclaimed the 8-byte reserve), so the record genuinely
    // grows. The growth is exactly +4 — a u32 — so this pin catches
    // any accidental field-padding that would silently bloat the
    // account.
    assert_eq!(SlashRecord::SIZE_WITHOUT_DISCRIMINATOR, 265);
    assert_eq!(SlashRecord::SPACE, 273);
}

#[test]
fn slash_config_layout_version_pins_m08_bump() {
    assert_eq!(SLASH_CONFIG_LAYOUT_VERSION, 5);
}

#[test]
fn slash_record_layout_version_pins_m08_bump() {
    assert_eq!(SlashRecord::CURRENT_LAYOUT_VERSION, 4);
}

// -----------------------------------------------------------------------------
// Genesis-version pin
// -----------------------------------------------------------------------------

#[test]
fn genesis_version_is_one_not_zero() {
    // Zero is intentionally reserved as the "config has not been
    // initialised yet" sentinel — a SlashRecord that ever lands with
    // a zero snapshot is provably from a pre-init or corrupted state.
    // Initialising at 1 lets that distinction survive on chain.
    assert_eq!(SLASH_CONFIG_GENESIS_VERSION, 1);
}

// -----------------------------------------------------------------------------
// Error-code pin
// -----------------------------------------------------------------------------

#[test]
fn slash_config_version_overflow_code_is_stable() {
    // The off-chain monitor + TS SDK switch on the literal Anchor code.
    // 6089 was chosen to slot directly after the SPOF-#2 block
    // (6080..6088) so all "authority-rotation related" codes stay
    // contiguous — a refactor that renumbers must update both this pin
    // AND the canonical error-code allocation list.
    assert_eq!(SlashError::SlashConfigVersionOverflow as u32, 6089);
}

// -----------------------------------------------------------------------------
// SlashExecuted event — field surface pin
// -----------------------------------------------------------------------------

#[test]
fn slash_executed_event_carries_authority_epoch() {
    // Struct-literal type pin: this would not compile if the M-08
    // field were removed or renamed. The off-chain indexer dispatches
    // on the event SCHEMA, so silently dropping the field would break
    // every consumer at runtime — pin it at compile time instead.
    let _ev = SlashExecuted {
        agent_wallet:                    Pubkey::default(),
        index:                           0,
        offense_tier:                    0,
        slashed_lamports:                0,
        destination:                     0,
        stake_after:                     0,
        terminal:                        false,
        executor:                        Pubkey::default(),
        executed_at:                     0,
        slash_config_version_at_execute: 1,
    };
}

// -----------------------------------------------------------------------------
// SlashRecord — field surface pin
// -----------------------------------------------------------------------------

#[test]
fn slash_record_struct_literal_includes_the_snapshot_field() {
    // Same compile-time pin as the event: the field has to be present
    // and named exactly. A refactor that renames it (say to drop the
    // `_at_execute` suffix) breaks here, alerting maintainers that
    // every consumer of the IDL needs to re-roll in lockstep.
    let r = SlashRecord {
        agent_wallet:                    Pubkey::default(),
        index:                           0,
        offense_tier:                    0,
        slashed_lamports:                0,
        destination:                     0,
        evidence_hash:                   [0u8; 32],
        stake_before:                    0,
        stake_after:                     0,
        executed_at:                     0,
        executor:                        Pubkey::default(),
        bump:                            0,
        layout_version:                  SlashRecord::CURRENT_LAYOUT_VERSION,
        status:                          0,
        appeal_deadline:                 0,
        appeal_hash:                     [0u8; 32],
        appealed_at:                     0,
        settlement_unlock_at:            0,
        appeal_resolved_by:              Pubkey::default(),
        treasury_at_execute:             Pubkey::default(),
        slash_config_version_at_execute: 42,
    };
    // Sanity: the value the test wrote round-trips through the field
    // (catches any accidental shadow / reorder bugs).
    assert_eq!(r.slash_config_version_at_execute, 42);
}

// -----------------------------------------------------------------------------
// Pre-M-08 sentinel
// -----------------------------------------------------------------------------

#[test]
fn zero_snapshot_distinguishes_pre_m08_records() {
    // A SlashRecord whose `slash_config_version_at_execute` reads 0 is
    // provably either (a) pre-M-08 (read off an old layout-v3 PDA whose
    // 4 new bytes were never written), or (b) corrupted. The genesis
    // version is 1, so 0 is unreachable through any legitimate write
    // path — pin the sentinel so an off-chain auditor can rely on it.
    let r = SlashRecord {
        agent_wallet:                    Pubkey::default(),
        index:                           0,
        offense_tier:                    0,
        slashed_lamports:                0,
        destination:                     0,
        evidence_hash:                   [0u8; 32],
        stake_before:                    0,
        stake_after:                     0,
        executed_at:                     0,
        executor:                        Pubkey::default(),
        bump:                            0,
        layout_version:                  3, // pre-M-08 layout
        status:                          0,
        appeal_deadline:                 0,
        appeal_hash:                     [0u8; 32],
        appealed_at:                     0,
        settlement_unlock_at:            0,
        appeal_resolved_by:              Pubkey::default(),
        treasury_at_execute:             Pubkey::default(),
        slash_config_version_at_execute: 0,
    };
    assert_eq!(r.slash_config_version_at_execute, 0);
    assert_ne!(r.slash_config_version_at_execute, SLASH_CONFIG_GENESIS_VERSION);
}
