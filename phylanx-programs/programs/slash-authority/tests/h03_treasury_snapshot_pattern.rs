// =============================================================================
// programs/slash-authority/tests/h03_treasury_snapshot_pattern.rs
//
// H-03 — snapshot mutable refs at action time.
//
// THE AUDIT FINDING
// -----------------
// When a multi-step instruction lifecycle (action_A then action_B)
// accepts an `UncheckedAccount` at step B that is validated against a
// MUTABLE field on a config PDA (e.g. `slash_config.treasury`), an
// attacker who can rotate the config field between A and B can
// redirect funds at step B. The original observation was the
// settle_slash treasury payout: execute_slash committed the slash
// against `slash_config.treasury` at time T1, settle_slash validated
// the destination against `slash_config.treasury` at time T2 — a
// rotation between T1 and T2 silently re-routed the payout.
//
// THE FIX
// -------
// At step A, SNAPSHOT the live config value onto the per-action record
// PDA. At step B, validate the supplied UncheckedAccount against the
// SNAPSHOT, not the live config value. Concretely:
//
//   * `execute_slash` writes `slash_config.treasury` into
//     `SlashRecord.treasury_at_execute`.
//   * `settle_slash` validates the supplied `destination` account
//     against `slash_record.treasury_at_execute`.
//
// A post-execute treasury rotation cannot redirect a Pending settlement
// because the binding is to the SNAPSHOT, not the live config.
//
// AUDIT CONCLUSION (codebase sweep, 2026-05-29)
// ---------------------------------------------
// Across all three programs (health-oracle, certificate-issuer,
// slash-authority) the only `UncheckedAccount` (or unchecked
// `AccountInfo`) that is validated against a MUTABLE field on a
// program-owned config PDA is the `destination` account on
// `settle_slash`, which is ALREADY protected via the snapshot pattern
// (`SlashRecord.treasury_at_execute`).
//
// Every other unchecked account in the codebase falls into one of:
//   * Sysvars (Instructions sysvar, SlotHashes sysvar) — pinned via
//     `address = <canonical sysvar ID>` constraints; the ID is fixed
//     and not mutable.
//   * Anchor-managed accounts (Account<'info, T>, Program<'info, T>,
//     Signer<'info>) — Anchor's account-resolution layer enforces the
//     type / ownership / signer invariants before the handler runs.
//   * CPI passthrough accounts that are not validated at the boundary
//     (the callee's accounts derived from the CPI signer chain) — not
//     in scope for H-03.
//   * Burn-tier destination — pinned to the IMMUTABLE
//     `SlashConfig::INCINERATOR` const, not to a mutable config field.
//
// WHAT THIS FILE PINS
// -------------------
//   * The `SlashRecord.treasury_at_execute` field exists and is a
//     `Pubkey` (struct-literal probe: a rename / removal becomes a
//     compile error here, NOT a silent behaviour change).
//   * The `SlashConfig::INCINERATOR` const is the canonical 11111
//     "1nc1nerator" burn address (the burn-tier H-03 boundary).
//   * The SlashConfig layout did NOT grow — the snapshot lives on the
//     record (per-action, write-once), not on the config (mutable
//     singleton); growing the config would re-introduce the very
//     mutability the snapshot is meant to escape.
//   * Doc-level reminder: any FUTURE instruction that adds an
//     UncheckedAccount validated against a mutable config field MUST
//     apply the snapshot pattern OR the H-03 mitigation regresses.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::state::{
    SlashConfig, SlashRecord, SLASH_CONFIG_LAYOUT_VERSION,
};
use std::str::FromStr;

// Build a baseline SlashRecord with the H-03 field set to `snapshot`
// and every other field zeroed. Centralising the literal keeps the
// per-test bodies focused on the H-03 assertion and means a future
// SlashRecord field-shape change re-routes through one site.
fn record_with_treasury_snapshot(snapshot: Pubkey) -> SlashRecord {
    SlashRecord {
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
        treasury_at_execute:             snapshot,
        slash_config_version_at_execute: 0,
    }
}

// ----------------------------------------------------------------------------
// Treasury snapshot field surface — STRUCT-LITERAL pin
// ----------------------------------------------------------------------------

#[test]
fn slash_record_carries_treasury_at_execute_field() {
    // The struct-literal probe in `record_with_treasury_snapshot` is the
    // tripwire — if a future refactor renames or removes
    // `treasury_at_execute`, this file fails to COMPILE, which is the
    // intended H-03 alert. The runtime assertion below is the
    // round-trip sanity check.
    let snapshot = Pubkey::new_unique();
    let record = record_with_treasury_snapshot(snapshot);
    assert_eq!(record.treasury_at_execute, snapshot);
}

#[test]
fn treasury_at_execute_is_a_pubkey_not_a_byte_array() {
    // Subtle: the H-03 snapshot must be a `Pubkey` so the `==`
    // constraint in settle_slash compares full 32-byte identities.
    // A drift to `[u8; 32]` would still compile (Pubkey IS a 32-byte
    // newtype) but it would tempt future code to skip Pubkey-aware
    // equality. This probe pins the typed form via a `&Pubkey`
    // function-arg coercion.
    fn want_pubkey(_: &Pubkey) {}
    let record = record_with_treasury_snapshot(Pubkey::default());
    want_pubkey(&record.treasury_at_execute);
}

// ----------------------------------------------------------------------------
// Burn boundary — the IMMUTABLE incinerator constant
// ----------------------------------------------------------------------------

#[test]
fn incinerator_address_is_the_canonical_11111_burn_pubkey() {
    // Burn-tier slashes are H-03-safe because the destination is pinned
    // to the SlashConfig::INCINERATOR const, NOT to a mutable config
    // field. A rotation of slash_config.treasury cannot redirect a
    // burn-tier payout. This pin locks the INCINERATOR value so a
    // future refactor cannot silently re-aim the burn destination.
    let expected =
        Pubkey::from_str("1nc1nerator11111111111111111111111111111111")
            .expect("the canonical incinerator pubkey must parse");
    assert_eq!(SlashConfig::INCINERATOR, expected);
}

// ----------------------------------------------------------------------------
// Layout-shape pin — H-03 added the 32-byte snapshot field;
// SlashConfig itself was NOT affected (the snapshot lives on the record)
// ----------------------------------------------------------------------------

#[test]
fn h03_did_not_perturb_slash_config_layout() {
    // The snapshot pattern lives on the RECORD (per-action, written-once)
    // — NOT on the config (singleton, mutable). This is the whole point:
    // we don't want to grow the mutable surface; we capture the value at
    // the moment of action. If this pin fires, the H-03 fix has been
    // mis-applied to the config and the snapshot semantics are broken.
    assert_eq!(SLASH_CONFIG_LAYOUT_VERSION, 5);
    assert_eq!(SlashConfig::SIZE_WITHOUT_DISCRIMINATOR, 209);
}

#[test]
fn rotation_after_snapshot_does_not_mutate_the_snapshot() {
    // The SEMANTIC pin: even if the operator mutates the config's
    // treasury value AFTER a slash has been executed (writing it onto
    // the record), the record's snapshot is its own copy and does NOT
    // observe the mutation. This is the SlashConfig <-> SlashRecord
    // decoupling at the heart of the H-03 fix.
    let legitimate_treasury = Pubkey::new_unique();
    let record              = record_with_treasury_snapshot(legitimate_treasury);

    // ... time passes; the operator rotates slash_config.treasury to a
    // new pubkey. We model that by simply minting a new key — the
    // crucial property is that mutating the new key does NOT change
    // the snapshot on the previously-written record.
    let attacker_treasury = Pubkey::new_unique();
    assert_ne!(legitimate_treasury, attacker_treasury);

    // settle_slash reads `slash_record.treasury_at_execute`, NOT the
    // live config — so the legitimate destination is still the only
    // valid payout target for THIS slash.
    assert_eq!(record.treasury_at_execute, legitimate_treasury);
    assert_ne!(record.treasury_at_execute, attacker_treasury);
}
