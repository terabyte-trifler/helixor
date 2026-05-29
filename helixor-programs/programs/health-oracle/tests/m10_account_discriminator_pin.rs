// =============================================================================
// programs/health-oracle/tests/m10_account_discriminator_pin.rs
//
// M-10 — pin every health-oracle `#[account]` discriminator so a schema
// refactor cannot silently break account deserialization on already-
// deployed PDAs.
//
// THE CONCERN
// -----------
// Anchor's `#[account]` macro autoderives an 8-byte discriminator from
// `sha256("account:<TypeName>")[..8]`. That discriminator is the FIRST
// 8 bytes of every account's data, and `try_deserialize` refuses to
// load an account whose first 8 bytes don't match the expected value.
//
// This is a robust invariant -- but it is also brittle to four common
// changes a future contributor might make without realising the impact:
//
//   1. RENAME: `OracleConfig` -> `Config`. The autoderived discriminator
//      changes; every already-deployed `OracleConfig` PDA stops being
//      loadable. Anchor flags this at deserialize time, but only at the
//      cost of every instruction that touches the type returning
//      `AccountDiscriminatorMismatch` on chain -- a stealth migration
//      hazard the integration tests would only catch if they happened
//      to exercise that exact PDA on the exact build.
//
//   2. ADD A COLLIDING TYPE: a brand-new account whose name happens to
//      hash to the same first 8 bytes as an existing type. Vanishingly
//      improbable for short names, but the bytes ARE the on-chain
//      ABI -- and "improbable" is not the audit standard for a money-
//      handling protocol. Without this file, the collision would land
//      silently and only surface as cross-type deserialization mishits
//      under production load.
//
//   3. ADD AN UN-NAMESPACED `#[account(...)]`: same effect as a rename
//      if the new namespace string changes from "account" to something
//      else. The Anchor macro accepts a `namespace` arg; a refactor
//      that switches it silently re-keys every discriminator. This pin
//      fails loudly on that, too.
//
//   4. SCHEMA DRIFT WITHOUT NAME CHANGE: a contributor changes the
//      internal field layout but keeps the name. The discriminator
//      stays the same, BUT pre-refactor PDAs now deserialize under
//      the new field order. This file does NOT catch that -- our
//      per-account `CURRENT_LAYOUT_VERSION` constants (asserted in
//      the per-feature test files) carry that contract. The note is
//      here so a future contributor knows where each invariant lives.
//
// THE FIX
// -------
// Hardcode every health-oracle account's CURRENT discriminator bytes.
// The pin test asserts the bytes are exactly the autoderived value at
// the time the file was authored. Pair it with a pairwise-distinct
// check so future additions to the account zoo cannot silently collide.
// A rename / namespace change / collision now fails THIS file rather
// than every integration test on mainnet.
//
// THE CONTRACT FOR FUTURE CONTRIBUTORS
// ------------------------------------
// If you rename an account, add a new account, or change the
// `#[account(...)]` namespace, you MUST:
//   (a) update the per-account pin below to the new autoderived value,
//   (b) write a one-shot migration handler that reads the OLD
//       discriminator + bytes and writes the NEW discriminator + bytes,
//       OR explicitly decide that no migration is needed (e.g. you are
//       adding a fresh type with no pre-existing PDAs).
// Failing to do either is the M-10 hazard.
// =============================================================================

use anchor_lang::Discriminator;
use health_oracle::state::{
    AgentRegistration, BaselineDataAccount, EpochState, OracleConfig,
    PendingOracleRotation,
};

// -----------------------------------------------------------------------------
// Per-account pins
//
// Each constant is the result of `sha256("account:<TypeName>")[..8]` at
// the time of authoring. Recompute via:
//   python3 -c 'import hashlib; print(list(hashlib.sha256(b"account:OracleConfig").digest()[:8]))'
// -----------------------------------------------------------------------------

#[test]
fn oracle_config_discriminator_pinned() {
    // sha256("account:OracleConfig")[..8]
    assert_eq!(
        OracleConfig::DISCRIMINATOR,
        &[133, 196, 152, 50, 27, 21, 145, 254],
    );
}

#[test]
fn agent_registration_discriminator_pinned() {
    // sha256("account:AgentRegistration")[..8]
    assert_eq!(
        AgentRegistration::DISCRIMINATOR,
        &[130, 53, 100, 103, 121, 77, 148, 19],
    );
}

#[test]
fn baseline_data_account_discriminator_pinned() {
    // sha256("account:BaselineDataAccount")[..8]
    assert_eq!(
        BaselineDataAccount::DISCRIMINATOR,
        &[152, 18, 125, 17, 172, 222, 208, 71],
    );
}

#[test]
fn epoch_state_discriminator_pinned() {
    // sha256("account:EpochState")[..8]
    assert_eq!(
        EpochState::DISCRIMINATOR,
        &[191, 63, 139, 237, 144, 12, 223, 210],
    );
}

#[test]
fn pending_oracle_rotation_discriminator_pinned() {
    // sha256("account:PendingOracleRotation")[..8]
    assert_eq!(
        PendingOracleRotation::DISCRIMINATOR,
        &[208, 235, 123, 121, 6, 166, 12, 211],
    );
}

// -----------------------------------------------------------------------------
// Length pin
//
// Anchor's account discriminator is exactly 8 bytes. The Discriminator
// trait surface allows for arbitrary lengths via `&'static [u8]`, but
// the on-chain account header reserves 8 bytes. A future Anchor upgrade
// (or an `#[account(discriminator = ...)]` override) that changes the
// length silently breaks every existing PDA. Pin the invariant.
// -----------------------------------------------------------------------------

#[test]
fn every_health_oracle_discriminator_is_eight_bytes() {
    assert_eq!(OracleConfig::DISCRIMINATOR.len(), 8);
    assert_eq!(AgentRegistration::DISCRIMINATOR.len(), 8);
    assert_eq!(BaselineDataAccount::DISCRIMINATOR.len(), 8);
    assert_eq!(EpochState::DISCRIMINATOR.len(), 8);
    assert_eq!(PendingOracleRotation::DISCRIMINATOR.len(), 8);
}

// -----------------------------------------------------------------------------
// Pairwise-distinct pin
//
// The cryptographic argument that two random 8-byte hashes will not
// collide is overwhelming, BUT:
//   * the input to the hash is operator-controlled (the type NAME),
//     so an adversarial or careless contributor could pick a name
//     whose first 8 bytes collide with an existing one;
//   * the on-chain ABI surface is small (5 accounts today) and the
//     check is O(n^2) at compile time -- the cost is nothing, the
//     benefit is a hard guard against a class of silent-corruption
//     bug.
//
// If a new `#[account]` type is added to health-oracle, append it to
// the list below.
// -----------------------------------------------------------------------------

#[test]
fn no_two_health_oracle_accounts_share_a_discriminator() {
    let all: &[(&str, &[u8])] = &[
        ("OracleConfig",          OracleConfig::DISCRIMINATOR),
        ("AgentRegistration",     AgentRegistration::DISCRIMINATOR),
        ("BaselineDataAccount",   BaselineDataAccount::DISCRIMINATOR),
        ("EpochState",            EpochState::DISCRIMINATOR),
        ("PendingOracleRotation", PendingOracleRotation::DISCRIMINATOR),
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(
                all[i].1, all[j].1,
                "discriminator collision between {} and {}: both = {:?}",
                all[i].0, all[j].0, all[i].1,
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Cross-type misload sanity
//
// The on-chain effect of a discriminator collision OR a silent rename
// is that `try_deserialize` may load the wrong type. We can't exercise
// the full failure runtime here (no validator), but we CAN assert the
// boring property the runtime relies on: each pinned discriminator,
// taken as a literal byte slice, is not equal to any OTHER pinned
// discriminator. This is what the runtime checks at deserialize time
// and exactly the property we want to be loud about.
// -----------------------------------------------------------------------------

#[test]
fn raw_discriminator_bytes_match_the_pinned_constants() {
    // Tautological-looking but worth keeping: this test is the canary
    // that the `#[account]` macro is still producing the SAME bytes as
    // when the file was authored. If a future Anchor upgrade changes
    // how the macro derives the discriminator (e.g. switches from
    // sha256 to a different hash), the per-account pins above would
    // fail -- but a contributor reading this single test gets the
    // canonical explanation of what to recompute, all in one place.
    let pinned: &[(&[u8], [u8; 8])] = &[
        (OracleConfig::DISCRIMINATOR,
            [133, 196, 152, 50, 27, 21, 145, 254]),
        (AgentRegistration::DISCRIMINATOR,
            [130, 53, 100, 103, 121, 77, 148, 19]),
        (BaselineDataAccount::DISCRIMINATOR,
            [152, 18, 125, 17, 172, 222, 208, 71]),
        (EpochState::DISCRIMINATOR,
            [191, 63, 139, 237, 144, 12, 223, 210]),
        (PendingOracleRotation::DISCRIMINATOR,
            [208, 235, 123, 121, 6, 166, 12, 211]),
    ];
    for (actual, expected) in pinned {
        assert_eq!(*actual, expected);
    }
}
