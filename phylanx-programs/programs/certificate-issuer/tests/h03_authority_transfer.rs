// =============================================================================
// programs/certificate-issuer/tests/h03_authority_transfer.rs
//
// H-3 — two-step, time-locked transfer of the IssuerConfig admin authority.
//
// THE AUDIT FINDING
// -----------------
// `issuer_config.authority` was written once by `initialize_config` and there
// was NO instruction to change it. A single compromised admin key had
// irrevocable control of cluster rotation (enabling H-2) with no on-chain
// remedy; a LOST key meant cluster keys could never be rotated again.
//
// THE FIX
// -------
// Ownable2Step + a 48h timelock: the current authority PROPOSES a successor
// (recorded as `pending_authority` with `eta = now + 48h`); the successor
// ACCEPTS after the timelock (proving key possession); the current authority
// may CANCEL during the window.
//
// WHAT THIS FILE PINS (runtime-free)
// ----------------------------------
// The on-chain handler logic (signer gates, timelock comparison, atomic swap)
// is exercised by the TypeScript / on-chain smoke path. These tests pin the
// state-level invariants the handlers depend on: the timelock constant, the
// pending-transfer predicate, and the genesis (no-pending) default — plus the
// SPACE growth that reserves room for the two new fields.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use certificate_issuer::state::IssuerConfig;

#[test]
fn authority_transfer_timelock_is_48h() {
    assert_eq!(
        IssuerConfig::AUTHORITY_TRANSFER_TIMELOCK_SECONDS,
        48 * 60 * 60,
    );
}

#[test]
fn space_reserves_room_for_the_two_h3_fields() {
    // 32 (pending_authority) + 8 (authority_transfer_eta) over the
    // post-M-05 / pre-H-3 baseline of 439; H-5 later appends 14 bytes
    // (cluster_key_domains: 4 Vec prefix + 2*5 domain slots), 479 -> 493.
    assert_eq!(IssuerConfig::SPACE, 439 + 32 + 8 + 14);
    assert_eq!(IssuerConfig::SPACE, 493);
}

#[test]
fn default_config_has_no_pending_transfer() {
    // A freshly-initialised config (all fields default) has no pending
    // transfer — `initialize_config` sets pending_authority to the zero
    // pubkey, the sentinel the predicate keys off.
    let cfg = IssuerConfig::default();
    assert!(!cfg.has_pending_authority_transfer());
    assert_eq!(cfg.pending_authority, Pubkey::default());
    assert_eq!(cfg.authority_transfer_eta, 0);
}

#[test]
fn pending_predicate_flips_with_a_nonzero_pending_authority() {
    let mut cfg = IssuerConfig::default();
    assert!(!cfg.has_pending_authority_transfer());

    // Propose: a non-default successor is recorded.
    cfg.pending_authority = Pubkey::new_unique();
    assert!(cfg.has_pending_authority_transfer());

    // Accept / cancel: clearing the slot returns to "no pending".
    cfg.pending_authority = Pubkey::default();
    assert!(!cfg.has_pending_authority_transfer());
}
