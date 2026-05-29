// =============================================================================
// programs/health-oracle/tests/m04_secondary_slot_gate.rs
//
// Pure unit tests pinning the M-04 fix: a SECONDARY oracle-side
// SlotHashes verification on `submit_score`, independent of the
// certificate-issuer's primary AW-01-EXT check.
//
// THE BUG
// -------
// `submit_score` forwards `(slot_anchor_slot, slot_anchor_hash)` verbatim
// to the certificate-issuer CPI. The cert-issuer side calls
// `verify_slot_anchor` against the SlotHashes sysvar — that is the
// PRIMARY gate. The oracle side did not verify the anchor itself, so a
// future refactor that swapped the cert-write path (or a regression in
// the cert-issuer check) could let an un-anchored score reach the
// certificate without the SlotHashes invariant ever being enforced. The
// audit flagged the missing secondary gate.
//
// THE FIX
// -------
// `slot_gate::verify_slot_anchor` is a clone of the cert-issuer's logic
// with HelixorError attribution. `submit_score` calls it BEFORE the CPI.
// Two independent implementations of the same SlotHashes invariant.
//
// These tests pin the public surface a caller relies on:
//   - the four typed errors (codes 6090..=6093),
//   - the zero-hash sentinel constant,
//   - acceptance of a matching anchor,
//   - rejection of each failure mode with the correct error.
//
// Runtime behaviour of the `submit_score` handler itself (CPI plumbing,
// epoch checks, event emission) is exercised by the TypeScript
// integration suite; this file pins ONLY the pure helper that backs the
// new on-chain gate.
// =============================================================================

use anchor_lang::error::Error as AnchorError;
use anchor_lang::prelude::*;
use health_oracle::errors::HelixorError;
use health_oracle::slot_gate::{verify_slot_anchor, ZERO_SLOT_ANCHOR_HASH};
use solana_program::pubkey::Pubkey;
use solana_program::sysvar::slot_hashes::ID as SLOT_HASHES_ID;
use std::cell::RefCell;
use std::rc::Rc;

// ----------------------------------------------------------------------------
// Error-code stability pins
// ----------------------------------------------------------------------------

#[test]
fn wrong_slot_hashes_sysvar_error_code_pinned() {
    // 6090 — distinct from VULN-13 (6060..=6068), AW-02 (6070..=6074),
    // and AW-03 (6080..=6084). M-04 reserves 6090..=6093.
    assert_eq!(HelixorError::WrongSlotHashesSysvar as u32, 6090);
}

#[test]
fn missing_slot_anchor_error_code_pinned() {
    assert_eq!(HelixorError::MissingSlotAnchor as u32, 6091);
}

#[test]
fn slot_anchor_too_old_error_code_pinned() {
    assert_eq!(HelixorError::SlotAnchorTooOld as u32, 6092);
}

#[test]
fn slot_anchor_hash_mismatch_error_code_pinned() {
    assert_eq!(HelixorError::SlotAnchorHashMismatch as u32, 6093);
}

#[test]
fn zero_slot_anchor_hash_sentinel_is_all_zeros() {
    // The sentinel is the documented "no slot anchor available" marker
    // from the off-chain submitter. Pinned so a future refactor cannot
    // silently change the sentinel value (which would let an un-anchored
    // score sneak through the missing-anchor gate).
    assert_eq!(ZERO_SLOT_ANCHOR_HASH, [0u8; 32]);
}

// ----------------------------------------------------------------------------
// Sysvar fixture
// ----------------------------------------------------------------------------

const LEN_PREFIX_BYTES: usize = 8;
const ENTRY_BYTES: usize = 8 + 32;

/// Build a synthetic SlotHashes sysvar buffer. Entries are written in the
/// order supplied — real SlotHashes are newest-first, but the verifier
/// linear-scans and matches by exact slot, so ordering does not affect
/// the pin semantics, only fixture realism.
fn make_sysvar(entries: &[(u64, [u8; 32])]) -> (Pubkey, Vec<u8>) {
    let mut data = Vec::with_capacity(
        LEN_PREFIX_BYTES + entries.len() * ENTRY_BYTES,
    );
    data.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (slot, hash) in entries {
        data.extend_from_slice(&slot.to_le_bytes());
        data.extend_from_slice(hash);
    }
    (SLOT_HASHES_ID, data)
}

fn with_account_info<R>(
    key: Pubkey,
    data: &mut Vec<u8>,
    f: impl FnOnce(&AccountInfo) -> R,
) -> R {
    let mut lamports: u64 = 0;
    let owner = Pubkey::default();
    let info = AccountInfo {
        key: &key,
        is_signer: false,
        is_writable: false,
        lamports: Rc::new(RefCell::new(&mut lamports)),
        data: Rc::new(RefCell::new(data.as_mut_slice())),
        owner: &owner,
        executable: false,
        _unused: 0,
    };
    f(&info)
}

fn anchor_code(err: &AnchorError) -> Option<u32> {
    match err {
        AnchorError::AnchorError(boxed) => Some(boxed.error_code_number),
        _ => None,
    }
}

fn err_matches(err: AnchorError, code: HelixorError) -> bool {
    let expected: AnchorError = code.into();
    anchor_code(&err) == anchor_code(&expected)
}

// ----------------------------------------------------------------------------
// Happy path
// ----------------------------------------------------------------------------

/// The canonical accept path: cluster pins a slot present in the sysvar,
/// with the exact hash the cluster captured. `submit_score` forwards
/// these to the gate, which must accept.
#[test]
fn matching_anchor_is_accepted() {
    let hash = [7u8; 32];
    let (key, mut data) = make_sysvar(&[
        (100, [9u8; 32]),
        (99,  hash),
        (98,  [11u8; 32]),
    ]);
    with_account_info(key, &mut data, |info| {
        verify_slot_anchor(info, 99, &hash).unwrap();
    });
}

// ----------------------------------------------------------------------------
// Failure modes — each pinned with a dedicated error
// ----------------------------------------------------------------------------

/// The zero-hash sentinel must short-circuit BEFORE the sysvar layout
/// walk — otherwise a misconfigured submitter could pass (slot=0, hash=0)
/// and trip on the SlotAnchorTooOld branch instead.
#[test]
fn zero_anchor_hash_rejected_as_missing() {
    let (key, mut data) = make_sysvar(&[(1, [0u8; 32])]);
    with_account_info(key, &mut data, |info| {
        let err = verify_slot_anchor(info, 1, &ZERO_SLOT_ANCHOR_HASH).unwrap_err();
        assert!(err_matches(err, HelixorError::MissingSlotAnchor));
    });
}

/// An account that is NOT the canonical SlotHashes sysvar must be
/// rejected before any data is parsed. Defends against a caller passing
/// a fake sysvar account with cherry-picked entries.
#[test]
fn foreign_account_rejected_as_wrong_sysvar() {
    let foreign = Pubkey::new_unique();
    let mut data = vec![0u8; LEN_PREFIX_BYTES];
    with_account_info(foreign, &mut data, |info| {
        let err = verify_slot_anchor(info, 1, &[1u8; 32]).unwrap_err();
        assert!(err_matches(err, HelixorError::WrongSlotHashesSysvar));
    });
}

/// A slot that exists in the sysvar but with a DIFFERENT hash than the
/// cluster supplied is the classic forged-anchor case. Must surface the
/// distinct `SlotAnchorHashMismatch` (not SlotAnchorTooOld), so the
/// monitor can distinguish "cluster lied about the hash" from "cluster
/// pinned a slot the sysvar has rolled past".
#[test]
fn slot_present_but_hash_wrong_rejected_as_hash_mismatch() {
    let (key, mut data) = make_sysvar(&[
        (100, [9u8; 32]),
        (99,  [1u8; 32]),
    ]);
    with_account_info(key, &mut data, |info| {
        let err = verify_slot_anchor(info, 99, &[2u8; 32]).unwrap_err();
        assert!(err_matches(err, HelixorError::SlotAnchorHashMismatch));
    });
}

/// A slot below the sysvar window — the cluster pinned an anchor older
/// than ~3.4 minutes — must surface `SlotAnchorTooOld` so the operator
/// re-pins with a fresher slot.
#[test]
fn slot_below_window_rejected_as_too_old() {
    let (key, mut data) = make_sysvar(&[
        (200, [9u8; 32]),
        (199, [10u8; 32]),
    ]);
    with_account_info(key, &mut data, |info| {
        let err = verify_slot_anchor(info, 150, &[9u8; 32]).unwrap_err();
        assert!(err_matches(err, HelixorError::SlotAnchorTooOld));
    });
}

/// A slot AHEAD of the cluster's known tip — e.g. the cluster fabricated
/// a future slot — is also unverifiable and collapses to
/// `SlotAnchorTooOld`. Pinned separately so a future change that splits
/// "future" off into its own error surfaces deliberately.
#[test]
fn slot_above_window_also_rejected_as_too_old() {
    let (key, mut data) = make_sysvar(&[
        (100, [9u8; 32]),
        (99,  [10u8; 32]),
    ]);
    with_account_info(key, &mut data, |info| {
        let err = verify_slot_anchor(info, 9_999, &[9u8; 32]).unwrap_err();
        assert!(err_matches(err, HelixorError::SlotAnchorTooOld));
    });
}

/// An empty sysvar buffer (count == 0) cannot satisfy any anchor — pinned
/// so an off-by-one in the bounds check (e.g. iterating one past end of
/// data) surfaces here instead of silently accepting.
#[test]
fn empty_sysvar_rejects_any_nonzero_anchor_as_too_old() {
    let (key, mut data) = make_sysvar(&[]);
    with_account_info(key, &mut data, |info| {
        let err = verify_slot_anchor(info, 42, &[1u8; 32]).unwrap_err();
        assert!(err_matches(err, HelixorError::SlotAnchorTooOld));
    });
}

/// Order-independence: the verifier matches by exact slot, not position.
/// The cert-issuer test fixture used newest-first; this one writes
/// oldest-first to pin that the linear scan finds the entry regardless.
#[test]
fn match_is_order_independent() {
    let hash = [42u8; 32];
    let (key, mut data) = make_sysvar(&[
        (50, [1u8; 32]),
        (51, [2u8; 32]),
        (52, hash),
    ]);
    with_account_info(key, &mut data, |info| {
        verify_slot_anchor(info, 52, &hash).unwrap();
    });
}
