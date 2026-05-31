// =============================================================================
// programs/health-oracle/tests/c01_advance_epoch_2phase.rs
//
// C-01 PIN TESTS — 2-phase commit for advance_epoch.
//
// Background (see also state/epoch_state.rs):
//   The audit C-01 finding flagged a boundary race on advance_epoch — the
//   pre-fix handler verified Tier-1 (or Tier-2 fallback) authority AND
//   mutated `current_epoch` in a single tx, so off-chain monitors only
//   saw the tick AFTER it had landed. There was no observability window
//   to react to a malformed advance.
//
//   C-01 splits the instruction into a propose half (verifies attesters,
//   stages target in `pending_*` fields, emits `EpochAdvanceProposed`) and
//   a finalize half (refuses until FINALIZE_DELAY_SECONDS have elapsed,
//   then commits `current_epoch = pending_target_epoch` and emits the
//   canonical events). A staleness window (`PROPOSE_OVERWRITE_DELAY_SECONDS`)
//   prevents a crashed proposer from deadlocking forward progress.
//
// These tests pin the EpochState-side invariants of the split. The
// on-chain handler tests (Tier-2 finalize cluster gate, etc.) live in the
// production e2e suite — here we lock down the constants, the SPACE
// invariance (no PDA realloc migration), and the pure helpers the
// propose/finalize handlers rely on.
// =============================================================================

use anchor_lang::prelude::Pubkey;

use health_oracle::state::epoch_state::{
    EpochState, FINALIZE_DELAY_SECONDS, PROPOSE_OVERWRITE_DELAY_SECONDS,
};

// ── Constants pins ─────────────────────────────────────────────────────────

/// FINALIZE_DELAY_SECONDS is the C-01 observability budget. 30s ≈ 75
/// Solana slots — long enough for indexers to react, short enough that
/// the legitimate ops loop adds only one extra short wait per 24h tick.
/// A silent drift of this constant downward would collapse the
/// observability window the audit rec bought; a silent drift upward
/// would slow legitimate ticks. Pin it.
#[test]
fn c01_finalize_delay_constant_pin() {
    assert_eq!(
        FINALIZE_DELAY_SECONDS, 30,
        "C-01 FINALIZE_DELAY_SECONDS must stay at 30s — the audited \
         observability budget"
    );
}

/// PROPOSE_OVERWRITE_DELAY_SECONDS is the staleness window. 1 hour.
/// Below this, a stuck pending proposal (e.g. proposer crashed before
/// it could finalize) would deadlock the next tick; above this, a
/// hostile spammer gets a wider blast radius to flap proposals at the
/// boundary. Pin to the audited value.
#[test]
fn c01_propose_overwrite_delay_constant_pin() {
    assert_eq!(
        PROPOSE_OVERWRITE_DELAY_SECONDS,
        60 * 60,
        "C-01 PROPOSE_OVERWRITE_DELAY_SECONDS must stay at 1h"
    );
}

// ── SPACE invariance pin ───────────────────────────────────────────────────

/// EpochState SPACE must NOT grow from C-01. The 18 bytes the four
/// pending fields claim were RECLAIMED from the `_reserved` cushion
/// (32 → 14), keeping the deployed PDA size unchanged so no realloc
/// migration is required. A reviewer that accidentally re-added bytes
/// to `_reserved` or grew another field would force a migration —
/// this test fails loudly first.
#[test]
fn c01_epoch_state_space_unchanged_pin() {
    //   8 (disc)
    // + 8  current_epoch
    // + 8  last_advanced_at
    // + 8  epoch_duration_seconds
    // + 32 advance_authority
    // + 1  bump
    // + 8  pending_target_epoch
    // + 8  pending_proposed_at
    // + 1  pending_attester_count
    // + 1  pending_by_fallback
    // + 14 _reserved
    // ───────
    //   97 bytes
    assert_eq!(
        EpochState::SPACE,
        8 + 8 + 8 + 8 + 32 + 1 + 8 + 8 + 1 + 1 + 14,
        "C-01 must NOT grow EpochState — bytes are carved from _reserved"
    );
    // And specifically: the SPACE value the PRE-C-01 layout used
    // (8 disc + 8 + 8 + 8 + 32 + 1 + 32 reserved = 97). C-01 must equal
    // this exactly.
    assert_eq!(EpochState::SPACE, 97);
}

/// The C-01 18-byte pending bundle (8 + 8 + 1 + 1) must come entirely
/// out of the original 32-byte _reserved cushion. Reserved before:
/// 32. Reserved after: 14. Sum of pending bundle: 18. 32 - 18 = 14.
/// This invariant is what makes the migration-free deploy possible.
#[test]
fn c01_pending_bundle_carved_from_reserved_pin() {
    let pending_size = 8 + 8 + 1 + 1; // target_epoch + proposed_at + attester_count + by_fallback
    let original_reserved = 32usize;
    let new_reserved_expected = original_reserved - pending_size;
    assert_eq!(
        new_reserved_expected, 14,
        "C-01 pending bundle (18B) must carve from _reserved (32B) → 14B"
    );

    // And confirm the field's declared length matches.
    let st = EpochState::default();
    assert_eq!(st._reserved.len(), 14);
}

// ── has_pending_advance() truth table ──────────────────────────────────────

/// Genesis EpochState has no pending advance.
#[test]
fn c01_has_pending_false_at_genesis() {
    let st = EpochState::default();
    assert!(!st.has_pending_advance());
}

/// A non-zero pending_target_epoch means a proposal is in flight, even
/// if the proposed_at is zero (which can only happen via a hand-crafted
/// in-memory state — on chain the propose handler writes both together).
#[test]
fn c01_has_pending_true_when_target_nonzero() {
    let mut st = EpochState::default();
    st.pending_target_epoch = 42;
    assert!(st.has_pending_advance());
}

// ── pending_advance_ready() boundary ───────────────────────────────────────

/// With no pending, the ready predicate returns false regardless of
/// the clock — finalize must refuse with NoPendingAdvance, not with
/// the delay-active error, so this guard matters.
#[test]
fn c01_pending_ready_false_when_no_pending() {
    let st = EpochState::default();
    assert!(!st.pending_advance_ready(i64::MAX));
}

/// Inside the FINALIZE_DELAY window, the predicate refuses.
#[test]
fn c01_pending_ready_false_inside_window() {
    let mut st = EpochState::default();
    st.pending_target_epoch = 2;
    st.pending_proposed_at  = 1_000;

    // 1s before the boundary — must refuse.
    let boundary = 1_000 + FINALIZE_DELAY_SECONDS;
    assert!(!st.pending_advance_ready(boundary - 1));
}

/// At exactly proposed_at + FINALIZE_DELAY_SECONDS the predicate
/// flips true — boundary is inclusive on the ready side so a finalize
/// that lands the same second can succeed.
#[test]
fn c01_pending_ready_true_at_boundary() {
    let mut st = EpochState::default();
    st.pending_target_epoch = 2;
    st.pending_proposed_at  = 1_000;

    let boundary = 1_000 + FINALIZE_DELAY_SECONDS;
    assert!(st.pending_advance_ready(boundary));
    assert!(st.pending_advance_ready(boundary + 1_000));
}

// ── pending_overwrite_allowed() ────────────────────────────────────────────

/// When no proposal is in flight, ANY clock is allowed to propose.
#[test]
fn c01_overwrite_allowed_when_no_pending() {
    let st = EpochState::default();
    assert!(st.pending_overwrite_allowed(0));
    assert!(st.pending_overwrite_allowed(i64::MAX));
}

/// A fresh in-flight proposal blocks overwrite until the full staleness
/// window has elapsed. One second before the boundary the propose
/// handler must refuse to re-stage.
#[test]
fn c01_overwrite_blocked_inside_staleness_window() {
    let mut st = EpochState::default();
    st.pending_target_epoch = 5;
    st.pending_proposed_at  = 10_000;

    let stale_boundary = 10_000 + PROPOSE_OVERWRITE_DELAY_SECONDS;
    assert!(!st.pending_overwrite_allowed(stale_boundary - 1));
}

/// At exactly the staleness boundary, overwrite becomes allowed.
#[test]
fn c01_overwrite_allowed_at_staleness_boundary() {
    let mut st = EpochState::default();
    st.pending_target_epoch = 5;
    st.pending_proposed_at  = 10_000;

    let stale_boundary = 10_000 + PROPOSE_OVERWRITE_DELAY_SECONDS;
    assert!(st.pending_overwrite_allowed(stale_boundary));
    assert!(st.pending_overwrite_allowed(stale_boundary + 7_777));
}

/// The staleness window is STRICTLY LARGER than the finalize delay —
/// otherwise a proposal could be "stale enough to overwrite" before it
/// was even "ready to finalize", which would let proposers race a tick
/// out of existence. The invariant is: finalize_delay < overwrite_delay.
#[test]
fn c01_overwrite_window_strictly_larger_than_finalize_delay() {
    assert!(
        PROPOSE_OVERWRITE_DELAY_SECONDS > FINALIZE_DELAY_SECONDS,
        "staleness window must exceed finalize delay or proposers can \
         race finalize out of the legitimate path"
    );
}

// ── clear_pending_advance() ────────────────────────────────────────────────

/// After finalize commits, every pending field must zero. A surviving
/// pending_target_epoch would re-block the next propose; a surviving
/// pending_proposed_at would skew the next staleness window. Pin to
/// all-zero.
#[test]
fn c01_clear_pending_zeroes_all_four_fields() {
    let mut st = EpochState::default();
    st.pending_target_epoch   = 9;
    st.pending_proposed_at    = 12_345;
    st.pending_attester_count = 4;
    st.pending_by_fallback    = 1;

    assert!(st.has_pending_advance());

    st.clear_pending_advance();

    assert_eq!(st.pending_target_epoch, 0);
    assert_eq!(st.pending_proposed_at, 0);
    assert_eq!(st.pending_attester_count, 0);
    assert_eq!(st.pending_by_fallback, 0);
    assert!(!st.has_pending_advance());
}

/// `clear_pending_advance` must NOT touch the non-pending fields. A
/// careless cleanup that nuked `current_epoch` or `advance_authority`
/// would be catastrophic.
#[test]
fn c01_clear_pending_does_not_touch_committed_state() {
    let auth = Pubkey::new_unique();
    let mut st = EpochState::default();
    st.current_epoch          = 17;
    st.last_advanced_at       = 7_777;
    st.epoch_duration_seconds = 86_400;
    st.advance_authority      = auth;
    st.bump                   = 254;
    st.pending_target_epoch   = 18;
    st.pending_proposed_at    = 9_999;
    st.pending_attester_count = 3;
    st.pending_by_fallback    = 0;

    st.clear_pending_advance();

    assert_eq!(st.current_epoch, 17);
    assert_eq!(st.last_advanced_at, 7_777);
    assert_eq!(st.epoch_duration_seconds, 86_400);
    assert_eq!(st.advance_authority, auth);
    assert_eq!(st.bump, 254);
}

// ── Layout struct-literal pin ──────────────────────────────────────────────

/// The EpochState field surface is the source of truth for what
/// propose/finalize touch. If somebody renames or removes one of the
/// four pending fields (or adds an unaccounted-for new field), this
/// struct literal fails to compile — a CI guard against silent layout
/// drift.
#[test]
fn c01_epoch_state_field_surface_pin() {
    let _st = EpochState {
        current_epoch:          1,
        last_advanced_at:       0,
        epoch_duration_seconds: 86_400,
        advance_authority:      Pubkey::default(),
        bump:                   0,
        pending_target_epoch:   0,
        pending_proposed_at:    0,
        pending_attester_count: 0,
        pending_by_fallback:    0,
        _reserved:              [0u8; 14],
    };
}
