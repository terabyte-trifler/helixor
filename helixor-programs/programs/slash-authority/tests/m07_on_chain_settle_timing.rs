// =============================================================================
// programs/slash-authority/tests/m07_on_chain_settle_timing.rs
//
// M-07 — pin the SlashConfig timing surface that the audit asked for.
//
// Pre-M-07 the 48h execute->settle floor and the 1h post-appeal-window
// grace were `pub const` in `settle_slash.rs`. Tuning them required a
// program redeploy. M-07 moved them onto `SlashConfig` as i64 fields
// carved from the existing `_reserved` cushion, exposed `effective_*`
// accessors with documented fallbacks, added hard on-chain bounds, and
// shipped a new `update_settle_timing` admin-gated ix that goes through
// `validate_settle_timing_seconds`.
//
// This file pins the cryptographic / structural invariants of that
// surface so a future refactor cannot silently:
//   * change `SLASH_CONFIG_LAYOUT_VERSION` without bumping the doc gate,
//   * grow the account past the historical 209-byte size cap,
//   * weaken the on-chain bounds (an attacker-friendly 1-second floor
//     would be a defence-in-depth regression),
//   * break the pre-M-07 "zero field = use the default" backward-compat,
//   * renumber the `SettleTimingOutOfBounds` error code (the off-chain
//     monitor + the TS SDK switch on the literal code).
//
// Runtime gating (admin signer, no-op rejection, event emission) is
// exercised by the TypeScript integration tests.
// =============================================================================

use slash_authority::errors::SlashError;
use slash_authority::state::{
    validate_settle_timing_seconds, SettleTimingBoundsError, SlashConfig,
    DEFAULT_EXECUTE_TO_SETTLE_SECONDS, DEFAULT_SETTLE_GRACE_SECONDS,
    MAX_EXECUTE_TO_SETTLE_BOUND, MAX_SETTLE_GRACE_BOUND,
    MIN_EXECUTE_TO_SETTLE_BOUND, MIN_SETTLE_GRACE_BOUND,
    SLASH_CONFIG_LAYOUT_VERSION,
};

// -----------------------------------------------------------------------------
// Layout pins
// -----------------------------------------------------------------------------

#[test]
fn slash_config_size_unchanged_after_m07_carve() {
    // M-07 carved 16 bytes of `_reserved` into two i64 fields without
    // growing the account. The original byte budget — 209 without the
    // discriminator, 217 with — must hold so already-deployed accounts
    // remain byte-compatible.
    assert_eq!(SlashConfig::SIZE_WITHOUT_DISCRIMINATOR, 209);
    assert_eq!(SlashConfig::SPACE, 8 + 209);
}

#[test]
fn slash_config_layout_version_is_v4() {
    // v3 → v4 documents the M-07 carve. A refactor that touches the
    // shape MUST bump this too.
    assert_eq!(SLASH_CONFIG_LAYOUT_VERSION, 4);
}

// -----------------------------------------------------------------------------
// Default pins
// -----------------------------------------------------------------------------

#[test]
fn defaults_match_pre_m07_constants() {
    // M-07 is mobility, not a re-tune. The on-chain defaults must
    // exactly match the pre-M-07 hard-coded values, or else any
    // pre-M-07 account whose _reserved bytes were zero would surprise
    // its operators with new timing on first read.
    assert_eq!(DEFAULT_EXECUTE_TO_SETTLE_SECONDS, 48 * 3_600);
    assert_eq!(DEFAULT_SETTLE_GRACE_SECONDS, 60 * 60);
}

#[test]
fn defaults_lie_strictly_inside_bounds() {
    // SANITY: the documented defaults must themselves be acceptable
    // values — otherwise `update_settle_timing` couldn't write the
    // defaults back, and `initialize_config` (which seeds them) would
    // produce an account that fails its own validator.
    assert!(DEFAULT_EXECUTE_TO_SETTLE_SECONDS >= MIN_EXECUTE_TO_SETTLE_BOUND);
    assert!(DEFAULT_EXECUTE_TO_SETTLE_SECONDS <= MAX_EXECUTE_TO_SETTLE_BOUND);
    assert!(DEFAULT_SETTLE_GRACE_SECONDS >= MIN_SETTLE_GRACE_BOUND);
    assert!(DEFAULT_SETTLE_GRACE_SECONDS <= MAX_SETTLE_GRACE_BOUND);
}

// -----------------------------------------------------------------------------
// Bound pins — the audit's protection against a hostile admin
// -----------------------------------------------------------------------------

#[test]
fn bounds_are_pinned() {
    // Bumping any of these silently is a defence-in-depth regression.
    // The audit explicitly chose:
    //   floor: 12h..7d  — long enough to react, short enough to ship
    //   grace: 5m..24h  — long enough to cover an MEV-raced appeal,
    //                     short enough to not look like a freeze
    assert_eq!(MIN_EXECUTE_TO_SETTLE_BOUND, 12 * 3_600);
    assert_eq!(MAX_EXECUTE_TO_SETTLE_BOUND, 7 * 24 * 3_600);
    assert_eq!(MIN_SETTLE_GRACE_BOUND, 5 * 60);
    assert_eq!(MAX_SETTLE_GRACE_BOUND, 24 * 3_600);
}

#[test]
fn validator_accepts_canonical_defaults() {
    assert!(validate_settle_timing_seconds(
        DEFAULT_EXECUTE_TO_SETTLE_SECONDS,
        DEFAULT_SETTLE_GRACE_SECONDS,
    )
    .is_ok());
}

#[test]
fn validator_accepts_both_bound_edges() {
    // The bounds are CLOSED intervals — the floor and ceiling values
    // are valid. Verify at all four edges separately so a one-sided
    // off-by-one (e.g. `>` vs `>=`) shows up.
    assert!(validate_settle_timing_seconds(
        MIN_EXECUTE_TO_SETTLE_BOUND,
        MIN_SETTLE_GRACE_BOUND,
    )
    .is_ok());
    assert!(validate_settle_timing_seconds(
        MAX_EXECUTE_TO_SETTLE_BOUND,
        MAX_SETTLE_GRACE_BOUND,
    )
    .is_ok());
}

#[test]
fn validator_rejects_floor_below_minimum() {
    let err = validate_settle_timing_seconds(
        MIN_EXECUTE_TO_SETTLE_BOUND - 1,
        DEFAULT_SETTLE_GRACE_SECONDS,
    )
    .expect_err("floor 1s below MIN must be rejected");
    assert_eq!(err, SettleTimingBoundsError::ExecuteToSettleOutOfBounds);
}

#[test]
fn validator_rejects_floor_above_maximum() {
    let err = validate_settle_timing_seconds(
        MAX_EXECUTE_TO_SETTLE_BOUND + 1,
        DEFAULT_SETTLE_GRACE_SECONDS,
    )
    .expect_err("floor 1s above MAX must be rejected");
    assert_eq!(err, SettleTimingBoundsError::ExecuteToSettleOutOfBounds);
}

#[test]
fn validator_rejects_grace_below_minimum() {
    let err = validate_settle_timing_seconds(
        DEFAULT_EXECUTE_TO_SETTLE_SECONDS,
        MIN_SETTLE_GRACE_BOUND - 1,
    )
    .expect_err("grace 1s below MIN must be rejected");
    assert_eq!(err, SettleTimingBoundsError::SettleGraceOutOfBounds);
}

#[test]
fn validator_rejects_grace_above_maximum() {
    let err = validate_settle_timing_seconds(
        DEFAULT_EXECUTE_TO_SETTLE_SECONDS,
        MAX_SETTLE_GRACE_BOUND + 1,
    )
    .expect_err("grace 1s above MAX must be rejected");
    assert_eq!(err, SettleTimingBoundsError::SettleGraceOutOfBounds);
}

#[test]
fn validator_rejects_zero() {
    // The zero sentinel is reserved for "use the default" at READ
    // time (via `effective_*`). It must not be a WRITEable value —
    // an admin who genuinely wants the defaults writes the explicit
    // default constants.
    let err = validate_settle_timing_seconds(
        0,
        DEFAULT_SETTLE_GRACE_SECONDS,
    )
    .expect_err("zero floor must be rejected");
    assert_eq!(err, SettleTimingBoundsError::ExecuteToSettleOutOfBounds);

    let err = validate_settle_timing_seconds(
        DEFAULT_EXECUTE_TO_SETTLE_SECONDS,
        0,
    )
    .expect_err("zero grace must be rejected");
    assert_eq!(err, SettleTimingBoundsError::SettleGraceOutOfBounds);
}

#[test]
fn validator_rejects_negative() {
    // Negative seconds are nonsensical against a unix timestamp. The
    // bound check catches them implicitly (any i64 < MIN_* fails) —
    // pin that here so a refactor that switches to u64 cannot weaken
    // the guarantee.
    let err = validate_settle_timing_seconds(
        -1,
        DEFAULT_SETTLE_GRACE_SECONDS,
    )
    .expect_err("negative floor must be rejected");
    assert_eq!(err, SettleTimingBoundsError::ExecuteToSettleOutOfBounds);
}

// -----------------------------------------------------------------------------
// effective_* fallback pins — pre-M-07 backward-compat
// -----------------------------------------------------------------------------

#[test]
fn effective_falls_back_to_default_when_field_is_zero() {
    // A pre-M-07 account has 22 bytes of `_reserved` zero. Post-M-07,
    // 16 of those bytes are reinterpreted as two i64 fields and
    // continue to read as 0. The `effective_*` accessors MUST treat
    // that as "use the documented default" — otherwise pre-M-07
    // accounts would suddenly pass the timing gates trivially (now >=
    // executed_at + 0 is always true).
    let cfg = SlashConfig {
        execute_to_settle_seconds: 0,
        settle_grace_seconds:      0,
        ..SlashConfig::default()
    };
    assert_eq!(
        cfg.effective_execute_to_settle_seconds(),
        DEFAULT_EXECUTE_TO_SETTLE_SECONDS,
    );
    assert_eq!(
        cfg.effective_settle_grace_seconds(),
        DEFAULT_SETTLE_GRACE_SECONDS,
    );
}

#[test]
fn effective_falls_back_when_field_is_negative() {
    // A negative i64 in storage can only arise from a refactor bug —
    // the writer-side validator forbids it. But the read path MUST
    // remain safe; falling back is the defence.
    let cfg = SlashConfig {
        execute_to_settle_seconds: -1,
        settle_grace_seconds:      -42,
        ..SlashConfig::default()
    };
    assert_eq!(
        cfg.effective_execute_to_settle_seconds(),
        DEFAULT_EXECUTE_TO_SETTLE_SECONDS,
    );
    assert_eq!(
        cfg.effective_settle_grace_seconds(),
        DEFAULT_SETTLE_GRACE_SECONDS,
    );
}

#[test]
fn effective_uses_field_when_field_is_positive() {
    // Post-M-07 retune: the admin wrote 24h floor + 2h grace. The
    // effective values are exactly what's in storage — no fallback.
    let cfg = SlashConfig {
        execute_to_settle_seconds: 24 * 3_600,
        settle_grace_seconds:      2 * 3_600,
        ..SlashConfig::default()
    };
    assert_eq!(cfg.effective_execute_to_settle_seconds(), 24 * 3_600);
    assert_eq!(cfg.effective_settle_grace_seconds(),      2  * 3_600);
}

// -----------------------------------------------------------------------------
// Error code pins
// -----------------------------------------------------------------------------

#[test]
fn settle_timing_out_of_bounds_code_is_stable() {
    // The off-chain monitor + TS SDK switch on the literal code. The
    // M-07 code slots into the VULN-08 family at 6072 (after 6070, 6071).
    assert_eq!(SlashError::SettleTimingOutOfBounds as u32, 6072);
}
