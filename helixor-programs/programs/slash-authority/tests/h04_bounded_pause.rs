// =============================================================================
// programs/slash-authority/tests/h04_bounded_pause.rs
//
// Pure unit tests pinning the H-04 fix: bounded-pause-with-hard-cap on
// the slash kill switch.
//
// The audit flagged the original pause as a HIGH-risk SPOF — a single
// compromised pause_authority could freeze settle/appeal/execute
// indefinitely, locking encumbered collateral. The fix:
//
//   1. pause_settlements takes a `duration_seconds` argument, validated
//      to 1..=MAX_PAUSE_SECONDS (7 days).
//   2. SlashConfig grows a `paused_until` field; the gating predicate
//      becomes `paused && now < paused_until`.
//   3. An expired pause behaves identically to "not paused" without
//      requiring an unpause tx — so a hostile pause_authority must
//      re-pause every 7 days, leaving an observable on-chain trail.
//
// These tests pin the time-window predicate, the hard cap, the layout
// version, and the on-disk size (which must NOT have grown — the new
// field was reclaimed from the existing _reserved bytes).
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::state::{
    SlashConfig, MAX_PAUSE_SECONDS, SLASH_CONFIG_LAYOUT_VERSION,
};

// ----------------------------------------------------------------------------
// Hard cap and layout pinning
// ----------------------------------------------------------------------------

#[test]
fn max_pause_is_seven_days() {
    // The audit hard-caps pause windows at 7 days. Bumping this constant
    // weakens the H-04 mitigation — bump deliberately, not accidentally.
    assert_eq!(MAX_PAUSE_SECONDS, 7 * 24 * 3_600);
}

#[test]
fn layout_version_pins_h04_bump() {
    // H-04 added `paused_until` (v2 -> v3); M-07 then carved the two
    // settle-timing i64 fields from the same `_reserved` cushion
    // (v3 -> v4). Both bumps share this single pin so any subsequent
    // shape change must update it deliberately.
    assert_eq!(SLASH_CONFIG_LAYOUT_VERSION, 4);
}

#[test]
fn layout_size_did_not_grow_for_paused_until() {
    // The new 8-byte `paused_until` was carved out of the pre-existing
    // 30-byte reserve, so the on-disk SlashConfig size is unchanged. If
    // this assertion ever fires the H-04 patch has accidentally
    // increased the account size — a stealth migration risk on a live
    // PDA, and a redeploy hazard for devnet/mainnet.
    assert_eq!(SlashConfig::SIZE_WITHOUT_DISCRIMINATOR, 209);
    assert_eq!(SlashConfig::SPACE, 217);
}

// ----------------------------------------------------------------------------
// is_paused_now — the predicate that gates execute / appeal / settle
// ----------------------------------------------------------------------------

fn cfg_paused(paused_at: i64, paused_until: i64) -> SlashConfig {
    // Build a minimal SlashConfig with just the pause-relevant fields
    // populated. Everything else is default; only `paused`,
    // `paused_at`, and `paused_until` are read by `is_paused_now`.
    SlashConfig {
        admin:                       Pubkey::default(),
        slash_executor:              Pubkey::default(),
        appeal_resolver:             Pubkey::default(),
        pause_authority:             Pubkey::default(),
        treasury:                    Pubkey::default(),
        settlement_timelock_seconds: 0,
        paused:                      true,
        paused_at,
        paused_until,
        bump:                        0,
        layout_version:              SLASH_CONFIG_LAYOUT_VERSION,
        execute_to_settle_seconds:   0,
        settle_grace_seconds:        0,
        _reserved:                   [0u8; 6],
    }
}

fn cfg_unpaused() -> SlashConfig {
    SlashConfig {
        admin:                       Pubkey::default(),
        slash_executor:              Pubkey::default(),
        appeal_resolver:             Pubkey::default(),
        pause_authority:             Pubkey::default(),
        treasury:                    Pubkey::default(),
        settlement_timelock_seconds: 0,
        paused:                      false,
        paused_at:                   0,
        paused_until:                0,
        bump:                        0,
        layout_version:              SLASH_CONFIG_LAYOUT_VERSION,
        execute_to_settle_seconds:   0,
        settle_grace_seconds:        0,
        _reserved:                   [0u8; 6],
    }
}

#[test]
fn is_paused_now_false_when_flag_clear() {
    let cfg = cfg_unpaused();
    assert!(!cfg.is_paused_now(0));
    assert!(!cfg.is_paused_now(i64::MAX));
}

#[test]
fn is_paused_now_true_inside_window() {
    let now = 1_000_000i64;
    let cfg = cfg_paused(now, now + 3_600);
    assert!(cfg.is_paused_now(now));
    assert!(cfg.is_paused_now(now + 1));
    assert!(cfg.is_paused_now(now + 3_599));
}

#[test]
fn is_paused_now_false_at_exact_expiry() {
    // The predicate is `now < paused_until` — at `paused_until` the
    // pause has expired. This boundary matters because settle_slash
    // and friends use the same off-by-one as elsewhere in the lifecycle.
    let now = 1_000_000i64;
    let cfg = cfg_paused(now, now + 3_600);
    assert!(!cfg.is_paused_now(now + 3_600));
}

#[test]
fn is_paused_now_false_after_expiry_even_with_flag_high() {
    // The core H-04 guarantee: a stuck `paused = true` does not block
    // settlement once `paused_until` has passed. This is the property
    // that prevents an indefinite freeze even if the pause_authority
    // is compromised and never explicitly unpauses.
    let now = 1_000_000i64;
    let cfg = cfg_paused(now, now + 60);
    assert!(!cfg.is_paused_now(now + 61));
    assert!(!cfg.is_paused_now(now + 10_000_000));
}

#[test]
fn is_paused_now_false_when_paused_until_is_zero() {
    // Degenerate state: flag set but window never written. Equivalent
    // to "expired" — gates open. Same property guards against a buggy
    // future codepath that flips `paused` without setting the timer.
    let cfg = cfg_paused(0, 0);
    assert!(!cfg.is_paused_now(0));
    assert!(!cfg.is_paused_now(1));
}
