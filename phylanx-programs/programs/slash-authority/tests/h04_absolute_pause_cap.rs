// =============================================================================
// programs/slash-authority/tests/h04_absolute_pause_cap.rs
//
// H-04 (absolute cap) — convert the bounded pause from
// "bounded by SPOF-#2 rotation latency" to "bounded by CODE."
//
// THE AUDIT FINDING (extension)
// -----------------------------
// The first H-04 patch capped each pause at MAX_PAUSE_SECONDS (7d) and
// blocked re-pause while a window was still active. But a compromised
// pause_authority could still loop: pause 7d, wait for natural expiry
// (or manually unpause), immediately re-pause. The duty cycle ceiling
// was ~100% — the only thing that bounded total freeze time was the
// SPOF-#2 rotation latency (48h timelock + 2-of-3 attestation).
//
// THE FIX
// -------
// 1. A `PAUSE_COOLDOWN_SECONDS` (24h) constant — the minimum time
//    between the END of one pause window (`paused_until`) and the
//    START of the next.
// 2. `SlashConfig::pause_cooldown_satisfied(now)` — the predicate that
//    `pause_settlements` consults at the boundary.
// 3. `unpause_settlements` DELIBERATELY PRESERVES `paused_until` — only
//    `paused` and `paused_at` are cleared. The cooldown therefore
//    applies even when the previous pause was unpaused early; a
//    compromised key cannot bypass via pause -> unpause -> re-pause.
//
// WORST-CASE DUTY CYCLE
// ---------------------
// MAX_PAUSE_SECONDS = 7d, PAUSE_COOLDOWN_SECONDS = 24h.
// Worst-case sustainable duty cycle: 7d / 8d = 87.5%.
// Guaranteed unpaused window: 24h every 8d — enough for a 48h-timelock
// rotation to be proposed in one window and enacted in a later one.
//
// WHAT THIS FILE PINS
// -------------------
//   * The cooldown constant value (24h) — bump deliberately.
//   * The predicate is `now >= paused_until + PAUSE_COOLDOWN_SECONDS`
//     (saturating, never wrapping).
//   * Genesis (paused_until == 0) trivially satisfies the cooldown.
//   * The boundary moment — cooldown elapses EXACTLY at
//     `paused_until + COOLDOWN`.
//   * The on-disk layout is UNCHANGED — the cooldown does not require a
//     new field; it reads the existing `paused_until` directly.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::state::{
    SlashConfig, MAX_PAUSE_SECONDS, PAUSE_COOLDOWN_SECONDS,
    SLASH_CONFIG_LAYOUT_VERSION,
};

// ----------------------------------------------------------------------------
// Constant pins
// ----------------------------------------------------------------------------

#[test]
fn pause_cooldown_is_24_hours() {
    // The cooldown is the CODE-side ceiling on the H-04 duty cycle.
    // Shortening it weakens the bound; lengthening it shrinks the
    // pause_authority's legitimate operational window. Either direction
    // is a deliberate parameter change, not an accident.
    assert_eq!(PAUSE_COOLDOWN_SECONDS, 24 * 3_600);
}

#[test]
fn worst_case_duty_cycle_bound_is_seven_over_eight() {
    // The H-04 (absolute cap) invariant, numerically:
    //   per_pause_max + cooldown == 7d + 24h == 8d
    //   worst_case_duty = per_pause_max / cycle = 7d / 8d
    // Any future tweak of MAX_PAUSE_SECONDS or PAUSE_COOLDOWN_SECONDS
    // that re-balances this ratio should update this pin too.
    let cycle = MAX_PAUSE_SECONDS + PAUSE_COOLDOWN_SECONDS;
    assert_eq!(cycle, 8 * 24 * 3_600);
    assert_eq!(MAX_PAUSE_SECONDS as f64 / cycle as f64, 7.0 / 8.0);
}

// ----------------------------------------------------------------------------
// Layout invariance — the cooldown adds NO new fields
// ----------------------------------------------------------------------------

#[test]
fn h04_absolute_cap_did_not_grow_slash_config() {
    // The cooldown is enforced against the EXISTING `paused_until`
    // field — no new persistent state was added. If this pin ever
    // fires, the layout has grown stealthily, which is a live-deploy
    // migration risk.
    assert_eq!(SlashConfig::SIZE_WITHOUT_DISCRIMINATOR, 209);
    assert_eq!(SlashConfig::SPACE, 217);
    // Same layout version as the original H-04 + M-07 + M-08 stack —
    // the cooldown is pure code, not on-disk shape.
    assert_eq!(SLASH_CONFIG_LAYOUT_VERSION, 5);
}

// ----------------------------------------------------------------------------
// Predicate truth table
// ----------------------------------------------------------------------------

fn cfg_with_last_paused_until(paused_until: i64) -> SlashConfig {
    // The cooldown predicate reads ONLY `paused_until`. Everything else
    // is default. We are NOT pausing — `paused` stays false; the
    // predicate models the moment a NEXT pause is being considered.
    SlashConfig {
        admin:                       Pubkey::default(),
        slash_executor:              Pubkey::default(),
        appeal_resolver:             Pubkey::default(),
        pause_authority:             Pubkey::default(),
        treasury:                    Pubkey::default(),
        settlement_timelock_seconds: 0,
        paused:                      false,
        paused_at:                   0,
        paused_until,
        bump:                        0,
        layout_version:              SLASH_CONFIG_LAYOUT_VERSION,
        execute_to_settle_seconds:   0,
        settle_grace_seconds:        0,
        slash_config_version:        0,
        _reserved:                   [0u8; 2],
    }
}

#[test]
fn genesis_paused_until_zero_satisfies_cooldown_for_any_plausible_now() {
    // A freshly initialised config has paused_until == 0. The first
    // pause must not be blocked by the cooldown — the predicate is
    // `now >= 0 + COOLDOWN`, which is trivially true for any unix
    // timestamp past 1970-01-02.
    let cfg = cfg_with_last_paused_until(0);
    assert!(cfg.pause_cooldown_satisfied(PAUSE_COOLDOWN_SECONDS));
    assert!(cfg.pause_cooldown_satisfied(2_000_000_000));
    // Defensive: at exactly the cooldown horizon the predicate flips on.
    assert!(cfg.pause_cooldown_satisfied(PAUSE_COOLDOWN_SECONDS));
    // Anything below the cooldown horizon (degenerate, only happens in
    // the first day of the unix epoch) is correctly blocked.
    assert!(!cfg.pause_cooldown_satisfied(PAUSE_COOLDOWN_SECONDS - 1));
}

#[test]
fn cooldown_blocks_immediate_re_pause_after_window_ends() {
    // Previous pause ended at t = 1_000_000. The cooldown blocks
    // re-pause until t + 24h. Pin every boundary moment in between.
    let prev_end = 1_000_000_i64;
    let cfg      = cfg_with_last_paused_until(prev_end);

    // Exactly at the previous expiry: still cooling down.
    assert!(!cfg.pause_cooldown_satisfied(prev_end));
    // 1s into the cooldown: still blocked.
    assert!(!cfg.pause_cooldown_satisfied(prev_end + 1));
    // 23h59m59s in: still blocked.
    assert!(!cfg.pause_cooldown_satisfied(prev_end + PAUSE_COOLDOWN_SECONDS - 1));
    // Exactly 24h in: cooldown elapsed, next pause allowed.
    assert!(cfg.pause_cooldown_satisfied(prev_end + PAUSE_COOLDOWN_SECONDS));
    // Long after: still allowed.
    assert!(cfg.pause_cooldown_satisfied(prev_end + PAUSE_COOLDOWN_SECONDS + 10_000));
}

#[test]
fn cooldown_blocks_re_pause_even_after_seven_day_window() {
    // The canonical hostile pattern: a compromised pause_authority
    // pauses for MAX_PAUSE_SECONDS, waits for natural expiry, tries
    // to re-pause IMMEDIATELY at expiry. The cooldown blocks them for
    // the next 24h.
    let pause_start = 5_000_000_i64;
    let pause_end   = pause_start + MAX_PAUSE_SECONDS;
    let cfg         = cfg_with_last_paused_until(pause_end);

    // Adversary tries to re-pause the moment the previous window ends.
    assert!(!cfg.pause_cooldown_satisfied(pause_end));
    // ...1h into the unpaused window. Still blocked.
    assert!(!cfg.pause_cooldown_satisfied(pause_end + 3_600));
    // ...exactly 24h in. Re-pause allowed (worst-case cycle = 8d).
    assert!(cfg.pause_cooldown_satisfied(pause_end + PAUSE_COOLDOWN_SECONDS));
}

// ----------------------------------------------------------------------------
// Defence vs i64 overflow
// ----------------------------------------------------------------------------

#[test]
fn cooldown_predicate_does_not_wrap_at_i64_max() {
    // A pathological `paused_until` near i64::MAX must not panic the
    // predicate via integer overflow. The implementation uses
    // saturating_add; the cooldown horizon saturates at i64::MAX and
    // the predicate returns false for every reachable `now`.
    let cfg = cfg_with_last_paused_until(i64::MAX);
    assert!(!cfg.pause_cooldown_satisfied(0));
    assert!(!cfg.pause_cooldown_satisfied(i64::MAX - 1));
    // At now == i64::MAX (the saturation ceiling), the predicate flips
    // on — but reaching that timestamp requires a unix epoch on the
    // order of 10^11 years, which the program operationally never sees.
    assert!(cfg.pause_cooldown_satisfied(i64::MAX));
}
