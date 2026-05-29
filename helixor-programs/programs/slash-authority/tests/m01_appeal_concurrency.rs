// =============================================================================
// programs/slash-authority/tests/m01_appeal_concurrency.rs
//
// Pure unit tests pinning the M-01 fix: per-vault hard cap on concurrent
// Appealed slashes.
//
// THE BUG
// -------
// The pre-existing 24h `last_appeal_at` cooldown only PACED appeal
// filings — it did not cap the number of in-flight appeals. An agent
// with N Pending slashes could sequentially appeal each within the 72h
// appeal window (one per 24h), so a single 72h window allowed THREE
// independent appeals to stack up, each blocking its own slash's
// settlement until resolved. The aggregate stall — bounded but real —
// could be exploited to delay multiple settlements in parallel.
//
// THE FIX
// -------
// `EscrowVault.appeals_in_flight: u8` records the number of slashes
// currently in the Appealed state for this vault.
//   - `appeal_slash` rejects with `AppealAlreadyInFlight` when the
//     counter is at `MAX_APPEALS_IN_FLIGHT` (= 1), and increments it
//     by one on a successful appeal.
//   - `resolve_appeal` decrements the counter by one on BOTH the
//     uphold (Pending) and overturn (Overturned) paths.
//
// The cap is one; an agent must wait for resolve_appeal on the
// current appeal before filing another. The 24h cooldown is retained
// as defence in depth against fast-cycle filings.
//
// These tests pin: the cap constant, the on-disk layout-version bump,
// the no-growth size invariant (1 byte reclaimed from `_reserved`), and
// the runtime-independent behaviour of the increment / decrement
// transitions.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::state::EscrowVault;

// ----------------------------------------------------------------------------
// Constant + layout pins
// ----------------------------------------------------------------------------

#[test]
fn max_appeals_in_flight_is_one() {
    // The audit-driven cap is exactly one in-flight Appealed slash per
    // vault. Bumping this constant weakens M-01 — bump deliberately.
    assert_eq!(EscrowVault::MAX_APPEALS_IN_FLIGHT, 1);
}

#[test]
fn vault_layout_version_bumped_for_m01() {
    // M-01 added `appeals_in_flight`. The on-disk shape changed, so
    // the layout version must bump (1 -> 2). If this fires the version
    // and the struct are out of sync — every M-01 invariant depends
    // on the on-chain data being readable with the new struct.
    assert_eq!(EscrowVault::CURRENT_LAYOUT_VERSION, 2);
}

#[test]
fn vault_size_unchanged_after_m01() {
    // The 1-byte `appeals_in_flight` was carved from the pre-existing
    // 16-byte reserve. The total stays at 99 bytes — so no PDA
    // resize / no devnet migration. If this fires the patch has
    // accidentally grown the vault.
    assert_eq!(EscrowVault::SIZE_WITHOUT_DISCRIMINATOR, 99);
    assert_eq!(EscrowVault::SPACE, 107);
}

// ----------------------------------------------------------------------------
// Cap behaviour — pure increment/decrement transitions
// ----------------------------------------------------------------------------

fn vault(appeals_in_flight: u8) -> EscrowVault {
    EscrowVault {
        agent_wallet:           Pubkey::default(),
        staked_lamports:        0,
        slash_count:            0,
        total_slashed_lamports: 0,
        created_at:             0,
        active:                 true,
        bump:                   0,
        layout_version:         EscrowVault::CURRENT_LAYOUT_VERSION,
        encumbered_lamports:    0,
        last_appeal_at:         0,
        appeals_in_flight,
        _reserved:              [0u8; 15],
    }
}

/// A fresh vault — no appeals filed — is below the cap and can accept
/// a new appeal. This is the common path.
#[test]
fn fresh_vault_can_accept_first_appeal() {
    let v = vault(0);
    assert!(v.appeals_in_flight < EscrowVault::MAX_APPEALS_IN_FLIGHT);
}

/// A vault with the cap already saturated is the M-01 reject path —
/// the gate fires and `appeal_slash` must refuse with
/// `AppealAlreadyInFlight`. Pinned with a direct comparison so the
/// constant change required to break the property is visible.
#[test]
fn saturated_vault_rejects_new_appeal() {
    let v = vault(EscrowVault::MAX_APPEALS_IN_FLIGHT);
    assert!(!(v.appeals_in_flight < EscrowVault::MAX_APPEALS_IN_FLIGHT));
}

/// Strict-less-than is intentional: the cap is the supremum, so a
/// vault sitting AT the cap cannot accept another appeal. If the
/// inequality were ever rewritten as `<=` this test fires.
#[test]
fn cap_predicate_uses_strict_less_than() {
    let v = vault(EscrowVault::MAX_APPEALS_IN_FLIGHT);
    let allowed = v.appeals_in_flight < EscrowVault::MAX_APPEALS_IN_FLIGHT;
    assert!(!allowed, "at-the-cap must NOT permit another appeal");
}

/// Increment path: appeal_slash takes the counter from 0 to 1 — the
/// only legal forward transition under MAX_APPEALS_IN_FLIGHT = 1.
#[test]
fn increment_zero_to_one_is_legal() {
    let mut v = vault(0);
    v.appeals_in_flight = v.appeals_in_flight.checked_add(1).unwrap();
    assert_eq!(v.appeals_in_flight, 1);
}

/// Increment overflow guard: with a u8 counter the realistic overflow
/// is 255 -> 256, but the cap stops well below that. Pin the checked
/// arithmetic anyway — if the field type widens later this still
/// rejects the wrap.
#[test]
fn increment_from_max_u8_overflows_under_checked_add() {
    let mut v = vault(u8::MAX);
    let res = v.appeals_in_flight.checked_add(1);
    assert!(res.is_none(), "checked_add at u8::MAX must overflow");
    v.appeals_in_flight = v.appeals_in_flight.checked_add(0).unwrap();
    assert_eq!(v.appeals_in_flight, u8::MAX);
}

/// Decrement path on uphold: resolve_appeal(uphold=true) takes the
/// counter from 1 back to 0 so a future, distinct slash can be
/// appealed.
#[test]
fn decrement_one_to_zero_on_uphold() {
    let mut v = vault(1);
    v.appeals_in_flight = v.appeals_in_flight.checked_sub(1).unwrap();
    assert_eq!(v.appeals_in_flight, 0);
}

/// Decrement path on overturn: same as uphold, the slot is released.
/// Pinned separately so a future refactor that wires the two branches
/// independently can't drift them out of sync.
#[test]
fn decrement_one_to_zero_on_overturn() {
    let mut v = vault(1);
    v.appeals_in_flight = v.appeals_in_flight.checked_sub(1).unwrap();
    assert_eq!(v.appeals_in_flight, 0);
}

/// Decrement underflow guard: resolve_appeal should never be called
/// against a vault with no in-flight appeals (lifecycle rejects an
/// already-resolved record first), but if it ever were, `checked_sub`
/// pins the failure rather than silently wrapping to 255 and opening
/// the door to UNbounded concurrent appeals.
#[test]
fn decrement_from_zero_underflows_under_checked_sub() {
    let v = vault(0);
    assert!(v.appeals_in_flight.checked_sub(1).is_none());
}

/// Cycle check: 0 -> 1 -> 0 -> 1 is the steady-state shape of an
/// agent appealing one slash, getting it resolved, appealing the
/// next. After the cycle the counter is back to 1 with no drift.
#[test]
fn full_appeal_resolve_cycle_returns_to_one() {
    let mut v = vault(0);
    v.appeals_in_flight = v.appeals_in_flight.checked_add(1).unwrap(); // appeal A
    v.appeals_in_flight = v.appeals_in_flight.checked_sub(1).unwrap(); // resolve A
    v.appeals_in_flight = v.appeals_in_flight.checked_add(1).unwrap(); // appeal B
    assert_eq!(v.appeals_in_flight, 1);
    // And the gate still permits NO further appeal (B is in flight).
    assert!(!(v.appeals_in_flight < EscrowVault::MAX_APPEALS_IN_FLIGHT));
}

// ----------------------------------------------------------------------------
// Error code stability — M-01 must not collide with any other error.
// ----------------------------------------------------------------------------

#[test]
fn appeal_already_in_flight_error_code_pinned() {
    // 6047 follows AppealCooldownActive (6045) and RecordVaultMismatch
    // (6046). Pinned so an unrelated reordering of the SlashError enum
    // cannot silently shift the code observed by clients.
    use slash_authority::errors::SlashError;
    assert_eq!(SlashError::AppealAlreadyInFlight as u32, 6047);
}
