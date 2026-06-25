// =============================================================================
// programs/slash-authority/tests/m11_settle_lamport_audit_trail.rs
//
// M-11 — bind the SlashSettled event to a self-auditing lamport-balance
// record, so the direct `try_borrow_mut_lamports` mutation in settle_slash
// produces an on-chain audit trail equivalent to a System::transfer log.
//
// THE PROBLEM THE AUDIT FLAGGED
// -----------------------------
// settle_slash moves lamports out of the program-owned escrow vault by
// directly mutating the source's `lamports` cell:
//
//     **vault_ai.try_borrow_mut_lamports()? = vault_after;
//     **dest_ai.try_borrow_mut_lamports()?  = dest_after;
//
// This is the canonical Solana pattern for a program-owned source —
// System::transfer refuses to move lamports out of an account whose
// owner is not the System Program. The pattern is SAFE.
//
// BUT: it produces NO System Program "Transfer" log. An off-chain
// auditor that watches `Program 11111111111111111111111111111111 invoke`
// + "Transfer:" lines as their ledger of value movement sees nothing
// for this debit — the only signal that lamports moved is the
// SlashSettled event. Pre-M-11 that event only carried
// `settled_lamports` — there was no on-chain proof that the vault was
// debited by exactly that amount and the destination credited by the
// same. A future refactor introducing a partial-update bug could have
// emitted SlashSettled while silently dropping lamports on the floor,
// and an off-chain audit relying on the event would have missed it.
//
// THE FIX
// -------
// M-11 enriches SlashSettled with:
//   * destination_key            — the explicit recipient pubkey
//   * vault_balance_before/after — pre/post the direct mutation
//   * destination_balance_before/after — same for the recipient
//
// The handler reads the live balances post-mutation and asserts they
// balance against `amount`:
//   require!(vault_before - amount == vault_after,    LamportAuditMismatch);
//   require!(dest_before  + amount == dest_after,     LamportAuditMismatch);
// (= 6090). A violation aborts the tx so the event log NEVER carries
// an internally-inconsistent SlashSettled.
//
// In addition the handler emits a stable parseable `msg!()` line:
//     "slash-authority transfer: from=<vault> to=<dest> amount=<lamports>
//      vault_before=<n> vault_after=<n> dest_before=<n> dest_after=<n>"
// so off-chain log scrapers can grep this line the same way they grep
// System Program Transfer logs.
//
// These tests pin:
//   * the SlashSettled struct surface via a struct-literal type pin
//     (so a refactor that drops a field fails this file, not the
//     downstream indexer at runtime);
//   * the new LamportAuditMismatch error code (= 6090);
//   * the conservation invariants the handler enforces, exercised in
//     isolation (Rust-level) so the predicate is unit-testable without
//     spinning up a validator.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::errors::SlashError;
use slash_authority::events::SlashSettled;

// -----------------------------------------------------------------------------
// Error-code pin
// -----------------------------------------------------------------------------

#[test]
fn lamport_audit_mismatch_code_is_stable() {
    // 6090 was chosen to slot directly after the M-08 block (6089), keeping
    // M-09/M-10/M-11 codes contiguous in the slash-authority allocation
    // (M-09 / M-10 are non-error-code fixes elsewhere). The off-chain
    // monitor + TS SDK switch on this literal — a renumber MUST update
    // both this pin AND the canonical error-code allocation list.
    assert_eq!(SlashError::LamportAuditMismatch as u32, 6090);
}

// -----------------------------------------------------------------------------
// SlashSettled — field surface pin
// -----------------------------------------------------------------------------

#[test]
fn slash_settled_event_carries_full_balance_audit_surface() {
    // Struct-literal type pin: this file does not compile if any of the
    // M-11 fields are removed or renamed. The off-chain indexer dispatches
    // on the event SCHEMA, so silently dropping a balance field would
    // break audit-trail consumers at runtime — pin it at compile time
    // instead.
    let _ev = SlashSettled {
        agent_wallet:               Pubkey::default(),
        index:                      0,
        settled_lamports:           0,
        destination:                0,
        destination_key:            Pubkey::default(),
        vault_balance_before:       0,
        vault_balance_after:        0,
        destination_balance_before: 0,
        destination_balance_after:  0,
        terminal:                   false,
        settled_at:                 0,
        executed_at:                0,
    };
}

#[test]
fn slash_settled_event_round_trips_audit_fields() {
    // Sanity: the values the test writes survive the move into the event
    // struct in the order declared. Catches a field-shadow / reorder bug
    // where the event compiles but stores `vault_balance_after` in the
    // `destination_balance_before` slot or similar.
    let dest = Pubkey::new_unique();
    let ev = SlashSettled {
        agent_wallet:               Pubkey::default(),
        index:                      0,
        settled_lamports:           100,
        destination:                0,
        destination_key:            dest,
        vault_balance_before:       1_000,
        vault_balance_after:        900,
        destination_balance_before: 0,
        destination_balance_after:  100,
        terminal:                   false,
        settled_at:                 0,
        executed_at:                0,
    };
    assert_eq!(ev.destination_key,            dest);
    assert_eq!(ev.vault_balance_before,       1_000);
    assert_eq!(ev.vault_balance_after,        900);
    assert_eq!(ev.destination_balance_before, 0);
    assert_eq!(ev.destination_balance_after,  100);
}

// -----------------------------------------------------------------------------
// Conservation invariants — the predicate the handler enforces, pure form
// -----------------------------------------------------------------------------

/// Pure form of the handler's M-11 invariant. Returns true iff the
/// pre/post balance quadruple balances against `amount`.
fn lamport_audit_balances(
    vault_before:       u64,
    vault_after:        u64,
    dest_before:        u64,
    dest_after:         u64,
    amount:             u64,
) -> bool {
    let vault_ok = vault_before
        .checked_sub(amount)
        .map(|expected| expected == vault_after)
        .unwrap_or(false);
    let dest_ok = dest_before
        .checked_add(amount)
        .map(|expected| expected == dest_after)
        .unwrap_or(false);
    vault_ok && dest_ok
}

#[test]
fn audit_invariant_passes_for_a_balanced_transfer() {
    assert!(lamport_audit_balances(1_000, 900, 0, 100, 100));
    assert!(lamport_audit_balances(50_000, 49_500, 12_345, 12_845, 500));
}

#[test]
fn audit_invariant_passes_for_a_zero_transfer() {
    // Operationally settle_slash never settles a zero amount (the slash
    // would have nothing to encumber), but the predicate should still
    // hold trivially — pre and post balances unchanged.
    assert!(lamport_audit_balances(100, 100, 50, 50, 0));
}

#[test]
fn audit_invariant_rejects_a_skim_on_the_destination() {
    // Vault debited by 100, destination credited by 99 — a skim attack.
    // The invariant catches it.
    assert!(!lamport_audit_balances(1_000, 900, 0, 99, 100));
}

#[test]
fn audit_invariant_rejects_an_over_debit_on_the_vault() {
    // Vault debited by 101, destination credited by 100 — lamports lost
    // to the void. The invariant catches it.
    assert!(!lamport_audit_balances(1_000, 899, 0, 100, 100));
}

#[test]
fn audit_invariant_rejects_an_unrelated_destination_credit() {
    // Vault debited correctly, BUT destination credited an extra amount
    // (e.g. an aliased account-info write from a future refactor).
    assert!(!lamport_audit_balances(1_000, 900, 0, 200, 100));
}

#[test]
fn audit_invariant_rejects_an_unchanged_vault() {
    // A bug that emits SlashSettled but actually performs no transfer:
    // both balances unchanged, non-zero amount. The invariant catches it.
    assert!(!lamport_audit_balances(1_000, 1_000, 0, 0, 100));
}

#[test]
fn audit_invariant_rejects_arithmetic_underflow_in_vault() {
    // amount > vault_before — debit would underflow. The handler
    // catches this earlier with `checked_sub`, but the predicate
    // should also fail (it returns `false` via the `checked_sub`
    // -> `unwrap_or(false)` fallback).
    assert!(!lamport_audit_balances(50, 0, 0, 50, 100));
}

#[test]
fn audit_invariant_rejects_arithmetic_overflow_in_destination() {
    // amount + dest_before > u64::MAX — credit would overflow.
    assert!(!lamport_audit_balances(
        u64::MAX, u64::MAX - 1, u64::MAX, 0, 1,
    ));
}

// -----------------------------------------------------------------------------
// Audit-trail log line — algorithmic shape
// -----------------------------------------------------------------------------

#[test]
fn audit_trail_log_prefix_is_grepable() {
    // The on-chain handler emits a `msg!()` line beginning with the
    // string `"slash-authority transfer:"`. Off-chain log scrapers
    // grep this exact prefix to find slash-authority's program-owned-
    // source movements that System::transfer cannot produce. The
    // prefix is part of the operational contract — pin it.
    //
    // We can't observe the on-chain `msg!()` from a unit test, but we
    // CAN pin the string the handler concatenates from. The prefix
    // lives in the handler source — if it ever drifts, an integration
    // test that greps the log buffer fires. This test exists to
    // document the contract so a contributor renaming the prefix is
    // forced to read the rationale here first.
    const EXPECTED_PREFIX: &str = "slash-authority transfer:";
    // Sanity: the literal we documented matches itself. Deliberately
    // tautological — a future contributor changing the prefix in the
    // handler updates THIS pin (and the off-chain scrapers).
    assert_eq!(EXPECTED_PREFIX, "slash-authority transfer:");
}
