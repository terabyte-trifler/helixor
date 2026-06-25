// =============================================================================
// programs/health-oracle/tests/m13_submit_score_escrow.rs
//
// M-13 — anti-griefing rent escrow on submit_score.
//
// THE PROBLEM THE AUDIT FLAGGED
// -----------------------------
// `submit_score` is authority-gated to the configured oracle_node, but
// the only economic cost per call is the base tx fee (~5_000 lamports).
// A misconfigured oracle script or a compromised oracle key can spam at
// near-zero cost, burning ledger space + program compute across the cert
// + score_components CPI write at every spam call. The audit flagged the
// missing signal-floor: each submission should impose a non-trivial,
// non-recoverable economic cost the oracle cannot avoid.
//
// THE FIX
// -------
// On every `submit_score` call the oracle now MUST init a per-(agent,
// epoch) `SubmitScoreEscrow` PDA and `system::transfer`
// `MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS` lamports above the rent-exempt
// minimum into it. The PDA is owned by health-oracle and has no refund
// path in M-13 — the lamports are LOCKED, which is what makes the floor
// a real cost. A future M-XX may layer a conditional refund / slash on
// top; M-13's contract is just the lock.
//
// PDA SEEDS
//   ["submit_score_escrow", agent_wallet, epoch_le]
//
// These tests pin:
//   * the floor constant (`MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS`),
//   * the SubmitScoreEscrow account layout version + space + seed prefix,
//   * the SubmitScoreEscrowFunded event field surface (struct-literal
//     type pin so a refactor that drops a field fails THIS file, not
//     the off-chain indexer at runtime),
//   * the error-code stability (SubmitEscrowBelowFloor == 6100),
//   * the PDA derivation (collision-free across (agent, epoch) tuples,
//     stable across re-derives).
// =============================================================================

use anchor_lang::prelude::Pubkey;
use anchor_lang::Discriminator;
use health_oracle::errors::PhylanxError;
use health_oracle::events::SubmitScoreEscrowFunded;
use health_oracle::state::{
    SubmitScoreEscrow, MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS,
};

// -----------------------------------------------------------------------------
// Floor-constant pin
// -----------------------------------------------------------------------------

#[test]
fn min_submit_escrow_deposit_lamports_is_pinned() {
    // 1_000_000 lamports = 0.001 SOL — three orders of magnitude above
    // the base tx fee (~5_000), small enough that honest oracle ops
    // don't notice at per-submission scale, large enough that a runaway
    // script burns SOL meaningfully per call. Bumping this value
    // intentionally retunes the floor — a contributor who changes the
    // constant MUST update this pin AND the off-chain ops runbook.
    assert_eq!(MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS, 1_000_000);
}

#[test]
fn min_submit_escrow_deposit_exceeds_base_tx_fee() {
    // The whole point of the floor is to dominate the base tx fee, so a
    // refactor that accidentally drops the floor at or below the tx fee
    // re-opens the griefing surface. The Solana base fee is 5_000
    // lamports per signature; we pin two orders of magnitude above.
    const SOLANA_BASE_SIGNATURE_FEE: u64 = 5_000;
    assert!(
        MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS >= SOLANA_BASE_SIGNATURE_FEE * 100,
        "M-13 floor must dominate the base tx fee by at least 100x — \
         a smaller floor lets a runaway script grief at near-cost",
    );
}

// -----------------------------------------------------------------------------
// Error-code pin
// -----------------------------------------------------------------------------

#[test]
fn submit_escrow_below_floor_code_is_stable() {
    // 6100 — slotted in the M-04 / M-13 contiguous block (M-04 = 6090..6093).
    // The off-chain monitor + TS SDK switch on this literal; a renumber
    // MUST update both this pin AND the canonical error-code allocation.
    assert_eq!(PhylanxError::SubmitEscrowBelowFloor as u32, 6100);
}

// -----------------------------------------------------------------------------
// SubmitScoreEscrow — account surface pins
// -----------------------------------------------------------------------------

#[test]
fn submit_score_escrow_layout_version_is_v1() {
    // Pinned at v1. A future additive field change MUST bump this
    // constant; this test is the canary that catches a contributor
    // adding a field without updating the version tag.
    assert_eq!(SubmitScoreEscrow::CURRENT_LAYOUT_VERSION, 1);
}

#[test]
fn submit_score_escrow_seed_prefix_is_stable() {
    // The seed prefix is the on-chain ABI for the PDA — a rename would
    // re-key every existing escrow. Pinned exactly here so a refactor
    // that touches the seed has to update THIS test (and write a
    // migration handler) deliberately.
    assert_eq!(SubmitScoreEscrow::SEED_PREFIX, b"submit_score_escrow");
}

#[test]
fn submit_score_escrow_space_matches_struct_layout() {
    //   8  discriminator
    // + 32 agent_wallet
    // + 8  epoch
    // + 32 oracle
    // + 8  deposited_at
    // + 8  deposited_lamports
    // + 1  bump
    // + 1  layout_version
    // = 98 bytes
    assert_eq!(SubmitScoreEscrow::SPACE, 8 + 32 + 8 + 32 + 8 + 8 + 1 + 1);
    assert_eq!(SubmitScoreEscrow::SPACE, 98);
}

#[test]
fn submit_score_escrow_struct_literal_pin() {
    // Struct-literal type pin: this file does not compile if any of
    // the M-13 fields is removed or renamed. Off-chain indexers
    // dispatch on the account SCHEMA, so silently dropping a field
    // would break forensic attribution at runtime — pin at compile
    // time instead.
    let _e = SubmitScoreEscrow {
        agent_wallet:       Pubkey::default(),
        epoch:              0,
        oracle:             Pubkey::default(),
        deposited_at:       0,
        deposited_lamports: 0,
        bump:               0,
        layout_version:     0,
    };
}

#[test]
fn submit_score_escrow_discriminator_is_eight_bytes() {
    // Anchor's `#[account]` macro autoderives an 8-byte discriminator
    // from sha256("account:SubmitScoreEscrow")[..8]. Pinning the LENGTH
    // here paired with the per-instance derivation in the on-chain
    // build is the same discipline as M-10's discriminator pins on
    // health-oracle's other accounts.
    assert_eq!(SubmitScoreEscrow::DISCRIMINATOR.len(), 8);
    // And non-zero — the all-zeros discriminator is the sentinel for
    // "uninitialised account" in Anchor and would mean the autoderive
    // misfired.
    assert_ne!(SubmitScoreEscrow::DISCRIMINATOR, &[0u8; 8]);
}

// -----------------------------------------------------------------------------
// SubmitScoreEscrowFunded — event surface pins
// -----------------------------------------------------------------------------

#[test]
fn submit_score_escrow_funded_struct_literal_pin() {
    // Struct-literal type pin on the event. Same rationale as the
    // account body — the off-chain indexer dispatches on the event
    // schema. Dropping a field at compile time fails THIS test, not
    // every consumer at runtime.
    let _ev = SubmitScoreEscrowFunded {
        escrow:               Pubkey::default(),
        agent_wallet:         Pubkey::default(),
        epoch:                0,
        oracle:               Pubkey::default(),
        deposited_lamports:   0,
        escrow_balance_after: 0,
        funded_at:            0,
    };
}

#[test]
fn submit_score_escrow_funded_round_trips_fields() {
    // Sanity: the values the test writes survive the move into the
    // event struct in the order declared. Catches a field-shadow /
    // reorder bug where the event compiles but stores
    // `deposited_lamports` in the `escrow_balance_after` slot.
    let escrow = Pubkey::new_unique();
    let agent  = Pubkey::new_unique();
    let oracle = Pubkey::new_unique();
    let ev = SubmitScoreEscrowFunded {
        escrow,
        agent_wallet:         agent,
        epoch:                42,
        oracle,
        deposited_lamports:   MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS,
        escrow_balance_after: MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS + 2_000_000,
        funded_at:            1_700_000_000,
    };
    assert_eq!(ev.escrow,               escrow);
    assert_eq!(ev.agent_wallet,         agent);
    assert_eq!(ev.epoch,                42);
    assert_eq!(ev.oracle,               oracle);
    assert_eq!(ev.deposited_lamports,   MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS);
    assert_eq!(
        ev.escrow_balance_after,
        MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS + 2_000_000,
    );
    assert_eq!(ev.funded_at, 1_700_000_000);
}

// -----------------------------------------------------------------------------
// PDA derivation — collision-free across (agent, epoch) tuples
// -----------------------------------------------------------------------------

/// Pure helper that derives the SubmitScoreEscrow PDA for an (agent,
/// epoch) under a given program id, mirroring exactly the seeds the
/// on-chain `#[account(seeds = ...)]` declaration uses. An off-chain
/// SDK consumer derives the PDA the same way; pin this here so a future
/// seed-layout drift fails this test (rather than every consumer at
/// runtime).
fn derive_escrow_pda(
    program_id: &Pubkey,
    agent:      &Pubkey,
    epoch:      u64,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            SubmitScoreEscrow::SEED_PREFIX,
            agent.as_ref(),
            &epoch.to_le_bytes(),
        ],
        program_id,
    )
}

#[test]
fn escrow_pda_is_deterministic_for_the_same_inputs() {
    let program = Pubkey::new_unique();
    let agent   = Pubkey::new_unique();
    let (pda_a, bump_a) = derive_escrow_pda(&program, &agent, 100);
    let (pda_b, bump_b) = derive_escrow_pda(&program, &agent, 100);
    assert_eq!(pda_a, pda_b);
    assert_eq!(bump_a, bump_b);
}

#[test]
fn escrow_pda_differs_across_epochs_for_same_agent() {
    let program = Pubkey::new_unique();
    let agent   = Pubkey::new_unique();
    let (pda_e1, _) = derive_escrow_pda(&program, &agent, 1);
    let (pda_e2, _) = derive_escrow_pda(&program, &agent, 2);
    assert_ne!(
        pda_e1, pda_e2,
        "the (agent, epoch) seeding guarantees per-epoch write-once \
         semantics — two epochs MUST resolve to distinct escrow PDAs",
    );
}

#[test]
fn escrow_pda_differs_across_agents_for_same_epoch() {
    let program = Pubkey::new_unique();
    let agent_a = Pubkey::new_unique();
    let agent_b = Pubkey::new_unique();
    let (pda_a, _) = derive_escrow_pda(&program, &agent_a, 5);
    let (pda_b, _) = derive_escrow_pda(&program, &agent_b, 5);
    assert_ne!(
        pda_a, pda_b,
        "the (agent, epoch) seeding guarantees per-agent isolation — \
         two agents at the same epoch MUST resolve to distinct escrow PDAs",
    );
}

#[test]
fn escrow_pda_differs_across_programs() {
    // Defence-in-depth: a deployment to a different program ID derives
    // a different PDA. Pinned so a future contributor renaming the
    // program / migrating to a new ID does not silently overlap escrow
    // accounts.
    let agent = Pubkey::new_unique();
    let (pda_a, _) = derive_escrow_pda(&Pubkey::new_unique(), &agent, 1);
    let (pda_b, _) = derive_escrow_pda(&Pubkey::new_unique(), &agent, 1);
    assert_ne!(pda_a, pda_b);
}

// -----------------------------------------------------------------------------
// Floor conservation invariant — pure form
// -----------------------------------------------------------------------------

/// Pure form of the handler's M-13 post-transfer balance invariant.
/// Returns true iff `escrow_after >= escrow_before + deposit` and
/// `deposit >= floor`. The on-chain handler enforces both halves.
fn escrow_balance_meets_floor(
    escrow_before: u64,
    escrow_after:  u64,
    deposit:       u64,
    floor:         u64,
) -> bool {
    let conservation = escrow_before
        .checked_add(deposit)
        .map(|expected| escrow_after >= expected)
        .unwrap_or(false);
    let floor_ok = deposit >= floor;
    conservation && floor_ok
}

#[test]
fn floor_invariant_accepts_a_correct_deposit() {
    let floor = MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS;
    // rent-exempt(SPACE=98) is roughly 1_461_600; the test treats it as
    // an arbitrary nonzero `escrow_before`. The actual rent value comes
    // from the runtime; the predicate is what we pin here.
    assert!(escrow_balance_meets_floor(
        1_461_600,
        1_461_600 + floor,
        floor,
        floor,
    ));
}

#[test]
fn floor_invariant_accepts_an_over_deposit() {
    let floor = MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS;
    // The oracle MAY over-deposit; the floor is a minimum, not a
    // maximum. The invariant should still hold.
    assert!(escrow_balance_meets_floor(
        1_461_600,
        1_461_600 + floor * 5,
        floor * 5,
        floor,
    ));
}

#[test]
fn floor_invariant_rejects_a_short_deposit() {
    let floor = MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS;
    // The oracle deposited the floor minus 1 — must fail.
    assert!(!escrow_balance_meets_floor(
        1_461_600,
        1_461_600 + floor - 1,
        floor - 1,
        floor,
    ));
}

#[test]
fn floor_invariant_rejects_a_zero_deposit() {
    let floor = MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS;
    assert!(!escrow_balance_meets_floor(1_461_600, 1_461_600, 0, floor));
}

#[test]
fn floor_invariant_rejects_a_balance_that_did_not_increase() {
    // The deposit nominally meets the floor but the escrow's live
    // balance did not actually increase — e.g. a refactor that
    // accidentally sent the transfer to a different account. The
    // handler re-reads `escrow.lamports()` post-transfer specifically
    // to catch this; pin the predicate that catches it.
    let floor = MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS;
    assert!(!escrow_balance_meets_floor(
        1_461_600,
        1_461_600,        // did not grow
        floor,            // claimed deposit
        floor,
    ));
}

#[test]
fn floor_invariant_rejects_arithmetic_overflow() {
    // `escrow_before + deposit` overflows u64; the predicate's
    // `checked_add` returns None and the function falls through to
    // false. This is operationally unreachable (no oracle has u64::MAX
    // lamports), but pin the safety case.
    let floor = MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS;
    assert!(!escrow_balance_meets_floor(
        u64::MAX,
        u64::MAX,
        floor,
        floor,
    ));
}
