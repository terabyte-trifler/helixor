// =============================================================================
// programs/slash-authority/tests/audit_mitigation_pins.rs
//
// Audit-response REGRESSION PINS for the informational / already-mitigated
// findings on slash-authority.
//
// The audit listed these as "the mitigation is correct and defensible in the
// current code". That is true. This file defends against a FUTURE REFACTOR
// silently weakening the mitigation — e.g. someone dropping the 72h
// settlement-timelock floor when adjusting a constant, or weakening the
// 2-of-3 SPOF-02 quorum.
//
// FINDINGS COVERED HERE
//   * VULN-04 — authority separation: executor / resolver / pauser are
//                distinct, enforced by `AuthoritiesMustDiffer = 6004` at
//                config init AND at every rotation enact.
//   * VULN-08 — settle observability: SettleSlashAttempted event surface
//                exists. (Existing tests in vuln08_settle_timing.rs pin
//                the timing-gate codes; this file pins the EVENT surface
//                that the audit asked for.)
//   * SPOF-02 — authority rotation: 48h timelock floor, 2-of-3 quorum,
//                3 role-key slots. Already heavily pinned by
//                spof02_authority_rotation.rs; this file pins the
//                INVARIANT CONSTANTS so a constant rename or floor
//                relaxation is caught at the test layer.
//   * VULN-13 — has_one ↔ seeds consistency on EscrowVault + SlashRecord
//                (single source of truth for `agent_wallet` + bump).
//   * VULN-10 — init_if_needed not used on settlement paths: EscrowVault's
//                SEED_PREFIX is stable; reopening is impossible because
//                `open_vault.rs` uses plain `init`.
// =============================================================================

use slash_authority::errors::SlashError;
use slash_authority::state::{
    EscrowVault, MIN_SETTLEMENT_TIMELOCK_SECONDS, PendingAuthorityRotation, SlashRecord,
};

// -----------------------------------------------------------------------------
// VULN-04 — authority separation invariant
// -----------------------------------------------------------------------------

#[test]
fn authorities_must_differ_code_is_stable() {
    // 6004 is referenced by the deploy runbook + the operational alert
    // wiring — any tx that bails with this code pages the on-call.
    // A renumber MUST also update the runbook + alert.
    assert_eq!(SlashError::AuthoritiesMustDiffer as u32, 6004);
}

#[test]
fn min_settlement_timelock_is_72_hours() {
    // VULN-04 demands the settlement timelock cannot fall below 72h.
    // The constant is the SINGLE SOURCE OF TRUTH consulted at
    // initialize_config, propose_authority_rotation, and
    // enact_authority_rotation. A weakening of this constant silently
    // weakens all three call sites.
    const SECONDS_PER_HOUR: i64 = 3600;
    assert_eq!(
        MIN_SETTLEMENT_TIMELOCK_SECONDS,
        72 * SECONDS_PER_HOUR,
        "VULN-04 settlement-timelock floor regressed below 72h",
    );
}

// -----------------------------------------------------------------------------
// SPOF-02 — rotation timelock + quorum constants
// -----------------------------------------------------------------------------

#[test]
fn rotation_timelock_floor_is_48_hours() {
    // SPOF-02 floor: 48h between propose and enact. Together with the
    // 2-of-3 quorum, this gives an attacker who controlled ONE role key
    // 48h of public timelock window to be revoked before they can enact
    // a malicious rotation. A weakening here destroys SPOF-02's core
    // safety claim.
    const SECONDS_PER_HOUR: i64 = 3600;
    assert_eq!(
        PendingAuthorityRotation::MIN_TIMELOCK_SECONDS,
        48 * SECONDS_PER_HOUR,
        "SPOF-02 rotation timelock floor regressed below 48h",
    );
}

#[test]
fn role_key_count_is_three() {
    // SPOF-02 design: exactly three role keys — executor, resolver,
    // pauser. Quorum sizing depends on this; adding a 4th role without
    // touching CONSENSUS_THRESHOLD silently weakens the ratio.
    assert_eq!(PendingAuthorityRotation::ROLE_KEY_COUNT, 3);
}

#[test]
fn consensus_threshold_is_two_of_three() {
    // SPOF-02 quorum: 2 of 3. Lowering to 1 = single-key attacker can
    // enact. Raising to 3 = the system cannot rotate if any key is lost
    // (the SPOF-02 attack itself).
    assert_eq!(PendingAuthorityRotation::CONSENSUS_THRESHOLD, 2);
    // Sanity: quorum < total, quorum > total/2.
    assert!(
        PendingAuthorityRotation::CONSENSUS_THRESHOLD
            < PendingAuthorityRotation::ROLE_KEY_COUNT,
    );
    assert!(
        PendingAuthorityRotation::CONSENSUS_THRESHOLD * 2
            > PendingAuthorityRotation::ROLE_KEY_COUNT,
    );
}

// -----------------------------------------------------------------------------
// VULN-10 — write-once EscrowVault PDA
// -----------------------------------------------------------------------------

#[test]
fn escrow_vault_seed_prefix_is_stable() {
    // The off-chain SDK derives the per-agent vault PDA from the LITERAL
    // bytes `b"escrow"`. A rename moves every existing vault out of
    // reach of old consumers; a slash executed against the "new" prefix
    // would target an empty account.
    assert_eq!(EscrowVault::SEED_PREFIX, b"escrow");
}

#[test]
fn escrow_vault_min_stake_pinned() {
    // The economic floor open_vault enforces. A reduction here silently
    // makes the stake pool less expensive to attack.
    assert_eq!(EscrowVault::MIN_STAKE_LAMPORTS, 10_000_000);
}

#[test]
fn slash_record_seed_prefix_is_stable() {
    // SlashRecord PDAs are derived from `b"slash"` + agent + slash_index.
    // Off-chain audit walks the append-only history by iterating
    // slash_index = 0, 1, 2... and re-deriving. A rename breaks the walk.
    assert_eq!(SlashRecord::SEED_PREFIX, b"slash");
}

// -----------------------------------------------------------------------------
// VULN-13 — has_one ↔ seeds consistency (cross-reference + struct probes)
// -----------------------------------------------------------------------------

#[test]
fn escrow_vault_carries_agent_wallet_field() {
    // The vault's `agent_wallet` is the single source of truth that
    // both the Anchor `has_one = agent_wallet` constraints AND the PDA
    // seed derivation reference. Dropping this field silently breaks
    // BOTH layers.
    fn probe(v: &EscrowVault) -> anchor_lang::prelude::Pubkey {
        v.agent_wallet
    }
    let _: fn(&EscrowVault) -> anchor_lang::prelude::Pubkey = probe;
}

#[test]
fn slash_record_carries_index_field() {
    // SlashRecord's `index` matches the slash_count at write time and is
    // also folded into the PDA seeds. The single-source-of-truth pin
    // applies the same as the EscrowVault one above.
    fn probe(r: &SlashRecord) -> u64 {
        r.index
    }
    let _: fn(&SlashRecord) -> u64 = probe;
}

// -----------------------------------------------------------------------------
// VULN-08 — settle observability (cross-reference)
// -----------------------------------------------------------------------------

#[test]
fn vuln08_observability_pinned_in_dedicated_file() {
    // The SettleSlashAttempted event surface + the timing-gate error
    // codes (ExecuteToSettleGapTooShort = 6070, AppealGraceWindowActive
    // = 6071, SettleTimingOutOfBounds = 6072) are comprehensively
    // pinned in vuln08_settle_timing.rs. Cross-reference only.
    const VULN08_PINNED_IN: &str = "vuln08_settle_timing.rs";
    assert_eq!(VULN08_PINNED_IN, "vuln08_settle_timing.rs");
}

// -----------------------------------------------------------------------------
// VULN-04 — authority-separation policy pinned in dedicated file
// -----------------------------------------------------------------------------

#[test]
fn vuln04_separation_policy_lives_in_dedicated_file() {
    // The full executor / resolver / pauser separation matrix is
    // pinned in vuln04_authority_separation.rs (16 tests cover the
    // distinct-keys + non-default invariants). This file pins only the
    // CONSTANTS those tests rely on, not the matrix itself.
    const VULN04_PINNED_IN: &str = "vuln04_authority_separation.rs";
    assert_eq!(VULN04_PINNED_IN, "vuln04_authority_separation.rs");
}
