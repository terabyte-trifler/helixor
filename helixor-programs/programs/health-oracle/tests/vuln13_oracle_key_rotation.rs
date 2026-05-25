// =============================================================================
// programs/health-oracle/tests/vuln13_oracle_key_rotation.rs
//
// VULN-13 pin tests — time-locked, N-of-M-attested oracle key rotation.
//
// These tests pin the PURE state-machine logic that backs the four
// instructions (propose / attest / enact / cancel). Runtime-level handler
// behaviour (account writes, CPI, rent refund on `close`) is exercised by
// the TypeScript integration suite; this file is the isolation layer that
// monitors against regressions to the audit-critical invariants:
//
//   1. The timelock floor is exactly 48 hours.
//   2. The enact gate requires BOTH the timelock elapsed AND a strict
//      majority of the LIVE cluster to have attested.
//   3. Attestation count requirement is computed against the CURRENT
//      cluster, not the proposed cluster (otherwise a hostile proposal
//      could "self-attest" with the proposed keys).
//   4. The error codes used by the four instructions are stable.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use health_oracle::errors::HelixorError;
use health_oracle::state::{OracleConfig, PendingOracleRotation};

fn pending_with(
    attestation_count: usize,
    enact_after:       i64,
) -> PendingOracleRotation {
    PendingOracleRotation {
        proposer:           Pubkey::new_unique(),
        new_keys:           (0..3).map(|_| Pubkey::new_unique()).collect(),
        new_min_confidence: 600,
        enact_after,
        attestations:       (0..attestation_count).map(|_| Pubkey::new_unique()).collect(),
        proposed_at:        0,
        bump:               0,
    }
}

// =============================================================================
// Timelock floor — audit-mandated 48h minimum
// =============================================================================

#[test]
fn min_timelock_is_48_hours() {
    // Audit-mandated: at least 48h between propose and enact so operators
    // monitoring the chain have time to detect a hostile proposal.
    assert_eq!(PendingOracleRotation::MIN_TIMELOCK_SECONDS, 48 * 60 * 60);
    assert_eq!(PendingOracleRotation::MIN_TIMELOCK_SECONDS, 172_800);
}

// =============================================================================
// Layout — account size reserves room for max cluster + max attestations
// =============================================================================

#[test]
fn space_reserves_room_for_max_cluster_plus_attestations() {
    //   8 disc + 32 proposer
    // + 4 Vec prefix + 32*5 reserved key slots
    // + 2 new_min_confidence + 8 enact_after
    // + 4 Vec prefix + 32*5 reserved attestation slots
    // + 8 proposed_at + 1 bump
    let expected = 8 + 32 + 4 + (32 * 5) + 2 + 8 + 4 + (32 * 5) + 8 + 1;
    assert_eq!(PendingOracleRotation::SPACE, expected);
    assert_eq!(PendingOracleRotation::SPACE, 387);
}

#[test]
fn seed_is_stable() {
    // Singleton — only one in-flight rotation at a time. Seed pin guards
    // against accidental rename that would break enact / cancel.
    assert_eq!(PendingOracleRotation::SEED, b"pending_rotation");
}

// =============================================================================
// has_attestation — duplicate-vote protection
// =============================================================================

#[test]
fn has_attestation_recognises_recorded_attester() {
    let mut pending = pending_with(0, 0);
    let k = Pubkey::new_unique();
    assert!(!pending.has_attestation(&k));
    pending.attestations.push(k);
    assert!(pending.has_attestation(&k));
}

#[test]
fn has_attestation_rejects_unrelated_key() {
    let pending = pending_with(3, 0);
    // None of the three stored keys is `Pubkey::new_unique()`.
    assert!(!pending.has_attestation(&Pubkey::new_unique()));
}

// =============================================================================
// is_enactable — BOTH timelock AND threshold gates
// =============================================================================

#[test]
fn enact_blocked_before_timelock_even_with_full_quorum() {
    // 3-of-3 attestations but the timelock has not elapsed → blocked.
    let pending = pending_with(3, 1_000_000);
    assert!(!pending.is_enactable(999_999, 3));
}

#[test]
fn enact_blocked_with_insufficient_attestations_after_timelock() {
    // Timelock elapsed but only 1-of-3 attested → blocked.
    let pending = pending_with(1, 1_000);
    assert!(!pending.is_enactable(10_000, 3));
}

#[test]
fn enact_allowed_with_both_gates_satisfied_3_of_3() {
    let pending = pending_with(3, 1_000);
    assert!(pending.is_enactable(10_000, 3));
}

#[test]
fn enact_allowed_at_exact_boundary() {
    // The audit-mandated comparator is `now >= enact_after`. The exact
    // boundary should enact, not block — pinning this guards against an
    // off-by-one that would push real rotations a slot past their intended
    // landing time.
    let pending = pending_with(3, 1_000);
    assert!(pending.is_enactable(1_000, 3));
}

#[test]
fn enact_allowed_with_2_of_3_strict_majority() {
    // 2-of-3 is the minimum majority for a 3-node cluster.
    let pending = pending_with(2, 1_000);
    assert!(pending.is_enactable(10_000, 3));
}

#[test]
fn enact_allowed_with_3_of_5() {
    // 3-of-5 is the minimum majority for a 5-node cluster (tolerates 2 faults).
    let pending = pending_with(3, 1_000);
    assert!(pending.is_enactable(10_000, 5));
}

#[test]
fn enact_blocked_with_2_of_5() {
    // 2-of-5 is NOT a majority of the 5-node cluster — must block.
    let pending = pending_with(2, 1_000);
    assert!(!pending.is_enactable(10_000, 5));
}

#[test]
fn enact_allowed_for_single_node_cluster_with_one_attestation() {
    // The degenerate 1-node deployment: threshold is 1, so the single
    // cluster member attesting suffices. Documented audit weakness of
    // single-node deployments; not introduced by VULN-13.
    let pending = pending_with(1, 1_000);
    assert!(pending.is_enactable(10_000, 1));
}

// =============================================================================
// Threshold uses CURRENT cluster, not proposed cluster
// =============================================================================

#[test]
fn threshold_computed_against_current_cluster_not_new_keys_len() {
    // The proposal carries `new_keys` (which the test factory fills with 3
    // entries) but the THRESHOLD is computed against the CURRENT cluster
    // size passed by the caller. This is critical: otherwise a compromised
    // admin could propose a 1-key cluster and need only 1 attestation
    // (which the proposer's pre-attestation already supplies).
    let pending = pending_with(2, 1_000);
    // Current cluster size 5 → need 3 attestations; only 2 present → blocked.
    assert!(!pending.is_enactable(10_000, 5));
    // Current cluster size 3 → need 2 attestations; 2 present → allowed.
    assert!(pending.is_enactable(10_000, 3));
}

// =============================================================================
// attestations_remaining — UI / RPC convenience
// =============================================================================

#[test]
fn attestations_remaining_for_partial_quorum() {
    let pending = pending_with(1, 0);
    // Cluster of 3 needs 2; one attestation present → 1 more needed.
    assert_eq!(pending.attestations_remaining(3), 1);
}

#[test]
fn attestations_remaining_saturates_at_zero_when_quorum_met() {
    let pending = pending_with(3, 0);
    // Threshold for 3 nodes is 2; we have 3 → saturate to 0 (not -1).
    assert_eq!(pending.attestations_remaining(3), 0);
}

#[test]
fn attestations_remaining_for_max_cluster() {
    let pending = pending_with(0, 0);
    // 5-node cluster, 0 attestations → need 3 more.
    assert_eq!(pending.attestations_remaining(5), 3);
}

// =============================================================================
// Cross-check: VULN-13 threshold matches OracleConfig::consensus_threshold
// =============================================================================

#[test]
fn vuln13_threshold_matches_oracleconfig_consensus_threshold() {
    // The audit requirement is that VULN-13 enact uses the SAME consensus
    // rule as the rest of the protocol — a strict majority of the live
    // cluster. If these two ever drift apart, off-chain monitors that read
    // `consensus_threshold` to predict landing will be wrong.
    for n in 1..=5 {
        let cfg = OracleConfig {
            authority:      Pubkey::default(),
            oracle_node:    Pubkey::default(),
            oracle_keys:    (0..n).map(|_| Pubkey::new_unique()).collect(),
            min_confidence: 0,
            bump:           0,
        };
        let pending = pending_with(cfg.consensus_threshold(), 0);
        assert!(
            pending.is_enactable(0, n),
            "VULN-13 threshold disagreed with consensus_threshold for n={n}",
        );
    }
}

// =============================================================================
// Error-code stability — surface contract for off-chain decoders
// =============================================================================

#[test]
fn vuln13_error_codes_are_stable() {
    assert_eq!(HelixorError::NotRotationProposer       as u32, 6060);
    assert_eq!(HelixorError::NotClusterMemberAttester  as u32, 6061);
    assert_eq!(HelixorError::TimelockTooShort          as u32, 6062);
    assert_eq!(HelixorError::PendingRotationExists     as u32, 6063);
    assert_eq!(HelixorError::NoopRotation              as u32, 6064);
    assert_eq!(HelixorError::TimelockNotElapsed        as u32, 6065);
    assert_eq!(HelixorError::InsufficientAttestations  as u32, 6066);
    assert_eq!(HelixorError::DuplicateAttestation      as u32, 6067);
    assert_eq!(HelixorError::OracleConfigMismatch      as u32, 6068);
}
