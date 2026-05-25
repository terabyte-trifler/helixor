// =============================================================================
// programs/health-oracle/src/state/pending_oracle_rotation.rs
//
// VULN-13 MITIGATION — time-locked, N-of-M-attested oracle key rotation.
//
// THE AUDIT FINDING (paraphrased)
// -------------------------------
// CRITICAL. If `OracleConfig.oracle_keys` could be replaced by a single
// admin signature, then any admin-key compromise would let the attacker
// substitute their own 5 cluster keys and immediately issue perfect GREEN
// certificates for any agent — and DeFi protocols, validating signatures
// against the on-chain cluster set, would honour them.
//
// THE PROTOCOL
// ------------
// The fix removes "admin alone" as a path that can rewrite cluster
// membership. Instead, key rotation is a two-phase, time-locked,
// N-of-M-attested ceremony driven through this PDA:
//
//   1. PROPOSE — admin OR any existing cluster member submits a
//      `PendingOracleRotation { new_keys, new_min_confidence, enact_after,
//      proposer, attestations }` with `enact_after = now + timelock_seconds`,
//      where `timelock_seconds >= MIN_TIMELOCK_SECONDS` (48h).
//
//   2. ATTEST — each existing cluster member submits their signature.
//      Only signatures from CURRENT `OracleConfig.oracle_keys` count
//      toward consensus.
//
//   3. ENACT — any signer may enact the proposal once both
//      gates are satisfied:
//         a) `now >= enact_after`         (the timelock has elapsed), and
//         b) `attestations.len() >= consensus_threshold(current_cluster)`
//            (a strict majority of the CURRENT cluster has attested).
//      Enactment applies `new_keys` + `new_min_confidence` to
//      `OracleConfig`, closes this PDA, and returns the rent to the
//      original proposer.
//
//   4. CANCEL — admin OR any current cluster member may cancel a pending
//      proposal at any time before enactment (defence in depth: a
//      compromised proposer cannot force the proposal through if the
//      honest cluster majority vetoes by cancelling).
//
// WHAT THIS DOES NOT FIX
// ----------------------
// `OracleConfig.authority` and the program-upgrade authority are still
// single keys; the audit's "Phase-0 Squads vault" is the infrastructure
// answer to those (out-of-band, in deployment ops). What this file fixes
// is the on-chain code path: even a fully-compromised admin key cannot
// rewrite the oracle cluster on its own. The cluster keys must consent
// AND a 48-hour public review window must elapse first.
//
// SIZING
// ------
// One PDA per in-flight rotation (singleton — `seeds = ["pending_rotation"]`).
// Only one proposal may exist at a time; a second propose is rejected until
// the first is enacted or cancelled. Both `new_keys` and `attestations` are
// bounded by `OracleConfig::MAX_ORACLE_KEYS` (5), so the account size is
// fixed at creation.
// =============================================================================

use anchor_lang::prelude::*;

use crate::state::OracleConfig;

#[account]
#[derive(Default, Debug)]
pub struct PendingOracleRotation {
    /// The pubkey that submitted this proposal (admin OR a cluster member).
    /// Used as the rent-refund target on enact / cancel.
    pub proposer:                 Pubkey,
    /// Proposed new cluster keys. Validated at PROPOSE time AND re-validated
    /// at ENACT time as defence in depth (the cluster could change between
    /// the two if a different rotation enacted first, though the singleton
    /// PDA guard makes that impossible — kept anyway).
    pub new_keys:                 Vec<Pubkey>,
    /// Proposed new `min_confidence`. May equal the current value.
    pub new_min_confidence:       u16,
    /// Unix timestamp at which this proposal becomes enactable. Set at
    /// PROPOSE time = `now + timelock_seconds`, where `timelock_seconds`
    /// is supplied by the proposer with a floor of `MIN_TIMELOCK_SECONDS`.
    pub enact_after:              i64,
    /// Existing cluster members who have signed off on the rotation.
    /// Bounded by `OracleConfig::MAX_ORACLE_KEYS`. Only members of the
    /// CURRENT cluster (at attest-time) may attest, and double-attestation
    /// is rejected.
    pub attestations:             Vec<Pubkey>,
    /// Unix timestamp the proposal was submitted. Carried for off-chain
    /// indexers + audit-log replay; not consulted by enact gating.
    pub proposed_at:              i64,
    /// Canonical PDA bump.
    pub bump:                     u8,
}

impl PendingOracleRotation {
    /// The audit-recommended minimum review window before a key-rotation
    /// proposal becomes enactable: 48 hours. Operators monitoring the
    /// chain have at least this long to detect a hostile proposal and
    /// vetoes it via the cancel path.
    pub const MIN_TIMELOCK_SECONDS: i64 = 48 * 60 * 60;

    /// The PDA seed. Only one in-flight rotation at a time.
    pub const SEED: &'static [u8] = b"pending_rotation";

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    ///
    ///   8  discriminator
    /// + 32 proposer
    /// + 4  new_keys length prefix
    /// + 32 * MAX_ORACLE_KEYS         (reserved key slots)
    /// + 2  new_min_confidence
    /// + 8  enact_after
    /// + 4  attestations length prefix
    /// + 32 * MAX_ORACLE_KEYS         (reserved attestation slots)
    /// + 8  proposed_at
    /// + 1  bump
    pub const SPACE: usize =
        8 + 32
        + 4 + (32 * OracleConfig::MAX_ORACLE_KEYS)
        + 2 + 8
        + 4 + (32 * OracleConfig::MAX_ORACLE_KEYS)
        + 8 + 1;

    /// Whether `key` has already attested to this proposal.
    pub fn has_attestation(&self, key: &Pubkey) -> bool {
        self.attestations.contains(key)
    }

    /// Whether this proposal is enactable at `now` against an oracle cluster
    /// of size `cluster_len`. Pure — exported for unit tests.
    ///
    /// Gates:
    ///   - the timelock has elapsed:   `now >= self.enact_after`
    ///   - a strict majority of the CURRENT cluster has attested:
    ///     `attestations.len() >= floor(cluster_len / 2) + 1`
    ///
    /// Caller (the `enact` handler) supplies `cluster_len` from the live
    /// `OracleConfig` at enact time so the threshold is computed against
    /// the cluster that exists NOW, not the cluster that existed at
    /// propose time.
    pub fn is_enactable(&self, now: i64, cluster_len: usize) -> bool {
        let threshold = cluster_len / 2 + 1;
        now >= self.enact_after && self.attestations.len() >= threshold
    }

    /// Convenience for tests / RPC consumers: how many more attestations are
    /// needed to clear the consensus gate against a cluster of `cluster_len`
    /// nodes. Saturates at 0 once the threshold is reached.
    pub fn attestations_remaining(&self, cluster_len: usize) -> usize {
        let threshold = cluster_len / 2 + 1;
        threshold.saturating_sub(self.attestations.len())
    }
}
