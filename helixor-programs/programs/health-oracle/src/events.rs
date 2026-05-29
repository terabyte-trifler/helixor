// =============================================================================
// programs/health-oracle/src/events.rs
//
// Anchor events emitted by commit_baseline. The off-chain indexer captures
// these into the append-only `baseline_commit_log` table — that gives us a
// full HISTORY of every commit even though the on-chain account only stores
// the latest.
// =============================================================================

use anchor_lang::prelude::*;

#[event]
pub struct BaselineCommitted {
    /// The monitored agent's wallet.
    pub agent_wallet:           Pubkey,
    /// The committer pubkey (oracle node or agent owner).
    pub committer:              Pubkey,
    /// The new committed hash.
    pub baseline_hash:          [u8; 32],
    /// Algorithm version that produced this hash.
    pub baseline_algo_version:  u8,
    /// New nonce value (= previous + 1, by the monotonicity rule).
    pub commit_nonce:           u64,
    /// Unix seconds (Clock::get().unix_timestamp).
    pub committed_at:           i64,
    /// True if this is the first commit for this agent.
    pub first_commit:           bool,
    /// "oracle" or "owner". Convenience for downstream indexers.
    pub committer_kind:         CommitterKind,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitterKind {
    Oracle,
    Owner,
}

// =============================================================================
// VULN-10: BaselineRotated — fired on every NON-FIRST commit so an agent
// owner's off-chain monitor can page on a rotation.
//
// `BaselineCommitted` is the canonical commit event; `BaselineRotated` is
// the SUPERSET-of-info event tailored to "the baseline that the network
// has been using just changed". It carries the FULL previous state so
// the monitor can show a diff without joining the indexer log.
//
// The owner detects an unexpected rotation (e.g. a compromised oracle
// node rotating to a stale-favorable hash) within seconds of the event
// landing, and uses the owner-override path on commit_baseline to
// re-rotate to the correct hash immediately (the owner path bypasses
// the oracle cooldown).
// =============================================================================

#[event]
pub struct BaselineRotated {
    pub agent_wallet:                 Pubkey,
    pub committer:                    Pubkey,
    pub committer_kind:               CommitterKind,
    /// The hash AFTER this commit.
    pub new_baseline_hash:            [u8; 32],
    /// The hash this rotation REPLACED.
    pub previous_baseline_hash:       [u8; 32],
    /// Who wrote the previous baseline.
    pub previous_committer:           Pubkey,
    /// Unix seconds the previous baseline was committed.
    pub previous_committed_at:        i64,
    /// The previous commit_nonce — pairs with the new one in this event.
    pub previous_commit_nonce:        u64,
    /// The new commit_nonce.
    pub new_commit_nonce:             u64,
    /// Seconds between the previous and current commit. The owner's
    /// monitor uses this to spot a too-fast rotation (a real rotation
    /// is typically 30 days; one a few seconds after the last is the
    /// smoking gun).
    pub seconds_since_previous:       i64,
    pub rotated_at:                   i64,
}

#[event]
pub struct RegistrationMigrated {
    pub agent_wallet:    Pubkey,
    pub from_version:    u8,
    pub to_version:      u8,
    pub migrated_at:     i64,
}

// ── AW-03: on-chain baseline data-availability proof ───────────────────────
// `BaselineDataPublished` is emitted alongside `BaselineCommitted` and
// carries the LOCATOR for the on-chain `BaselineDataAccount` whose payload
// bytes were just published. A DeFi consumer / off-chain indexer can index
// on this event, fetch the `baseline_data_pubkey` account, and verify
// `sha256(account.payload) == baseline_hash` — the audit gate the AW-03
// finding asked for. `payload_len` lets monitors gate on suspicious sizes
// (a sudden 30-byte baseline is a smoking gun).

#[event]
pub struct BaselineDataPublished {
    /// The monitored agent.
    pub agent_wallet:           Pubkey,
    /// The commit_nonce this DA account is keyed under — pairs with
    /// `BaselineCommitted.commit_nonce`.
    pub commit_nonce:           u64,
    /// The 32-byte SHA-256 over the published payload. Equal to the new
    /// `AgentRegistration.baseline_hash`.
    pub baseline_hash:          [u8; 32],
    /// Algorithm version that produced the payload + hash.
    pub baseline_algo_version:  u8,
    /// The PDA address of the new `BaselineDataAccount`. Consumers fetch
    /// this account to read the canonical payload and re-verify the hash.
    pub baseline_data_pubkey:   Pubkey,
    /// Length of the published payload in bytes. Monitors gate on this.
    pub payload_len:            u32,
    /// The committer (oracle or owner) — mirrors `BaselineCommitted`.
    pub committer:              Pubkey,
    /// Unix seconds when the payload was published (Clock::get()).
    pub published_at:           i64,
}

// ── Day 19: epoch + score submission events ─────────────────────────────────

/// Emitted when the epoch counter ticks at the end of a 24h cycle.
#[event]
pub struct EpochAdvanced {
    pub from_epoch:  u64,
    pub to_epoch:    u64,
    pub advanced_at: i64,
}

/// Emitted when the oracle submits an agent's epoch score. The certificate
/// itself is written by the CPI into certificate-issuer; this is the
/// oracle-side record of the submission.
#[event]
pub struct ScoreSubmitted {
    pub agent_wallet:  Pubkey,
    pub epoch:         u64,
    pub score:         u16,
    pub alert_tier:    u8,
    pub flags:         u32,
    pub immediate_red: bool,
    pub oracle:        Pubkey,
    pub submitted_at:  i64,
}

/// M-13: emitted on every successful `submit_score` AFTER the
/// SubmitScoreEscrow PDA is funded above the floor. The event carries
/// the locator (escrow pubkey) so an off-chain consumer can fetch the
/// PDA, the deposited amount, and the post-funding balance — all the
/// fields a forensic auditor needs to confirm the per-submission
/// economic floor was paid without re-deriving the PDA or reading the
/// account separately.
#[event]
pub struct SubmitScoreEscrowFunded {
    /// The per-(agent, epoch) SubmitScoreEscrow PDA address.
    pub escrow:               Pubkey,
    pub agent_wallet:         Pubkey,
    pub epoch:                u64,
    /// The oracle node that funded the escrow.
    pub oracle:               Pubkey,
    /// Lamports transferred from oracle to escrow ABOVE the rent-exempt
    /// minimum. Equal to the M-13 floor at minimum; may be larger if
    /// the oracle voluntarily over-deposits.
    pub deposited_lamports:   u64,
    /// The total escrow balance after the transfer (= rent_exempt(SPACE)
    /// + deposited_lamports). Off-chain auditors compare this against
    /// the PDA's `lamports()` at any later slot to detect a drain.
    pub escrow_balance_after: u64,
    pub funded_at:            i64,
}

/// Emitted by get_health — surfaces an agent's current-epoch certificate.
#[event]
pub struct HealthRead {
    pub agent_wallet:  Pubkey,
    pub epoch:         u64,
    pub score:         u16,
    pub alert_tier:    u8,
    pub flags:         u32,
    pub immediate_red: bool,
    pub issued_at:     i64,
}

/// Emitted when the liveness-fallback path triggers an epoch advance.
/// Emitted IN ADDITION TO `EpochAdvanced` so consumers can distinguish
/// normal oracle advances from fallback-cluster advances.
#[event]
pub struct EpochAdvancedByFallback {
    pub from_epoch:  u64,
    pub to_epoch:    u64,
    pub advanced_at: i64,
    /// The cluster key that triggered the fallback advance.
    pub cluster_key: Pubkey,
}

/// AW-02: emitted when the normal M-of-N threshold path advances the epoch.
/// Emitted IN ADDITION TO `EpochAdvanced`. Downstream consumers use this to
/// confirm a healthy multi-attester tick (versus the degraded
/// `EpochAdvancedByFallback` event, which indicates the cluster could not
/// assemble quorum and the liveness fallback fired).
///
/// `attester_count` lets monitoring distinguish "just made quorum" (count
/// equals threshold) from "comfortable supermajority" — a slow trend toward
/// the floor is an early warning that a node has dropped out without
/// triggering the full fallback.
#[event]
pub struct EpochAdvancedByThreshold {
    pub from_epoch:     u64,
    pub to_epoch:       u64,
    pub advanced_at:    i64,
    /// Distinct cluster signers counted on this advance.
    pub attester_count: u8,
    /// The tx submitter / fee payer. Has no sole-signer privilege; recorded
    /// for operational forensics only (who pushed the tx through).
    pub submitter:      Pubkey,
}

/// Emitted when the admin rotates the advance_authority key.
#[event]
pub struct AdvanceAuthorityRotated {
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
    pub rotated_by:    Pubkey,
    pub rotated_at:    i64,
}

// ── VULN-13: oracle key rotation governance events ──────────────────────────
// These events are the canonical timeline for an off-chain "rotation watcher"
// to alert on. Operators MUST alert on any `OracleRotationProposed` whose
// `proposer` is unexpected, and on any `OracleRotationEnacted` that was not
// preceded by the team's own internal rotation runbook.

/// Emitted when a new oracle-key-rotation proposal is created.
#[event]
pub struct OracleRotationProposed {
    pub proposer:           Pubkey,
    pub new_keys:           Vec<Pubkey>,
    pub new_min_confidence: u16,
    pub enact_after:        i64,
    pub proposed_at:        i64,
}

/// Emitted on each cluster-member attestation. A rotation that lands
/// `consensus_threshold(cluster)` of these is eligible to enact once the
/// timelock has elapsed.
#[event]
pub struct OracleRotationAttested {
    pub attester:                 Pubkey,
    pub total_attestations:       u8,
    pub required_attestations:    u8,
    pub attested_at:              i64,
}

/// Emitted on a successful enact. Carries the FULL diff so an indexer can
/// snapshot the cluster transition without joining other events.
#[event]
pub struct OracleRotationEnacted {
    pub enactor:            Pubkey,
    pub old_keys:           Vec<Pubkey>,
    pub new_keys:           Vec<Pubkey>,
    pub old_min_confidence: u16,
    pub new_min_confidence: u16,
    pub enacted_at:         i64,
}

/// Emitted on cancellation. The proposal is dropped and the rent returned
/// to the original proposer.
#[event]
pub struct OracleRotationCancelled {
    pub cancelled_by: Pubkey,
    pub proposer:     Pubkey,
    pub cancelled_at: i64,
}
