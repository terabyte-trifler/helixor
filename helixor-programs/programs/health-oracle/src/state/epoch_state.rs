// =============================================================================
// programs/health-oracle/src/state/epoch_state.rs
//
// EpochState — the singleton epoch counter.
//
//     seeds = ["epoch_state"]
//
// Helixor scores agents once per 24h epoch. The epoch number is what keys
// each HealthCertificate PDA (["cert", agent, epoch]) on the
// certificate-issuer program — so a single, authoritative, monotonic epoch
// counter has to live on chain.
//
// WHY A DEDICATED ACCOUNT (not a field on OracleConfig)
// -----------------------------------------------------
// OracleConfig is already deployed. Adding a field would change its size
// and force a realloc-migration of an existing account. EpochState is a
// fresh account — no migration — and gives epoch management its own clear
// home. The same reasoning the codebase used for keeping reserved cushions
// on the larger accounts.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   current_epoch                8   (u64 — the epoch currently being scored)
//   last_advanced_at             8   (i64 — unix seconds the epoch last ticked)
//   epoch_duration_seconds       8   (i64 — nominal cycle length, 86_400)
//   advance_authority           32   (Pubkey — DEPRECATED as sole-signer; see
//                                            AW-02 note below)
//   bump                         1   (u8)
//   pending_target_epoch         8   (u64 — C-01: 2-phase commit "phase 1"
//                                          target; 0 means no pending advance)
//   pending_proposed_at          8   (i64 — C-01: unix seconds the propose tx
//                                          landed; finalize delay anchors on
//                                          this)
//   pending_attester_count       1   (u8  — C-01: attesters observed at propose
//                                          time, replayed verbatim into the
//                                          finalize event)
//   pending_by_fallback          1   (u8 as bool — C-01: tier-2 liveness path
//                                          at propose time; 1 = Tier 2, 0 =
//                                          Tier 1)
//   _reserved                   14   (zeroed cushion — shrunk from 32 by the
//                                     18 bytes the C-01 pending fields claim,
//                                     so the account size is UNCHANGED)
//   TOTAL (without discriminator): 89 bytes
//
// AW-02 — `advance_authority` is NO LONGER A SOLE-SIGNER AUTHORITY
// ----------------------------------------------------------------
// The MVP and VULN-02-era code used `advance_authority` as the single key
// gating Tier-1 epoch advancement. The AW-02 audit flagged that as the
// only consensus-critical op NOT covered by the cluster's M-of-N threshold
// mechanism. AW-02 rewrites the Tier-1 path to require
// `consensus_threshold(OracleConfig.oracle_keys)` Ed25519 attestations
// over the canonical advance digest (see `advance_epoch.rs`).
//
// The field is RETAINED in the account layout for two reasons:
//   1. Account size is fixed; removing the field would force a
//      realloc-migration of the deployed singleton. Not worth the risk.
//   2. Operational forensics: ops teams may still want a "primary
//      advance-key" hint for monitoring (e.g. "did the expected node
//      participate in this tick?"). `rotate_advance_authority` remains
//      so the field can be kept current, but it no longer affects who
//      can advance.
//
// A stale or zero `advance_authority` no longer blocks epoch progression.
//
// C-01 — 2-PHASE COMMIT FOR advance_epoch
// ---------------------------------------
// The pre-C-01 design verified Tier-1 attestations (or Tier-2 fallback
// authority) and committed the epoch tick in a SINGLE transaction.
// Off-chain monitors saw the advance only AFTER it landed; there was no
// window to react if a hostile cluster member assembled a malicious
// quorum off-chain (e.g. signing a tick with a different
// `last_advanced_at` from the chain's). The audit (C-01) flagged this
// boundary race: any consensus-critical write should be observable
// BEFORE it commits.
//
// C-01 splits the ix into:
//   * `propose_advance_epoch`: runs the SAME Tier-1/Tier-2 verification
//     as before, but writes `pending_target_epoch / pending_proposed_at /
//     pending_attester_count / pending_by_fallback` to the EpochState
//     INSTEAD of mutating `current_epoch`. Emits `EpochAdvanceProposed`.
//   * `finalize_advance_epoch`: refuses until
//     `now >= pending_proposed_at + FINALIZE_DELAY_SECONDS`, then commits
//     the pending target into `current_epoch`, clears the pending fields,
//     emits the canonical `EpochAdvanced` + tier-specific event.
//
// During the finalize-delay window, observers can issue a `cancel_*`
// path (left as a follow-on; not in this commit) or stage a competing
// propose tx (which `propose_advance_epoch` will accept after
// `PROPOSE_OVERWRITE_DELAY_SECONDS` of staleness). The delay is the
// observability budget; the staleness window stops a stuck pending
// state from indefinitely blocking forward progress.
//
// The pending fields are RECLAIMED from the 32-byte `_reserved` cushion —
// the on-disk SlashConfig size does NOT grow, so no realloc-migration of
// the deployed singleton is needed.
// =============================================================================

use anchor_lang::prelude::*;

/// C-01: the minimum delay between a `propose_advance_epoch` tx landing
/// and the matching `finalize_advance_epoch` tx becoming acceptable.
/// 30 seconds (~75 Solana slots): long enough that off-chain monitors
/// can react inside the window, short enough that the legitimate ops
/// path adds only one extra tx and one extra short wait per 24h
/// epoch tick.
pub const FINALIZE_DELAY_SECONDS: i64 = 30;

/// C-01: how long a `propose_advance_epoch` proposal stays "fresh"
/// before another proposer may overwrite it without waiting. 1 hour.
/// Without this, a propose tx that never gets a matching finalize (e.g.
/// because the proposer crashed) would deadlock the next tick forever.
/// 1h leaves room for human intervention while keeping the ops loop
/// bounded.
pub const PROPOSE_OVERWRITE_DELAY_SECONDS: i64 = 60 * 60;

#[account]
#[derive(Default, Debug)]
pub struct EpochState {
    /// The epoch currently being scored. Epochs are 1-indexed: the account
    /// is initialised with current_epoch = 1.
    pub current_epoch:          u64,
    /// Unix seconds when the epoch was last advanced.
    pub last_advanced_at:       i64,
    /// The nominal epoch length in seconds (86_400 = 24h). Carried on-chain
    /// so the advance instruction can enforce "not too early".
    pub epoch_duration_seconds: i64,
    /// HISTORICAL primary-advancer hint.
    ///
    /// AW-02: NO LONGER a sole-signer authority. Retained for layout
    /// compatibility and operational forensics. Tier-1 advance now
    /// requires M-of-N cluster Ed25519 attestations (see
    /// `advance_epoch.rs`). Tier-2 liveness fallback gates on cluster
    /// membership, NOT on this field.
    pub advance_authority:      Pubkey,
    /// Canonical PDA bump.
    pub bump:                   u8,
    /// C-01: the target epoch staged by `propose_advance_epoch`. Zero
    /// means no pending advance — `finalize_advance_epoch` refuses
    /// with `NoPendingAdvance`. A non-zero value is ALWAYS
    /// `current_epoch + 1` at the moment of propose; the finalize
    /// handler re-checks this to defend against a `current_epoch`
    /// mutation between propose and finalize that drifted the target.
    pub pending_target_epoch:   u64,
    /// C-01: unix seconds when the matching `propose_advance_epoch` tx
    /// landed. Finalize anchors on this — refused until
    /// `now >= pending_proposed_at + FINALIZE_DELAY_SECONDS`. Also the
    /// staleness anchor for `PROPOSE_OVERWRITE_DELAY_SECONDS`. Zero
    /// when no proposal is in flight.
    pub pending_proposed_at:    i64,
    /// C-01: the attester count observed at propose time. Replayed
    /// verbatim into the finalize event so off-chain consumers see one
    /// consistent count across the propose/finalize pair. Tier-1
    /// proposals carry the actual cluster-attester count; Tier-2
    /// fallback proposals carry 1 (the solo cluster-member submitter).
    pub pending_attester_count: u8,
    /// C-01: tier marker for the in-flight proposal. 1 = Tier 2
    /// (liveness fallback); 0 = Tier 1 (M-of-N threshold). Drives the
    /// tier-specific event emitted at finalize time, so a Tier-2
    /// tick remains visible to ops monitors as a degraded-mode tick
    /// EVEN AFTER it has been finalised through the 2-phase pattern.
    pub pending_by_fallback:    u8,
    /// Zero-padded reserve. Shrunk from 32 to 14 — the 18 bytes the
    /// four `pending_*` fields claim are reclaimed from this cushion
    /// so the on-disk EpochState size is UNCHANGED (no PDA realloc
    /// migration on existing deployments).
    pub _reserved:              [u8; 14],
}

impl EpochState {
    /// The first epoch. Epochs are 1-indexed — epoch 0 is "never scored".
    pub const FIRST_EPOCH: u64 = 1;

    /// The default epoch duration: 24 hours.
    pub const DEFAULT_DURATION_SECONDS: i64 = 86_400;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    ///   8 + 8 + 8 + 32 + 1 + 8 + 8 + 1 + 1 + 14 = 89
    pub const SPACE: usize = 8 + 8 + 8 + 8 + 32 + 1 + 8 + 8 + 1 + 1 + 14;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"epoch_state";

    /// Whether enough time has elapsed for the epoch to advance.
    ///
    /// Pure — extracted so it is unit-testable without a runtime. A small
    /// grace margin is NOT applied here; the caller decides whether to
    /// allow early advance (e.g. an admin override).
    pub fn may_advance(&self, now: i64) -> bool {
        now.saturating_sub(self.last_advanced_at) >= self.epoch_duration_seconds
    }

    /// Whether the liveness-fallback window is open.
    ///
    /// The fallback allows ANY cluster oracle key to advance the epoch when
    /// `advance_authority` has been unavailable for at least 2× the epoch
    /// duration. This prevents a single lost or compromised key from
    /// permanently halting epoch progression and cert issuance.
    ///
    /// Invariant: `liveness_fallback_elapsed` ⟹ `may_advance`.
    /// (Two durations elapsed always implies one duration elapsed.)
    pub fn liveness_fallback_elapsed(&self, now: i64) -> bool {
        let double = self.epoch_duration_seconds.saturating_mul(2);
        now.saturating_sub(self.last_advanced_at) >= double
    }

    /// C-01: is a `propose_advance_epoch` proposal currently in flight?
    /// True iff the propose handler has staged a non-zero target since
    /// the last finalize (or since genesis). The check is decoupled from
    /// freshness; see `pending_advance_is_stale` for the
    /// PROPOSE_OVERWRITE_DELAY_SECONDS gate.
    pub fn has_pending_advance(&self) -> bool {
        self.pending_target_epoch != 0
    }

    /// C-01: has the finalize-delay window elapsed for the in-flight
    /// proposal? Returns false when no proposal is staged (genesis or
    /// a freshly cleared pending). The handler additionally checks
    /// `has_pending_advance` — this predicate is only the time-axis
    /// check.
    pub fn pending_advance_ready(&self, now: i64) -> bool {
        self.has_pending_advance()
            && now
                >= self
                    .pending_proposed_at
                    .saturating_add(FINALIZE_DELAY_SECONDS)
    }

    /// C-01: may a new `propose_advance_epoch` tx OVERWRITE the existing
    /// pending proposal? True iff no pending exists OR the existing
    /// pending is older than `PROPOSE_OVERWRITE_DELAY_SECONDS`. This
    /// stops a stuck pending state from indefinitely blocking the next
    /// tick while still preventing a hostile spammer from flapping the
    /// proposal back-and-forth inside the finalize window.
    pub fn pending_overwrite_allowed(&self, now: i64) -> bool {
        if !self.has_pending_advance() {
            return true;
        }
        now >= self
            .pending_proposed_at
            .saturating_add(PROPOSE_OVERWRITE_DELAY_SECONDS)
    }

    /// C-01: clear all pending-advance fields. Called from
    /// `finalize_advance_epoch` after the mutation commits, and from
    /// `propose_advance_epoch` immediately before staging a new
    /// proposal that legitimately overwrites a stale one.
    pub fn clear_pending_advance(&mut self) {
        self.pending_target_epoch   = 0;
        self.pending_proposed_at    = 0;
        self.pending_attester_count = 0;
        self.pending_by_fallback    = 0;
    }
}
