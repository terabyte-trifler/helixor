// =============================================================================
// programs/health-oracle/src/state/submit_score_escrow.rs
//
// M-13 — SubmitScoreEscrow PDA: per-(agent, epoch) anti-griefing rent escrow.
//
// THE PROBLEM THE AUDIT FLAGGED
// -----------------------------
// `submit_score` is authority-gated to the configured `oracle_node` — only
// the cluster's primary key can call it. That is the right authorization
// check, but it is NOT an economic check. A misconfigured oracle script
// running in a tight loop (or a compromised oracle key) can spam
// `submit_score` at the cost of only the base tx fee (~5_000 lamports), and
// every spam call consumes a non-trivial chunk of program compute + ledger
// space writing the cert + score-components accounts via the CPI. The base
// tx fee on its own is too small to deter that pattern at scale; the audit
// asked for a SIGNAL FLOOR — a per-submission economic cost the oracle
// cannot avoid that materially exceeds the base tx fee.
//
// THE FIX
// -------
// On every `submit_score` call the oracle MUST init a per-(agent, epoch)
// `SubmitScoreEscrow` PDA and deposit a minimum of
// `MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS` lamports above the rent-exempt
// minimum. The PDA is owned by health-oracle; its rent + extra deposit are
// LOCKED in the account for the lifetime of the protocol's M-13 phase (no
// refund / drain instruction is added in M-13 — that is intentionally
// scoped to a follow-up so the lamports remain at risk as a genuine
// economic floor right now). A future M-XX may introduce a
// `slash_submit_escrow` / `close_submit_escrow` path that conditionally
// recovers or burns the deposit; the M-13 contract is just the floor.
//
// PDA SEEDS
// ---------
//     ["submit_score_escrow", agent_wallet, epoch_le]
//
// The (agent, epoch) seeding makes the PDA write-once for that pairing —
// `init` fails if the PDA already exists, so a repeat submission for the
// same (agent, epoch) fails at the account level the same way the cert
// itself does. This is parallel to the certificate PDA's lifecycle.
//
// WHY NOT A SINGLE PROGRAM-LEVEL TREASURY?
// ----------------------------------------
// A single shared treasury PDA would also impose a per-submission cost
// (the system::transfer), but it would not give the protocol a per-
// submission AUDIT TRAIL: every escrow is independently fetchable by
// (agent, epoch), so an off-chain monitor can correlate "no escrow ⇒ no
// honest submission" without parsing aggregate logs. The per-submission
// PDA is the canonical Solana pattern for "the action happened" markers,
// and is what the M-13 fix uses.
//
// CONFIGURABILITY
// ---------------
// The floor is intentionally a program CONSTANT in M-13, not a value on
// OracleConfig. Adding it to OracleConfig would require a layout grow +
// realloc + migration, which is a much bigger surface to ship for a
// single-value knob. If operations needs to retune the floor later, the
// follow-up that adds the slash / close path can also lift the value
// onto OracleConfig.
// =============================================================================

use anchor_lang::prelude::*;

/// M-13 — the per-submission economic floor above the rent-exempt minimum.
/// The oracle MUST `system::transfer` AT LEAST this many lamports from
/// itself into the SubmitScoreEscrow PDA, in addition to the rent the
/// `init` payer covers. Chosen as 0.001 SOL (1_000_000 lamports) — three
/// orders of magnitude above the base tx fee (~5_000), small enough that
/// honest oracle ops are unaffected at the per-submission level, large
/// enough that a runaway script burns SOL meaningfully per call.
pub const MIN_SUBMIT_ESCROW_DEPOSIT_LAMPORTS: u64 = 1_000_000;

/// SubmitScoreEscrow — a write-once per-(agent, epoch) PDA whose lamport
/// balance is the per-submission economic floor. The account body is
/// metadata only; the lamports themselves are the floor.
#[account]
#[derive(Default, Debug)]
pub struct SubmitScoreEscrow {
    /// The agent the originating submission scored. Pinned in the body
    /// (not just in the seeds) so an off-chain consumer reading only the
    /// account bytes can attribute the escrow without re-deriving the PDA.
    pub agent_wallet:         Pubkey,
    /// The epoch the originating submission covers — same rationale.
    pub epoch:                u64,
    /// The oracle node that funded the escrow. Pinned for forensic
    /// attribution: if the floor is ever slashed in a future M-XX, the
    /// rotation history is recoverable from this field plus
    /// `OracleConfig` snapshots.
    pub oracle:               Pubkey,
    /// Unix seconds the escrow was funded — the original submit_score
    /// timestamp. The on-chain clock value, not a client-supplied one.
    pub deposited_at:         i64,
    /// The lamport amount transferred above the rent-exempt minimum at
    /// `submit_score` time. The full escrow balance is
    /// `account.lamports() == rent_exempt(SPACE) + deposited_lamports`
    /// at the moment of emission; this field denominates the FLOOR
    /// component so an off-chain audit can distinguish rent from floor
    /// without re-deriving the rent-exempt minimum.
    pub deposited_lamports:   u64,
    /// Canonical PDA bump.
    pub bump:                 u8,
    /// M-13 layout version tag — increments on every additive field
    /// change so a future contributor adding a field MUST bump this and
    /// the test that pins it.
    pub layout_version:       u8,
}

impl SubmitScoreEscrow {
    /// The PDA seed prefix. Concrete seeds:
    ///   [SEED_PREFIX, agent_wallet.as_ref(), &epoch.to_le_bytes()]
    pub const SEED_PREFIX: &'static [u8] = b"submit_score_escrow";

    /// Current layout-version tag — bump on every additive field change.
    /// Pinned in tests/m13_submit_score_escrow.rs so a refactor that
    /// drifts the layout must update BOTH the constant AND the test.
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    ///
    ///   8  discriminator
    /// + 32 agent_wallet
    /// + 8  epoch
    /// + 32 oracle
    /// + 8  deposited_at
    /// + 8  deposited_lamports
    /// + 1  bump
    /// + 1  layout_version
    pub const SPACE: usize = 8 + 32 + 8 + 32 + 8 + 8 + 1 + 1;
}
