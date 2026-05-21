// =============================================================================
// programs/slash-authority/src/state/slash_record.rs
//
// SlashRecord — one immutable record of one slash.
//
//     seeds = ["slash", agent_pubkey, count]
//
// `count` is the agent's slash index from EscrowVault.slash_count. Every
// slash gets its OWN account, created with `init` — so the record is
// write-once and the agent's full slash HISTORY is on chain, append-only.
// (The same per-index immutability pattern as the epoch-keyed certificates.)
//
// TIERED SLASHING
// ---------------
// A slash is not all-or-nothing. The OffenseTier determines the fraction
// of the staked collateral that is taken, and WHERE it goes:
//
//   Minor       — a soft, recoverable signal (e.g. a transient anomaly the
//                 oracle flagged but is not sure about). A small fraction
//                 is moved to the slash treasury — a penalty, not a death
//                 sentence. The vault stays active.
//
//   Major       — a serious, sustained offense (e.g. confirmed drift into
//                 adversarial behaviour). A large fraction goes to the
//                 treasury. The vault stays active but heavily penalised.
//
//   Compromise  — a CONFIRMED compromise (the security layer's
//                 IMMEDIATE_RED, verified). The ENTIRE remaining stake is
//                 BURNED — sent to the incinerator, economically destroyed
//                 — and the vault is deactivated. This is terminal.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet         32   (Pubkey)
//   index                 8   (u64 — this slash's count; part of the seed)
//   offense_tier          1   (u8  — OffenseTier code)
//   slashed_lamports      8   (u64 — lamports taken in this slash)
//   destination           1   (u8  — SlashDestination: 0 treasury, 1 burn)
//   evidence_hash        32   ([u8;32] — hash of the off-chain detection evidence)
//   stake_before          8   (u64 — staked_lamports before this slash)
//   stake_after           8   (u64 — staked_lamports after this slash)
//   executed_at           8   (i64 — unix seconds)
//   executor             32   (Pubkey — the slash authority that executed)
//   bump                  1   (u8)
//   layout_version        1   (u8)
//   status                1   (u8 — SlashStatus code)
//   appeal_deadline       8   (i64 — unix seconds)
//   appeal_hash          32   ([u8;32])
//   appealed_at           8   (i64 — unix seconds)
//   _reserved             7   (zeroed cushion)
//   TOTAL (without discriminator): 196 bytes
// =============================================================================

use anchor_lang::prelude::*;

/// The severity tier of an offense. Drives the slash fraction + destination.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum OffenseTier {
    /// A soft, recoverable signal. Small penalty, vault stays active.
    Minor = 0,
    /// A serious, sustained offense. Large penalty, vault stays active.
    Major = 1,
    /// A confirmed compromise. Entire stake burned, vault deactivated.
    Compromise = 2,
}

impl OffenseTier {
    pub fn from_u8(value: u8) -> Option<OffenseTier> {
        match value {
            0 => Some(OffenseTier::Minor),
            1 => Some(OffenseTier::Major),
            2 => Some(OffenseTier::Compromise),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The fraction of the remaining stake this tier slashes, expressed in
    /// BASIS POINTS (1 bp = 0.01%). Integer math only — no floats on chain.
    ///   Minor       =  500 bp  =  5%
    ///   Major       = 5000 bp  = 50%
    ///   Compromise  = 10000 bp = 100% (the whole stake)
    pub fn slash_bps(self) -> u64 {
        match self {
            OffenseTier::Minor      =>    500,
            OffenseTier::Major      =>  5_000,
            OffenseTier::Compromise => 10_000,
        }
    }

    /// Where the slashed lamports go.
    pub fn destination(self) -> SlashDestination {
        match self {
            OffenseTier::Minor | OffenseTier::Major => SlashDestination::Treasury,
            OffenseTier::Compromise                 => SlashDestination::Burn,
        }
    }

    /// Whether this tier is TERMINAL — deactivates the vault.
    pub fn is_terminal(self) -> bool {
        matches!(self, OffenseTier::Compromise)
    }
}

/// Where slashed lamports are sent.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlashDestination {
    /// The protocol slash treasury — a penalty pool.
    Treasury = 0,
    /// The incinerator — economically destroyed (burned).
    Burn = 1,
}

impl SlashDestination {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Compute the lamports a slash takes, given the tier and the current stake.
///
/// Pure — extracted so it is unit-testable without a runtime. Integer
/// basis-point math: `amount = stake * bps / 10_000`. A Compromise (10000
/// bp) always takes the WHOLE remaining stake exactly, with no rounding
/// drift, because `stake * 10000 / 10000 == stake`.
pub fn compute_slash_amount(staked_lamports: u64, tier: OffenseTier) -> u64 {
    // u128 intermediate so `stake * bps` cannot overflow u64.
    let product = (staked_lamports as u128) * (tier.slash_bps() as u128);
    let amount = (product / 10_000u128) as u64; // audit: u128 / constant, no overflow
    // A terminal tier must take the entire stake, defensively — guard
    // against any rounding leaving dust behind.
    if tier.is_terminal() {
        staked_lamports
    } else {
        amount.min(staked_lamports)
    }
}

/// The lifecycle state of a slash.
///
/// Day 20 executed a slash and moved funds immediately. Day 21 introduces
/// a lifecycle so an agent can APPEAL before funds are irrevocably gone:
///
///   Pending   — the slash is recorded and the funds are ENCUMBERED in the
///               vault (held, not yet moved). The appeal window is open.
///   Appealed  — the agent owner has filed an appeal; awaiting resolution.
///   Overturned— the appeal succeeded; the encumbered funds are released
///               back to the agent. Terminal.
///   Settled   — the appeal window closed without a successful appeal (or
///               the appeal was rejected); the funds were moved/burned.
///               Terminal.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlashStatus {
    Pending    = 0,
    Appealed   = 1,
    Overturned = 2,
    Settled    = 3,
}

impl SlashStatus {
    pub fn from_u8(value: u8) -> Option<SlashStatus> {
        match value {
            0 => Some(SlashStatus::Pending),
            1 => Some(SlashStatus::Appealed),
            2 => Some(SlashStatus::Overturned),
            3 => Some(SlashStatus::Settled),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this status is terminal — no further transition possible.
    pub fn is_terminal(self) -> bool {
        matches!(self, SlashStatus::Overturned | SlashStatus::Settled)
    }
}

/// The window, in seconds, during which a Pending slash may be appealed.
/// After this elapses the slash may be settled. 72h — long enough for a
/// human agent owner to notice and respond.
pub const APPEAL_WINDOW_SECONDS: i64 = 72 * 3_600;

#[account]
#[derive(Debug)]
pub struct SlashRecord {
    /// The agent that was slashed.
    pub agent_wallet:     Pubkey,
    /// This slash's index (= EscrowVault.slash_count at execution time).
    /// Part of the PDA seed — every slash a distinct, immutable account.
    pub index:            u64,
    /// The offense tier (OffenseTier code).
    pub offense_tier:     u8,
    /// Lamports taken in this slash.
    pub slashed_lamports: u64,
    /// Where the lamports went (SlashDestination code).
    pub destination:      u8,
    /// Hash of the off-chain detection evidence that justified the slash.
    pub evidence_hash:    [u8; 32],
    /// The vault's staked_lamports BEFORE this slash.
    pub stake_before:     u64,
    /// The vault's staked_lamports AFTER this slash.
    pub stake_after:      u64,
    /// Unix seconds the slash executed.
    pub executed_at:      i64,
    /// The slash authority that executed it.
    pub executor:         Pubkey,
    /// Canonical PDA bump.
    pub bump:             u8,
    /// Account-layout version.
    pub layout_version:   u8,

    // ── Day-21 lifecycle fields (carved from the former reserve) ────────────
    /// The lifecycle state (SlashStatus code).
    pub status:           u8,
    /// Unix seconds the appeal window closes (executed_at + APPEAL_WINDOW).
    /// After this a Pending slash may be settled.
    pub appeal_deadline:  i64,
    /// Hash of the agent's appeal justification. Zero until an appeal is
    /// filed.
    pub appeal_hash:      [u8; 32],
    /// Unix seconds the appeal was filed. Zero until an appeal is filed.
    pub appealed_at:      i64,
    /// Zero-padded reserve — shrunk to make room for the lifecycle fields.
    pub _reserved:        [u8; 7],
}

impl SlashRecord {
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 8 + 1 + 8 + 1 + 32 + 8 + 8 + 8 + 32 + 1 + 1 = 140  (Day-20 core)
    /// + 1 status + 8 appeal_deadline + 32 appeal_hash + 8 appealed_at = 49
    /// + 7 reserved                                                   =  7
    ///   = 196
    ///
    /// NOTE: Day 20 declared 172 bytes (140 core + 32 reserve). Day 21
    /// spends that 32-byte reserve on the lifecycle fields and adds 17
    /// more, so the account grows 172 -> 196. Because this is pre-mainnet
    /// devnet iteration, the larger size is simply the new SPACE — there
    /// are no Day-20 SlashRecords in existence to migrate.
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 8 + 1 + 8 + 1 + 32 + 8 + 8 + 8 + 32 + 1 + 1
        + 1 + 8 + 32 + 8 + 7;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"slash";

    /// Whether the appeal window is still open at time `now`.
    pub fn appeal_window_open(&self, now: i64) -> bool {
        now < self.appeal_deadline
    }
}
