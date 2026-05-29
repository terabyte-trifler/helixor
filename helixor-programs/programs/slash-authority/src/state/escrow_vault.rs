// =============================================================================
// programs/slash-authority/src/state/escrow_vault.rs
//
// EscrowVault — the per-agent staked-collateral account.
//
//     seeds = ["escrow", agent_pubkey]
//
// THE DOC-2 CHANGE: the MVP locked a 0.01 SOL escrow but never touched it —
// the stake was theatre. V2 makes it ECONOMICALLY REAL: execute_slash
// actually moves lamports out of this vault. An agent that gets slashed
// loses money.
//
// HOW A VAULT CUSTODIES SOL
// -------------------------
// EscrowVault is a program-OWNED data account. Because the slash-authority
// program owns it, the program may debit its lamports directly
// (try_borrow_mut_lamports) — no signer needed, the ownership IS the
// authority. The vault therefore holds two things at once:
//   - DATA: this struct (agent, staked amount, slash count, …)
//   - LAMPORTS: the rent-exempt minimum PLUS the staked collateral on top.
//
// `staked_lamports` is the bookkeeping figure — the collateral the agent
// has staked, ABOVE the account's own rent. The real lamport balance of
// the account is always `rent_exempt_minimum + staked_lamports` (minus any
// in-flight slash). Keeping the figure explicit means a slash can be
// validated against it without re-deriving rent every time.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet            32   (Pubkey)
//   staked_lamports          8   (u64 — collateral above rent)
//   slash_count             8   (u64 — how many slashes; keys SlashRecord)
//   total_slashed_lamports   8   (u64 — lifetime sum slashed; monotonic)
//   created_at               8   (i64 — unix seconds the vault opened)
//   active                   1   (bool — false after a terminal slash)
//   bump                     1   (u8)
//   layout_version           1   (u8)
//   encumbered_lamports      8   (u64 — held by Pending/Appealed slashes)
//   last_appeal_at           8   (i64 — most recent appeal; soft audit field)
//   appeals_in_flight        1   (u8  — M-01: count of currently-Appealed
//                                  slashes for this vault. Hard-capped at
//                                  1 by appeal_slash; resolve_appeal
//                                  decrements. Tighter than the 24h
//                                  cooldown — the agent cannot stack up
//                                  appeals to stall multiple settlements.)
//   _reserved               15   (zeroed cushion, shrunk by 1 to fit
//                                  appeals_in_flight at zero net growth)
//   TOTAL (without discriminator): 99 bytes
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct EscrowVault {
    /// The agent whose collateral this vault holds.
    pub agent_wallet:           Pubkey,
    /// The staked collateral, in lamports, ABOVE the account's rent-exempt
    /// minimum, that is FREE — not encumbered by a pending slash. A new
    /// slash deducts from this.
    pub staked_lamports:        u64,
    /// How many times this agent has been slashed. Monotonic. The NEXT
    /// SlashRecord is keyed ["slash", agent, slash_count].
    pub slash_count:            u64,
    /// Lifetime total lamports slashed from this vault. Monotonic — for
    /// audit / reputation, never decremented.
    pub total_slashed_lamports: u64,
    /// Unix seconds the vault was opened.
    pub created_at:             i64,
    /// True while the vault is live. A terminal (compromise) slash sets
    /// this false — the agent is no longer scoreable.
    pub active:                 bool,
    /// Canonical PDA bump.
    pub bump:                   u8,
    /// Account-layout version.
    pub layout_version:         u8,

    // ── Day-21 lifecycle fields (carved from the former reserve) ────────────
    /// Lamports ENCUMBERED by Pending/Appealed slashes — moved out of
    /// `staked_lamports` but still physically in the vault account. On
    /// settlement they leave the vault; on a successful appeal they return
    /// to `staked_lamports`. The Day-21 "funds held, not burned" model.
    pub encumbered_lamports:    u64,
    /// Unix seconds of the agent's most recent appeal — preserved as a
    /// soft audit field. The 24h cooldown derived from this is a soft
    /// throttle; the HARD M-01 gate is `appeals_in_flight` below.
    pub last_appeal_at:         i64,
    /// M-01: number of this vault's slashes that are currently in the
    /// Appealed state. `appeal_slash` requires this to be 0 (hard cap of
    /// one in-flight appeal per vault) and increments it to 1;
    /// `resolve_appeal` decrements it back to 0 on either outcome
    /// (uphold or overturn). This bounds the maximum number of
    /// settlements an agent can stall in parallel at 1 — tighter than
    /// the pre-existing 24h cooldown, which only paced filings without
    /// limiting their cumulative effect.
    pub appeals_in_flight:      u8,
    /// Zero-padded reserve — shrunk by 1 byte to fit `appeals_in_flight`
    /// at zero net account-size growth.
    pub _reserved:              [u8; 15],
}

impl EscrowVault {
    /// Bumped to 2 by M-01 (added `appeals_in_flight` for the per-vault
    /// concurrency cap). Bump again on any future on-disk shape change.
    pub const CURRENT_LAYOUT_VERSION: u8 = 2;

    /// M-01: hard cap on concurrent Appealed slashes per vault. One.
    /// Tightens the per-vault appeal-cooldown rate-limit into an
    /// absolute count limit, so an agent cannot stack up multiple
    /// in-flight appeals to stall multiple settlements at once.
    pub const MAX_APPEALS_IN_FLIGHT: u8 = 1;

    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 8 + 8 + 8 + 8 + 1 + 1 + 1 = 67  (Day-20 core)
    /// + 8 encumbered_lamports + 8 last_appeal_at = 16
    /// + 1 appeals_in_flight (M-01)               = 1
    /// + 15 reserved                              = 15
    ///   = 99
    ///
    /// The size is UNCHANGED — 1 byte was reclaimed from the former
    /// 16-byte reserve, which shrinks to 15.
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 8 + 8 + 8 + 8 + 1 + 1 + 1 + 8 + 8 + 1 + 15;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"escrow";

    /// The minimum collateral an agent must stake to open a vault.
    /// 0.01 SOL — the same figure the MVP used, now actually enforced.
    pub const MIN_STAKE_LAMPORTS: u64 = 10_000_000;

    /// The deductible balance — how much could still be slashed.
    pub fn slashable_lamports(&self) -> u64 {
        self.staked_lamports
    }
}
