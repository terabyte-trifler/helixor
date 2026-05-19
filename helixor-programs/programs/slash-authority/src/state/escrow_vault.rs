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
//   _reserved               32   (zeroed cushion)
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
    /// Unix seconds of the agent's most recent appeal — for the appeal
    /// cooldown. Zero until the first appeal.
    pub last_appeal_at:         i64,
    /// Zero-padded reserve — shrunk to make room for the lifecycle fields.
    pub _reserved:              [u8; 16],
}

impl EscrowVault {
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 8 + 8 + 8 + 8 + 1 + 1 + 1 = 67  (Day-20 core)
    /// + 8 encumbered_lamports + 8 last_appeal_at = 16
    /// + 16 reserved                              = 16
    /// = 99
    ///
    /// The size is UNCHANGED from Day 20 (still 99): the 16 new bytes are
    /// spent from the former 32-byte reserve, which shrinks to 16.
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 8 + 8 + 8 + 8 + 1 + 1 + 1 + 8 + 8 + 16;

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
