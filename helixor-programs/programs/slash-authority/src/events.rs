// =============================================================================
// programs/slash-authority/src/events.rs
//
// Anchor events for the slash-authority program. The off-chain indexer
// captures these so the slashing pipeline + dashboards see a slash the
// moment it lands.
// =============================================================================

use anchor_lang::prelude::*;

/// Emitted when an EscrowVault is opened and funded.
#[event]
pub struct VaultOpened {
    pub agent_wallet:    Pubkey,
    pub staked_lamports: u64,
    pub opened_at:       i64,
}

/// Emitted when a slash is executed.
#[event]
pub struct SlashExecuted {
    pub agent_wallet:     Pubkey,
    /// This slash's index — also the SlashRecord seed component.
    pub index:            u64,
    /// OffenseTier code (0 Minor, 1 Major, 2 Compromise).
    pub offense_tier:     u8,
    /// Lamports taken.
    pub slashed_lamports: u64,
    /// SlashDestination code (0 Treasury, 1 Burn).
    pub destination:      u8,
    /// The vault's stake after the slash.
    pub stake_after:      u64,
    /// True if the slash was terminal (vault deactivated).
    pub terminal:         bool,
    /// The slash authority that executed it.
    pub executor:         Pubkey,
    pub executed_at:      i64,
}

// ── Day 21: dispute-mechanism events ────────────────────────────────────────

/// Emitted when an agent owner appeals a Pending slash.
#[event]
pub struct SlashAppealed {
    pub agent_wallet: Pubkey,
    pub index:        u64,
    pub appeal_hash:  [u8; 32],
    pub appealed_at:  i64,
}

/// Emitted when the slash authority resolves an appeal.
#[event]
pub struct AppealResolved {
    pub agent_wallet:      Pubkey,
    pub index:             u64,
    /// True = appeal failed (slash stands); false = overturned.
    pub upheld:            bool,
    /// Lamports released back to free stake (non-zero only on overturn).
    pub released_lamports: u64,
    pub resolved_at:       i64,
}

/// Emitted when a Pending slash is settled — funds finally move/burn.
#[event]
pub struct SlashSettled {
    pub agent_wallet:     Pubkey,
    pub index:            u64,
    pub settled_lamports: u64,
    /// SlashDestination code (0 Treasury, 1 Burn).
    pub destination:      u8,
    pub terminal:         bool,
    pub settled_at:       i64,
    /// VULN-08 observability: unix seconds the slash was originally
    /// executed. Lets the off-chain monitor compute `settled_at -
    /// executed_at` to flag suspicious same-block / short-gap settlements.
    pub executed_at:      i64,
}

// ── VULN-08: settle observability ───────────────────────────────────────────

/// Emitted EVERY time someone calls settle_slash — emitted BEFORE the
/// timing/state gates run, so even REJECTED attempts surface on-chain.
///
/// Why a separate "attempted" event? VULN-08 names MEV front-running and
/// griefing patterns where a bot races settle_slash against an appeal.
/// `SlashSettled` only fires on success; an attacker spraying failed
/// settle attempts to time an appeal is invisible to it. This event makes
/// the spray observable: the off-chain monitor alerts on attempts whose
/// `seconds_since_execute` is suspiciously small or that cluster around
/// an appeal's mempool window.
#[event]
pub struct SettleSlashAttempted {
    pub agent_wallet:           Pubkey,
    pub index:                  u64,
    /// Who attempted — the slash_executor signer for this call.
    pub executor:               Pubkey,
    /// Original execute_slash timestamp.
    pub executed_at:            i64,
    /// The appeal window's close time (the gate the audit highlighted).
    pub appeal_deadline:        i64,
    /// Unix seconds the attempt landed.
    pub attempted_at:           i64,
    /// `attempted_at - executed_at` — the off-chain monitor's anomaly
    /// signal. Same-block (~0s) attempts are the smoking gun.
    pub seconds_since_execute:  i64,
}

// ── VULN-04 events: role separation + pause kill switch ────────────────────

/// Emitted when the admin rotates the role keys / settlement timelock.
#[event]
pub struct AuthoritiesUpdated {
    pub slash_executor:              Pubkey,
    pub appeal_resolver:             Pubkey,
    pub pause_authority:             Pubkey,
    pub settlement_timelock_seconds: i64,
    pub updated_at:                  i64,
}

/// Emitted when the pause_authority toggles the slash kill switch.
#[event]
pub struct SlashPaused {
    /// True for pause, false for unpause.
    pub paused:    bool,
    pub at:        i64,
    pub authority: Pubkey,
}

/// Emitted when a watchdog files an oracle challenge.
#[event]
pub struct OracleChallenged {
    pub accused_oracle:     Pubkey,
    pub challenger:         Pubkey,
    pub index:              u64,
    /// ProofType code (0 ConflictingScores, 1 PhantomAgent, 2 EvidenceHash).
    pub proof_type:         u8,
    /// ChallengeStatus code (0 Pending, 1 Verified, 2 Dismissed).
    pub status:             u8,
    /// Whether the proof type is verifiable by on-chain code alone.
    pub onchain_verifiable: bool,
    pub subject_epoch:      u64,
    pub filed_at:           i64,
}
