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
    /// M-08: the SlashConfig authority epoch this slash was executed
    /// under. Lets an indexer link `executor` to a specific authority
    /// set without having to walk the rotation event log.
    pub slash_config_version_at_execute: u32,
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
///
/// M-11 — LAMPORT AUDIT TRAIL
/// --------------------------
/// settle_slash moves lamports out of the program-owned escrow vault by
/// directly mutating `try_borrow_mut_lamports` — the canonical pattern
/// for a program-owned source (System::transfer refuses sources whose
/// owner is not the System Program). The pattern is safe, but it
/// produces NO System Program "Transfer" log entry: an off-chain
/// auditor watching System::transfer events would miss the movement
/// entirely.
///
/// M-11 closes the audit-trail gap by stamping the full balance
/// surface into THIS event:
///   * `destination_key`              — the explicit recipient (the
///     event's `destination` u8 alone names the LANE, not the address)
///   * `vault_balance_before/after`   — vault lamports immediately
///     pre/post the direct mutation
///   * `destination_balance_before/after` — the same for the recipient
///
/// Anything an off-chain log scraper could derive from a System Program
/// Transfer log is now derivable from a single SlashSettled emission,
/// without any cross-account RPC fetch. The settle handler ALSO
/// asserts `vault_before == vault_after + amount` and
/// `dest_after == dest_before + amount` post-mutation; a violation
/// trips `LamportAuditMismatch` (6090) and aborts the tx, so the
/// event's balance fields are guaranteed-consistent at emission time.
#[event]
pub struct SlashSettled {
    pub agent_wallet:     Pubkey,
    pub index:            u64,
    pub settled_lamports: u64,
    /// SlashDestination code (0 Treasury, 1 Burn).
    pub destination:      u8,
    /// M-11: the explicit recipient pubkey. The `destination` u8 only
    /// names the LANE; this carries the actual address the lamports
    /// landed at (the treasury pinned in slash_record.treasury_at_execute
    /// for Treasury settlements, or SlashConfig::INCINERATOR for Burn).
    /// Stamped here so an off-chain auditor doesn't have to cross-read
    /// the SlashRecord PDA + SlashConfig to verify routing.
    pub destination_key:               Pubkey,
    /// M-11: vault lamports immediately BEFORE the direct mutation.
    pub vault_balance_before:          u64,
    /// M-11: vault lamports immediately AFTER the direct mutation.
    /// `vault_balance_before - vault_balance_after == settled_lamports`
    /// is enforced on chain at emit time (see settle_slash handler).
    pub vault_balance_after:           u64,
    /// M-11: destination lamports immediately BEFORE the direct
    /// mutation. Useful for diff-style auditing.
    pub destination_balance_before:    u64,
    /// M-11: destination lamports immediately AFTER the direct
    /// mutation. `destination_balance_after - destination_balance_before
    /// == settled_lamports` is enforced on chain at emit time.
    pub destination_balance_after:     u64,
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

/// M-07: emitted when the admin retunes the VULN-08 settle-slash timing
/// gates via `update_settle_timing`. Carries the before/after pair on
/// both fields so an off-chain monitor sees the full delta in one event
/// (rather than having to diff against a prior snapshot it may not hold).
#[event]
pub struct SettleTimingUpdated {
    pub admin:                            Pubkey,
    pub old_execute_to_settle_seconds:    i64,
    pub new_execute_to_settle_seconds:    i64,
    pub old_settle_grace_seconds:         i64,
    pub new_settle_grace_seconds:         i64,
    pub updated_at:                       i64,
}

// ── SPOF-#2 events: time-locked, 2-of-3-attested authority rotation ────────

/// Emitted when a PendingAuthorityRotation is opened.
#[event]
pub struct AuthorityRotationProposed {
    pub proposer:                        Pubkey,
    pub new_slash_executor:              Pubkey,
    pub new_appeal_resolver:             Pubkey,
    pub new_pause_authority:             Pubkey,
    pub new_treasury:                    Pubkey,
    pub new_settlement_timelock_seconds: i64,
    pub enact_after:                     i64,
    pub proposed_at:                     i64,
}

/// Emitted when a current role key attests to the open proposal.
#[event]
pub struct AuthorityRotationAttested {
    pub attester:              Pubkey,
    pub total_attestations:    u8,
    pub required_attestations: u8,
    pub attested_at:           i64,
}

/// Emitted when the proposal is enacted (timelock + threshold satisfied).
#[event]
pub struct AuthorityRotationEnacted {
    pub enactor:                          Pubkey,
    pub old_slash_executor:               Pubkey,
    pub new_slash_executor:               Pubkey,
    pub old_appeal_resolver:              Pubkey,
    pub new_appeal_resolver:              Pubkey,
    pub old_pause_authority:              Pubkey,
    pub new_pause_authority:              Pubkey,
    pub old_treasury:                     Pubkey,
    pub new_treasury:                     Pubkey,
    pub old_settlement_timelock_seconds:  i64,
    pub new_settlement_timelock_seconds:  i64,
    /// M-08: authority-epoch counter — old/new. Every SlashRecord
    /// executed BEFORE this event carries `old_slash_config_version`;
    /// every one executed AFTER carries `new_slash_config_version`.
    /// That cut-line is the on-chain forensic anchor.
    pub old_slash_config_version:         u32,
    pub new_slash_config_version:         u32,
    pub attestation_count:                u8,
    pub enacted_at:                       i64,
}

/// Emitted when an open proposal is cancelled before enactment.
#[event]
pub struct AuthorityRotationCancelled {
    pub canceller:    Pubkey,
    pub cancelled_at: i64,
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
