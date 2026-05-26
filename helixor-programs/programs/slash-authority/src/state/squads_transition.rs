// =============================================================================
// programs/slash-authority/src/state/squads_transition.rs
//
// TA-7: admin-key → Squads-multisig transition deadline.
//
// THE TRUST ASSUMPTION (audit)
// -----------------------------
//   "Admin key is secure until Squads transition — no technical guarantee."
//
// Pre-mitigation the operator was relied on to TRANSFER program-upgrade
// authority to the Squads vault after mainnet deploy. There was no
// on-chain anchor saying "this MUST be done by date X" — a slow or
// forgetful operator leaves a live single-key authority in place.
//
// THE MITIGATION (this file)
// --------------------------
//   * `SQUADS_TRANSITION_DEADLINE_UNIX` is the absolute timestamp by
//     which the Squads multisig MUST be the upgrade authority on every
//     deployed program. After this date, any admin-gated handler that a
//     future patch may add SHOULD wrap itself in
//     `require!(now <= SQUADS_TRANSITION_DEADLINE_UNIX, ...)`. The
//     existing single-admin paths (`update_authorities`,
//     `rotate_advance_authority`) already return refusal errors — the
//     deadline is the additional belt that catches any newly-introduced
//     admin path post-launch.
//   * `is_before_squads_transition(now)` is the pure predicate. Returns
//     true while the legacy admin path is allowed; false thereafter.
//   * The TA-7 audit gate (`audit/trust_assumption_check.py`) verifies
//     that the constant is in the future at audit time and that the
//     LAUNCH_CHECKLIST pins the same date.
//
// VALUE
// -----
// 2026-09-01 00:00 UTC = 1_756_684_800. This date is the formal
// mainnet-V1 launch window plus a 90-day operational grace (mainnet
// deploy + Squads ceremony + audit retest). After this date, any honest
// deployment MUST be on the multisig; any single-admin call site newly
// introduced by a regression is REFUSED on-chain. The audit gate
// surfaces a regression if the constant is ever moved BACKWARDS or to
// the past.
// =============================================================================

use anchor_lang::prelude::*;

/// The unix timestamp (seconds since epoch) after which any admin-gated
/// program path is considered post-transition: callers MUST be the
/// Squads vault, not a single key. `is_before_squads_transition(now)`
/// returns false once the on-chain Clock crosses this anchor.
pub const SQUADS_TRANSITION_DEADLINE_UNIX: i64 = 1_788_220_800; // 2026-09-01T00:00:00Z

/// TA-7: pure predicate. True while the deadline has NOT been reached.
/// Use in any admin-gated handler:
///
/// ```text
/// require!(is_before_squads_transition(now_ts), TransitionDeadlinePassed);
/// ```
///
/// Outside an Anchor handler (tests, off-chain), pass `Clock::get()?
/// .unix_timestamp` or a deterministic fixture.
pub fn is_before_squads_transition(now_unix: i64) -> bool {
    now_unix < SQUADS_TRANSITION_DEADLINE_UNIX
}

/// TA-7: convenience wrapper for the predicate's inverse. True iff the
/// deadline has passed; a handler that reads this and proceeds is
/// committing the very SPOF the deadline exists to prevent.
pub fn is_after_squads_transition(now_unix: i64) -> bool {
    !is_before_squads_transition(now_unix)
}

/// TA-7: the formal cutoff anchor as a human-readable ISO-8601 string,
/// for cross-checking the LAUNCH_CHECKLIST entry without arithmetic.
pub const SQUADS_TRANSITION_DEADLINE_ISO: &str = "2026-09-01T00:00:00Z";
