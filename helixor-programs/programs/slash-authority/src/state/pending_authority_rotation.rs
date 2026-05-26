// =============================================================================
// programs/slash-authority/src/state/pending_authority_rotation.rs
//
// SPOF-#2 MITIGATION — time-locked, 2-of-3-attested slash-authority rotation.
//
// THE THREAT
// ----------
// Pre-mitigation, `update_authorities` was admin-gated: a single admin
// signature could rewrite slash_executor, appeal_resolver, AND
// pause_authority in one transaction. A compromised admin could install
// three attacker-controlled keys and then drain every escrow vault
// through the executor/resolver path. The settlement_timelock + pause
// kill switch (VULN-04) didn't help here: the admin can ALSO install
// a hostile pause_authority that refuses to pause.
//
// THE PROTOCOL
// ------------
// Mirrors the VULN-13 oracle-key-rotation ceremony in the health-oracle
// program. Authority rotation is now a two-phase, time-locked,
// N-of-M-attested ceremony driven through this PDA:
//
//   1. PROPOSE — admin OR any current role key (executor / resolver /
//      pauser) submits a PendingAuthorityRotation with the proposed
//      new role keys + treasury + timelock, plus `enact_after = now +
//      timelock_seconds` (>= MIN_TIMELOCK_SECONDS, 48h).
//
//   2. ATTEST — each CURRENT role key may submit its signature. Only the
//      live role-key set (executor, resolver, pauser) at attest-time
//      counts. The admin cannot attest — separation by design.
//
//   3. ENACT — any signer may enact once both gates hold:
//        a) `now >= enact_after`         (timelock has elapsed), AND
//        b) `attestations.len() >= 2`     (strict majority of the 3
//           role keys has signed off).
//      Applies the new role set, the new treasury (if changed), and
//      the new timelock. Closes the PDA; rent refunded to proposer.
//
//   4. CANCEL — admin OR any current role key may cancel before
//      enactment. A single honest role-key holder vetoes the
//      proposal during the 48h window.
//
// WHY ROLE KEYS, NOT ADMIN, ATTEST
// --------------------------------
// The audit's CRITICAL finding is that admin alone must NOT be able
// to rewrite the role set. Counting admin's signature as an
// attestation would defeat the fix: a compromised admin could
// "propose + self-attest" and only need to wait the timelock. By
// design admin can propose but not attest — the live role keys
// (who are the operational counterweight to admin) must consent.
//
// CLUSTER SIZE IS FIXED AT 3
// --------------------------
// Slash-authority has exactly three role keys (executor, resolver,
// pauser) — distinct by `validate_authority_separation`. Threshold
// is `floor(3/2)+1 = 2`. Two of the three must attest.
//
// SINGLETON GUARD
// ---------------
// PDA seed `["pending_authority_rotation"]` — only one in-flight
// proposal at a time. A second `propose` fails with Anchor's
// "account already exists" until the open proposal is enacted or
// cancelled. Prevents proposal-spam from a compromised admin.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   proposer                       32   (Pubkey)
//   new_slash_executor             32   (Pubkey)
//   new_appeal_resolver            32   (Pubkey)
//   new_pause_authority            32   (Pubkey)
//   new_treasury                   32   (Pubkey)
//   new_settlement_timelock_seconds 8   (i64)
//   enact_after                     8   (i64)
//   attestations length prefix      4
//   attestation slots             3*32  (96)
//   proposed_at                     8   (i64)
//   bump                            1   (u8)
//   TOTAL (without discriminator): 285 bytes
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct PendingAuthorityRotation {
    /// The pubkey that submitted this proposal. Either the admin or
    /// one of the three role keys at propose-time. Rent-refund target
    /// on enact / cancel.
    pub proposer:                        Pubkey,
    /// Proposed new slash_executor.
    pub new_slash_executor:              Pubkey,
    /// Proposed new appeal_resolver.
    pub new_appeal_resolver:             Pubkey,
    /// Proposed new pause_authority.
    pub new_pause_authority:             Pubkey,
    /// Proposed new treasury. May equal the current treasury (rotation
    /// of role keys WITHOUT a treasury change is the common case).
    pub new_treasury:                    Pubkey,
    /// Proposed new settlement timelock. Enforced at propose + enact
    /// to be >= MIN_SETTLEMENT_TIMELOCK_SECONDS (72h).
    pub new_settlement_timelock_seconds: i64,
    /// Unix timestamp at which this proposal becomes enactable.
    /// = `proposed_at + timelock_seconds` where `timelock_seconds`
    /// is supplied by the proposer with a floor of MIN_TIMELOCK_SECONDS
    /// (48h).
    pub enact_after:                     i64,
    /// Current role keys that have attested. Each key counts once.
    /// Bounded by 3 (executor, resolver, pauser); a Vec is used to
    /// keep parity with the VULN-13 PendingOracleRotation shape.
    pub attestations:                    Vec<Pubkey>,
    /// Unix timestamp the proposal was submitted. Carried for
    /// off-chain indexers + audit-log replay.
    pub proposed_at:                     i64,
    /// Canonical PDA bump.
    pub bump:                            u8,
}

impl PendingAuthorityRotation {
    /// The audit-recommended minimum review window: 48 hours.
    /// Matches the VULN-13 oracle-key-rotation floor.
    pub const MIN_TIMELOCK_SECONDS: i64 = 48 * 60 * 60;

    /// The PDA seed. Only one in-flight rotation at a time.
    pub const SEED: &'static [u8] = b"pending_authority_rotation";

    /// Slash-authority has exactly three role keys (executor, resolver,
    /// pauser) — distinct by validate_authority_separation. Threshold
    /// is a strict majority of three = 2.
    pub const ROLE_KEY_COUNT: usize    = 3;
    pub const CONSENSUS_THRESHOLD: usize = 2;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    ///
    ///   8  discriminator
    /// + 32 proposer
    /// + 32 new_slash_executor
    /// + 32 new_appeal_resolver
    /// + 32 new_pause_authority
    /// + 32 new_treasury
    /// + 8  new_settlement_timelock_seconds
    /// + 8  enact_after
    /// + 4  attestations length prefix
    /// + 32 * ROLE_KEY_COUNT            (reserved attestation slots)
    /// + 8  proposed_at
    /// + 1  bump
    pub const SPACE: usize =
        8 + 32 * 5 + 8 + 8 + 4 + (32 * Self::ROLE_KEY_COUNT) + 8 + 1;

    /// Whether `key` has already attested.
    pub fn has_attestation(&self, key: &Pubkey) -> bool {
        self.attestations.contains(key)
    }

    /// Whether this proposal is enactable at `now`. Pure — exported
    /// for unit tests.
    ///
    /// Gates:
    ///   - timelock elapsed:    `now >= self.enact_after`
    ///   - 2-of-3 attestations: `self.attestations.len() >=
    ///                             CONSENSUS_THRESHOLD`
    pub fn is_enactable(&self, now: i64) -> bool {
        now >= self.enact_after
            && self.attestations.len() >= Self::CONSENSUS_THRESHOLD
    }

    /// How many more attestations are needed. Saturates at 0 once
    /// the threshold is reached.
    pub fn attestations_remaining(&self) -> usize {
        Self::CONSENSUS_THRESHOLD.saturating_sub(self.attestations.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(now: i64, attestations: usize) -> PendingAuthorityRotation {
        let mut p = PendingAuthorityRotation {
            enact_after: now + 1,
            ..Default::default()
        };
        for i in 0..attestations {
            // Distinct, non-default pubkeys.
            let mut bytes = [0u8; 32];
            bytes[0] = (i as u8) + 1;
            p.attestations.push(Pubkey::new_from_array(bytes));
        }
        p
    }

    #[test]
    fn enactable_requires_timelock_and_threshold() {
        let mut p = fresh(100, 2);
        p.enact_after = 200;

        // Threshold OK but timelock not elapsed.
        assert!(!p.is_enactable(150));
        // Timelock OK and threshold OK.
        assert!(p.is_enactable(250));
        // Drop below threshold — fails even if timelock elapsed.
        p.attestations.pop();
        assert!(!p.is_enactable(250));
    }

    #[test]
    fn remaining_saturates_at_zero() {
        let mut p = fresh(0, 0);
        assert_eq!(p.attestations_remaining(), 2);
        p.attestations.push(Pubkey::new_unique());
        assert_eq!(p.attestations_remaining(), 1);
        p.attestations.push(Pubkey::new_unique());
        assert_eq!(p.attestations_remaining(), 0);
        p.attestations.push(Pubkey::new_unique());
        assert_eq!(p.attestations_remaining(), 0);
    }

    #[test]
    fn has_attestation_is_set_membership() {
        let mut p = fresh(0, 0);
        let k1 = Pubkey::new_unique();
        let k2 = Pubkey::new_unique();
        assert!(!p.has_attestation(&k1));
        p.attestations.push(k1);
        assert!(p.has_attestation(&k1));
        assert!(!p.has_attestation(&k2));
    }

    #[test]
    fn min_timelock_is_48h() {
        assert_eq!(
            PendingAuthorityRotation::MIN_TIMELOCK_SECONDS,
            48 * 60 * 60,
        );
    }
}
