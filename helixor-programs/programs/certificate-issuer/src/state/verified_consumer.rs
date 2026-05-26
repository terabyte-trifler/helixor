// =============================================================================
// programs/certificate-issuer/src/state/verified_consumer.rs
//
// VerifiedConsumer — DBP-2: the on-chain "Verified Integrator" badge.
//
// WHAT THIS IS FOR
// ----------------
// DBP-1 (audit/consumer_integration_check.py) is the off-chain self-serve
// linter that verifies a partner's cert-reader source against the
// audit-mandated safe surfaces (SafeCertReader, verifyAgainstSolanaLedger,
// the SOL-3 per-operation freshness floors). DBP-1 alone is necessary but
// not sufficient — a green linter run is a one-shot pre-flight; what
// downstream lending contracts actually need is a CRYPTOGRAPHIC anchor that
// names a specific partner and a specific `integration_hash` they attested
// to.
//
// That anchor is this account: VerifiedConsumer, a per-partner PDA owned by
// the certificate-issuer program. Created by `register_verified_consumer`
// when the partner signs the canonical attestation digest with the keypair
// behind `partner_wallet`, the account stores `(integration_hash,
// registered_at_*, state)` and persists forever as an audit trail. A
// downstream lending contract can:
//
//     anchor.pdaExists(["verified_consumer", caller_partner_wallet])
//
// to refuse a caller's cert-derived parameters if the caller has no
// VerifiedConsumer badge. The on-chain registration is the gate; the badge
// is tradeable in the sense that downstream-of-downstream contracts can
// recognize it without trusting the partner's off-chain claims.
//
// REVOKABILITY
// ------------
// `state` carries an Active/Revoked discriminator. The account is NEVER
// closed (the audit trail persists), so a downstream contract MUST check
// `state == VerifiedConsumerState::Active` rather than presence alone. A
// revoked badge is structurally distinct from an absent badge: the partner
// HAD the badge and lost it (bad-faith manifest, partner self-revoke,
// admin-terminated) versus the partner never claimed it.
//
// PDA SEED
// --------
//     ["verified_consumer", partner_wallet]
//
// One-per-partner. Anchor `init` (in register_verified_consumer) guarantees
// init-once, so a partner cannot re-register a new manifest without first
// revoking the prior one. Re-registration flow: revoke → close (admin only)
// → register again. The two-step flow is intentional so a partner can't
// silently rotate `integration_hash` without an on-chain audit trail.
//
// CANONICAL ATTESTATION DIGEST
// ----------------------------
// The partner_wallet keypair signs (off-chain, OR directly via the tx
// signer in the simple flow):
//
//     sha256( "helixor-dbp2-verified-consumer" || partner_wallet || integration_hash )
//
// — domain-separated from cert-signing and challenge-attestation digests so
// signatures cannot be lifted across surfaces.
// =============================================================================

use anchor_lang::prelude::*;

/// Discriminator: Active (0) means the badge is in good standing. Revoked
/// (1) means the partner has lost the badge (self-revoke, admin
/// bad-faith, or admin-terminated); the account is NOT closed so the
/// revocation remains visible.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedConsumerState {
    Active = 0,
    Revoked = 1,
}

impl VerifiedConsumerState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Reason codes for a revocation. Stored as a u8 for cheap external
/// decoding. `NotRevoked` (0) is the default while `state == Active`; once
/// `state := Revoked`, the reason names WHY.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// Not revoked — the default for an Active badge.
    NotRevoked = 0,
    /// Partner voluntarily revoked their own badge (manifest update,
    /// integration deprecation).
    PartnerSelfRevoke = 1,
    /// Admin revoked the badge because the partner's manifest is a
    /// bad-faith attestation (linter green on a manifest whose claimed
    /// cert-reader source differs materially from production).
    AdminBadFaith = 2,
    /// Admin terminated the partner from the program (legal, contract
    /// breach, ToS violation).
    AdminTerminated = 3,
}

impl RevokeReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NotRevoked),
            1 => Some(Self::PartnerSelfRevoke),
            2 => Some(Self::AdminBadFaith),
            3 => Some(Self::AdminTerminated),
            _ => None,
        }
    }
}

#[account]
#[derive(Debug)]
pub struct VerifiedConsumer {
    /// The partner's Solana pubkey — the DBP-1 manifest's `partner_wallet`
    /// field. Denormalised from the PDA seed for cheap reads.
    pub partner_wallet:     Pubkey,
    /// The DBP-1 canonical manifest hash — sha256(canonical_json(
    /// manifest minus integration_hash and signature_ed25519)). Stored
    /// here so a downstream verifier can re-fetch the manifest from
    /// `launch/integrations/<partner>.json`, recompute the canonical
    /// hash, and confirm the on-chain registration names the SAME
    /// manifest they read.
    pub integration_hash:   [u8; 32],
    /// Solana slot at registration time. Cheap timestamp; pairs with
    /// the unix seconds for ergonomics.
    pub registered_at_slot: u64,
    /// Unix seconds at registration time.
    pub registered_at_unix: i64,
    /// State discriminator — `VerifiedConsumerState::Active` (0) or
    /// `VerifiedConsumerState::Revoked` (1). Downstream contracts MUST
    /// gate on `Active`, not on account presence alone, since revoked
    /// accounts are NOT closed.
    pub state:              u8,
    /// Unix seconds when the badge was revoked. 0 while `state == Active`.
    pub revoked_at_unix:    i64,
    /// The signer that revoked the badge. `Pubkey::default()` while
    /// `state == Active`. Either `partner_wallet` (self-revoke) or
    /// `issuer_config.authority` (admin).
    pub revoked_by:         Pubkey,
    /// Reason code — `RevokeReason::NotRevoked` (0) while `state ==
    /// Active`.
    pub revoke_reason:      u8,
    /// Account-layout version for future migrations.
    pub layout_version:     u8,
    /// Canonical PDA bump.
    pub bump:               u8,
    /// Reserved cushion for small future fields without a realloc.
    pub _reserved:          [u8; 16],
}

impl VerifiedConsumer {
    /// Layout v1 — initial.
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"verified_consumer";

    /// Domain-separation tag on the registration attestation digest. Distinct
    /// from cert-signing (`helixor-cert-...`) and challenge-attestation
    /// (`helixor-aw01-ext-challenge`) so a registration signature cannot be
    /// lifted to any other surface or vice versa.
    pub const DOMAIN_TAG: &'static [u8] = b"helixor-dbp2-verified-consumer";

    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   32 partner_wallet
    /// + 32 integration_hash
    /// +  8 registered_at_slot
    /// +  8 registered_at_unix
    /// +  1 state
    /// +  8 revoked_at_unix
    /// + 32 revoked_by
    /// +  1 revoke_reason
    /// +  1 layout_version
    /// +  1 bump
    /// + 16 _reserved
    /// ─────────────────────
    /// =140
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 32 + 8 + 8 + 1 + 8 + 32 + 1 + 1 + 1 + 16;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// Decode the `state` byte into the strongly-typed enum.
    pub fn decoded_state(&self) -> Option<VerifiedConsumerState> {
        VerifiedConsumerState::from_u8(self.state)
    }

    /// Decode the `revoke_reason` byte into the strongly-typed enum.
    pub fn decoded_revoke_reason(&self) -> Option<RevokeReason> {
        RevokeReason::from_u8(self.revoke_reason)
    }

    /// True iff the badge is currently in the Active state. Downstream
    /// lending contracts SHOULD gate on this rather than account
    /// presence — a Revoked badge is not equivalent to no badge.
    pub fn is_active(&self) -> bool {
        self.state == VerifiedConsumerState::Active as u8
    }
}

/// Compute the canonical 32-byte attestation digest the partner_wallet
/// keypair signs over to claim the badge.
///
/// Layout (fixed, public):
///   "helixor-dbp2-verified-consumer"  (30 bytes)
///   partner_wallet                    (32 bytes) — pins the badge owner
///   integration_hash                  (32 bytes) — pins the manifest
pub fn registration_attestation_digest(
    partner_wallet:   &Pubkey,
    integration_hash: &[u8; 32],
) -> [u8; 32] {
    use solana_program::hash::hashv;
    let h = hashv(&[
        VerifiedConsumer::DOMAIN_TAG,
        partner_wallet.as_ref(),
        integration_hash,
    ]);
    h.to_bytes()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_matches_field_layout() {
        // Hand-verified against the comment in SIZE_WITHOUT_DISCRIMINATOR.
        assert_eq!(VerifiedConsumer::SIZE_WITHOUT_DISCRIMINATOR, 140);
        assert_eq!(VerifiedConsumer::SPACE, 148);
    }

    #[test]
    fn seed_prefix_is_pinned() {
        // A rename of the seed prefix would invalidate every existing
        // VerifiedConsumer PDA — pin the literal bytes so the test trips
        // before that drift reaches mainnet.
        assert_eq!(VerifiedConsumer::SEED_PREFIX, b"verified_consumer");
    }

    #[test]
    fn domain_tag_is_pinned() {
        // The domain tag is part of the canonical digest the partner
        // signs over. Changing it invalidates every off-chain signature
        // partners have already computed. Pin the literal bytes.
        assert_eq!(
            VerifiedConsumer::DOMAIN_TAG,
            b"helixor-dbp2-verified-consumer",
        );
        assert_eq!(VerifiedConsumer::DOMAIN_TAG.len(), 30);
    }

    #[test]
    fn state_enum_roundtrip() {
        assert_eq!(
            VerifiedConsumerState::from_u8(0),
            Some(VerifiedConsumerState::Active),
        );
        assert_eq!(
            VerifiedConsumerState::from_u8(1),
            Some(VerifiedConsumerState::Revoked),
        );
        assert_eq!(VerifiedConsumerState::from_u8(2), None);
        assert_eq!(VerifiedConsumerState::Active as u8, 0);
        assert_eq!(VerifiedConsumerState::Revoked as u8, 1);
    }

    #[test]
    fn revoke_reason_enum_roundtrip() {
        for (v, exp) in [
            (0, RevokeReason::NotRevoked),
            (1, RevokeReason::PartnerSelfRevoke),
            (2, RevokeReason::AdminBadFaith),
            (3, RevokeReason::AdminTerminated),
        ] {
            assert_eq!(RevokeReason::from_u8(v), Some(exp));
        }
        assert_eq!(RevokeReason::from_u8(4), None);
    }

    #[test]
    fn registration_attestation_digest_is_deterministic() {
        let wallet = Pubkey::new_from_array([7u8; 32]);
        let hash   = [11u8; 32];
        let d1 = registration_attestation_digest(&wallet, &hash);
        let d2 = registration_attestation_digest(&wallet, &hash);
        assert_eq!(d1, d2, "same inputs must give same digest");
    }

    #[test]
    fn registration_attestation_digest_binds_wallet() {
        // Two different partner_wallets MUST yield different digests so a
        // signature on partner A's hash cannot be replayed against partner B.
        let hash = [11u8; 32];
        let a = registration_attestation_digest(&Pubkey::new_from_array([1u8; 32]), &hash);
        let b = registration_attestation_digest(&Pubkey::new_from_array([2u8; 32]), &hash);
        assert_ne!(a, b);
    }

    #[test]
    fn registration_attestation_digest_binds_hash() {
        // Two different integration_hashes MUST yield different digests so a
        // signature on manifest A cannot be replayed against manifest B.
        let wallet = Pubkey::new_from_array([7u8; 32]);
        let a = registration_attestation_digest(&wallet, &[11u8; 32]);
        let b = registration_attestation_digest(&wallet, &[22u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn is_active_gates_only_on_state_byte() {
        // is_active must be a pure function of `state`. A consumer that
        // accidentally relies on account presence alone is not protected
        // against revoked badges.
        let mut v = VerifiedConsumer {
            partner_wallet:     Pubkey::default(),
            integration_hash:   [0u8; 32],
            registered_at_slot: 0,
            registered_at_unix: 0,
            state:              VerifiedConsumerState::Active as u8,
            revoked_at_unix:    0,
            revoked_by:         Pubkey::default(),
            revoke_reason:      RevokeReason::NotRevoked as u8,
            layout_version:     VerifiedConsumer::CURRENT_LAYOUT_VERSION,
            bump:               255,
            _reserved:          [0u8; 16],
        };
        assert!(v.is_active());
        v.state = VerifiedConsumerState::Revoked as u8;
        assert!(!v.is_active());
    }
}
