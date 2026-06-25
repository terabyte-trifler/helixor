// =============================================================================
// programs/certificate-issuer/src/state/score_components.rs
//
// AW-04 — ScoreComponentsAccount
//
// THE AUDIT FINDING
// -----------------
// Pre-AW-04 the cert carried only the final score (0..=1000) + flags (u32).
// A third party that wanted to know WHY the score was 750 had to trust the
// cluster's claim — there was no on-chain breakdown of which detector
// contributed what, and a malicious cluster could publish any score it
// wanted (subject only to the threshold-signature check on a fabricated
// digest). The scoring algorithm was an off-chain trust assumption.
//
// THE FIX
// -------
// Pair every cert with a `ScoreComponentsAccount` PDA whose `payload` is
// the canonical-JSON per-dimension breakdown the off-chain cluster
// computed. At init time the program enforces
// `sha256(payload) == components_hash`, and the cluster-signed
// `cert_payload_digest` folds `components_hash` in alongside the cert
// fields. A third-party verifier can then:
//
//   1. Fetch this account.
//   2. Verify `sha256(account.payload) == account.components_hash`.
//   3. Parse the canonical JSON.
//   4. Re-execute the documented scoring formula:
//        raw_score = sum(dims[i].contrib)
//        final     = apply_delta_guard(clamp(0, 1000, raw_score),
//                                      previous_score)
//      and refuse the cert if `final != cert.score`.
//
// A cluster that publishes a fabricated score is caught: it cannot produce
// a `dims[]` whose `sum -> clamp -> delta_guard` lands on the fabricated
// score AND whose canonical-JSON hash matches the digest the cluster's
// signatures already attested to.
//
// SEEDS
//   ["score_components", agent_wallet, epoch_le]
//
// One components account per (agent, epoch), parallelling the cert PDA.
// `init` makes the write WRITE-ONCE: a second issue for the same epoch
// fails because the account already exists. The bytes are immutable from
// the moment they land on chain.
//
// ON-CHAIN INVARIANT
// ------------------
//   sha256(self.payload) == self.components_hash
//
// Enforced at write time inside `issue_certificate`. Since the account is
// write-once, the invariant is permanent. The cluster's threshold
// signatures attest to `components_hash` (folded into
// `cert_payload_digest`), so any tampering with `payload` is doubly
// caught: by the on-chain `sha256` re-check at init AND by the
// cluster-signature digest.
//
// PAYLOAD CONTENT
// ---------------
// Exactly the canonical-JSON bytes produced by
// `oracle/score_components.py::serialize_score_components` (sort_keys,
// no whitespace). Floats are pre-canonicalised to fixed-precision
// strings (9 decimal places) so byte-identical output is guaranteed on
// every Python interpreter for the same `ScoreResult`.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet            32   (Pubkey)
//   epoch                    8   (u64 — links to the paired cert)
//   components_hash         32   ([u8; 32] — sha256(payload), invariant)
//   computed_at              8   (i64 — unix seconds, mirrors cert.issued_at)
//   payload_len              4   (u32 — borsh Vec<u8> length prefix)
//   payload                  N   (Vec<u8> — N bytes of canonical JSON)
//   bump                     1   (u8)
//   layout_version           1   (u8)
//   _reserved               16   (zero cushion for small future fields)
//   TOTAL (without discriminator): 102 + N bytes
//
// The 16-byte reserve mirrors BaselineDataAccount — the payload is the
// bulky variable-length field, future expansions would more naturally
// go through `layout_version` + a fresh account.
// =============================================================================

use anchor_lang::prelude::*;

/// The maximum canonical-payload length accepted by `issue_certificate`.
/// Real payloads run < 1 KB (five fixed-shape dim entries + a handful of
/// scalars); the 4 KB cap is the safety ceiling. Anything larger means the
/// off-chain serializer drifted from the canonical form — refusing the
/// write is the right call so the issue surfaces. Mirrors
/// `oracle/score_components.py::MAX_SCORE_COMPONENTS_PAYLOAD_LEN`.
pub const MAX_SCORE_COMPONENTS_PAYLOAD_LEN: usize = 4096;

#[account]
#[derive(Debug)]
pub struct ScoreComponentsAccount {
    /// The agent this components payload belongs to. Mirrors the paired
    /// cert's `agent_wallet`.
    pub agent_wallet:    Pubkey,
    /// The epoch this components payload covers. Mirrors the paired
    /// cert's `epoch`. Combined with `agent_wallet` it is the PDA seed.
    pub epoch:           u64,
    /// SHA-256 over `payload`. Folded into the cert-payload digest the
    /// cluster signed, so the threshold signatures cryptographically
    /// attest to this exact hash. Stored here so a consumer reading
    /// only this account can verify `sha256(payload) == components_hash`
    /// without a cross-account read of the cert.
    pub components_hash: [u8; 32],
    /// Unix seconds when this components account was written. Mirrors the
    /// paired cert's `issued_at`. Used by tooling to spot a missing-DA
    /// drift (cert exists, components do not, or vice versa).
    pub computed_at:     i64,
    /// The canonical-JSON payload bytes. Exactly the bytes that
    /// `oracle/score_components.py::serialize_score_components` produces
    /// off chain. `sha256(payload) == components_hash` is enforced at
    /// write time.
    pub payload:         Vec<u8>,
    /// Canonical PDA bump.
    pub bump:            u8,
    /// Account-layout version.
    pub layout_version:  u8,
    /// Zero-padded reserve.
    pub _reserved:       [u8; 16],
}

impl ScoreComponentsAccount {
    /// The current layout version. v1 is the AW-04 initial layout.
    pub const CURRENT_LAYOUT_VERSION: u8 = 1;

    /// The PDA seed prefix.
    pub const SEED_PREFIX: &'static [u8] = b"score_components";

    /// Size of the fixed-width fields ONLY (everything except the payload's
    /// Vec<u8> contents). Used to compute the per-instruction `space` from
    /// the actual payload length at init time.
    ///
    ///   32 agent_wallet
    /// +  8 epoch
    /// + 32 components_hash
    /// +  8 computed_at
    /// +  4 payload_len (borsh Vec<u8> prefix)
    /// +  1 bump
    /// +  1 layout_version
    /// + 16 _reserved
    ///   = 102
    pub const FIXED_FIELDS_LEN: usize = 32 + 8 + 32 + 8 + 4 + 1 + 1 + 16;

    /// Total account space for a payload of `payload_len` bytes, INCLUDING
    /// the 8-byte Anchor discriminator.
    pub const fn space_for(payload_len: usize) -> usize {
        8 + Self::FIXED_FIELDS_LEN + payload_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_fields_len_matches_field_byte_count() {
        // 32 + 8 + 32 + 8 + 4 + 1 + 1 + 16 = 102
        assert_eq!(ScoreComponentsAccount::FIXED_FIELDS_LEN, 102);
    }

    #[test]
    fn space_for_includes_discriminator_and_payload() {
        // 8 (disc) + 102 (fixed) + 567 (payload) = 677
        assert_eq!(ScoreComponentsAccount::space_for(567), 8 + 102 + 567);
    }

    #[test]
    fn max_payload_constant_is_4k() {
        assert_eq!(MAX_SCORE_COMPONENTS_PAYLOAD_LEN, 4096);
    }
}
