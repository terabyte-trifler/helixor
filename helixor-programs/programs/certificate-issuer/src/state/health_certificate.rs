// =============================================================================
// programs/certificate-issuer/src/state/health_certificate.rs
//
// HealthCertificate — the on-chain trust certificate for one agent, for one
// epoch.
//
// THE DOC-2 CHANGE: the MVP kept ONE certificate per agent and overwrote it
// each epoch — the on-chain record had no history. V2 keys the certificate
// by epoch:
//
//     seeds = ["cert", agent_pubkey, epoch]
//
// so every epoch gets its OWN account. epoch-1's certificate is still on
// chain, immutable, after epoch-2 is issued. The full scoring history is
// on-chain and auditable, not just the latest snapshot.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   agent_wallet            32   (Pubkey)
//   epoch                    8   (u64)
//   score                    2   (u16   — 0..1000 composite trust score)
//   alert_tier               1   (u8    — AlertTier: 0 GREEN, 1 YELLOW, 2 RED)
//   flags                    4   (u32   — aggregated detection flag bits)
//   issued_at                8   (i64   — unix seconds at issuance)
//   issuer                  32   (Pubkey — the oracle authority that issued)
//   baseline_hash           32   ([u8;32] — the baseline this score derives from)
//   immediate_red            1   (bool  — was the IMMEDIATE_RED fast-path tripped)
//   bump                     1   (u8)
//   layout_version           1   (u8)
//   signer_count             1   (u8    — how many cluster keys signed this cert)
//   input_commitment        32   ([u8;32] — AW-01 cluster-majority input commitment)
//   slot_anchor_slot         8   (u64    — AW-01-EXT Solana slot the cluster pinned)
//   slot_anchor_hash        32   ([u8;32]— AW-01-EXT Solana block hash for that slot)
//   challenge_state          1   (u8    — AW-01-EXT.6: None / Upheld / Rejected)
//   --- AW-03 (carved from _reserved, layout-compatible) ----
//   baseline_commit_nonce    8   (u64 — links to AgentRegistration.commit_nonce)
//   --- AW-04 (appended, requires realloc) ----
//   scoring_code_hash       32   ([u8;32] — sha256 of the scoring kernel
//                                  source bytes + algo/weights version
//                                  labels; see scoring/bundle_hash.py)
//   _reserved                6   (zeroed cushion; unchanged from v6)
//   TOTAL (without discriminator): 242 bytes (was 210 pre-AW-04;
//                                  +32 bytes is an explicit growth from
//                                  appending scoring_code_hash)
//
// AW-01: `input_commitment` is the 32-byte SHA-256 cluster-majority commitment
// over the canonical input transactions + windows the cluster scored. It is
// folded into the cert-payload digest (signing.rs), so the Ed25519 signature
// cryptographically attests to the INPUTS — not just to cluster agreement on
// a derived score. Storing it on the certificate lets an SDK consumer
// re-derive the commitment from observable on-chain transactions and refuse
// certs whose declared inputs do not match what they see.
//
// A certificate is WRITE-ONCE: once issued for (agent, epoch) the account
// exists and is never mutated. A re-issue attempt fails at account `init`
// (the PDA already exists). That immutability is the point — a certificate
// is a permanent record of what the oracle attested for that epoch.
// =============================================================================

use anchor_lang::prelude::*;

/// AlertTier on-chain encoding. Mirrors the off-chain scoring.AlertTier.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[borsh(use_discriminant = true)]
pub enum AlertTier {
    Green  = 0,
    Yellow = 1,
    Red    = 2,
}

/// AW-01-EXT.6: the lifecycle state of a certificate's challenge.
///   None     — never challenged. The healthy default.
///   Upheld   — a `challenge_certificate` succeeded; the cert is now
///              REPUDIATED. Downstream consumers must treat the cert as
///              invalid. The on-chain `ChallengeRecord` carries the
///              proof.
///   Rejected — a `challenge_certificate` was filed but rejected as
///              frivolous (the challenger's `true_block_hash` equalled
///              the cert's `slot_anchor_hash`). The cert is now
///              PROVABLY honest at the slot-anchor layer; the ix's
///              init-once guard prevents re-challenges.
///
/// Stored as a single u8 in `HealthCertificate._reserved` so the
/// layout grows from v4 → v5 without a realloc.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[borsh(use_discriminant = true)]
pub enum ChallengeState {
    None     = 0,
    Upheld   = 1,
    Rejected = 2,
}

impl ChallengeState {
    /// Decode a raw u8. Used by external decoders + tests.
    pub fn from_u8(v: u8) -> Option<ChallengeState> {
        match v {
            0 => Some(ChallengeState::None),
            1 => Some(ChallengeState::Upheld),
            2 => Some(ChallengeState::Rejected),
            _ => None,
        }
    }
    pub fn as_u8(self) -> u8 { self as u8 }
}

impl Default for ChallengeState {
    fn default() -> Self { ChallengeState::None }
}

impl AlertTier {
    /// Decode a raw u8 into an AlertTier. Used by the instruction to
    /// validate caller-supplied input before it is stored.
    pub fn from_u8(value: u8) -> Option<AlertTier> {
        match value {
            0 => Some(AlertTier::Green),
            1 => Some(AlertTier::Yellow),
            2 => Some(AlertTier::Red),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[account]
#[derive(Debug)]
pub struct HealthCertificate {
    /// The agent this certificate attests to.
    pub agent_wallet:   Pubkey,
    /// The scoring epoch this certificate covers. Part of the PDA seed —
    /// every epoch gets its own immutable certificate account.
    pub epoch:          u64,
    /// The composite trust score, 0..=1000.
    pub score:          u16,
    /// The alert tier (GREEN / YELLOW / RED) stored as its u8 code.
    pub alert_tier:     u8,
    /// The aggregated detection flag bits at issuance.
    pub flags:          u32,
    /// Unix seconds when the certificate was issued (on-chain Clock).
    pub issued_at:      i64,
    /// The oracle authority that issued this certificate.
    pub issuer:         Pubkey,
    /// The baseline-hash the score was derived from — links the certificate
    /// to the committed baseline on the health-oracle program.
    pub baseline_hash:  [u8; 32],
    /// True iff the IMMEDIATE_RED security fast-path was tripped this epoch.
    pub immediate_red:  bool,
    /// Canonical PDA bump.
    pub bump:           u8,
    /// Account-layout version, for future migrations.
    pub layout_version: u8,
    /// How many distinct cluster keys signed the cert digest when this
    /// certificate was issued. Stored on-chain for post-issuance audits:
    /// consumers can verify the signing quorum without replaying the tx.
    pub signer_count:   u8,
    /// AW-01: cluster-majority commitment over the canonical input
    /// transactions + windows the cluster scored. Folded into the
    /// cert-payload digest so the Ed25519 signature attests to inputs,
    /// not just to agreement on a derived score. SDK consumers re-derive
    /// the commitment from observable on-chain transactions and refuse
    /// certs whose declared inputs do not match.
    pub input_commitment: [u8; 32],
    /// AW-01-EXT: the Solana slot the cluster pinned at scoring time.
    /// Paired with `slot_anchor_hash` to verify against the SlotHashes
    /// sysvar — Solana itself attests that this slot existed and had
    /// that hash. Defends against COORDINATED upstream poisoning where
    /// every node in the cluster reads from the same compromised RPC
    /// fleet.
    pub slot_anchor_slot: u64,
    /// AW-01-EXT: the Solana block hash for `slot_anchor_slot`. Verified
    /// against the SlotHashes sysvar at issue time. SDK consumers can
    /// re-verify against `getSlotHashes()` on any RPC.
    pub slot_anchor_hash: [u8; 32],
    /// AW-01-EXT.6: lifecycle state of any filed challenge against this
    /// cert. `None` is the only state at issue time; flipped to `Upheld`
    /// or `Rejected` by `challenge_certificate`. Stored as a u8 so the
    /// layout grows v4 → v5 without realloc — consumes 1 byte of the
    /// previous `_reserved`.
    pub challenge_state: u8,
    /// AW-03: the `AgentRegistration.commit_nonce` the baseline used to
    /// produce this cert's `baseline_hash`. Stored so a consumer reading
    /// this cert can derive the exact `BaselineDataAccount` PDA from
    /// `["baseline_data", agent_wallet, baseline_commit_nonce_le]` —
    /// without it, AgentRegistration may have rotated to a newer baseline
    /// and the consumer would derive the wrong PDA. Carved from the
    /// previous 14-byte `_reserved`; legacy certs decode this as 0 (the
    /// sentinel meaning "pre-AW-03 — no DA account exists for this cert's
    /// baseline").
    pub baseline_commit_nonce: u64,
    /// AW-04: SHA-256 over the canonical scoring kernel source bytes
    /// (composite.py, weights.py, _gaming.py, determinism.py,
    /// detection/types.py) PLUS the algo + weights version labels. See
    /// `scoring/bundle_hash.py::compute_scoring_bundle_hash`. Folded into
    /// the cert-payload digest the cluster signed, so the threshold
    /// signatures cryptographically attest to the EXACT source bytes that
    /// produced this score. A consumer running `verify_score_computation`
    /// clones the helixor repo at the published tag, recomputes the
    /// bundle hash, and refuses the cert if it disagrees with this field
    /// — closing the gap where a cluster ships patched scoring code
    /// while claiming the published algo version. Appended (NOT carved
    /// from `_reserved`); cert account size grew 210 -> 242 at v7.
    /// Legacy v6 certs predate this field entirely.
    pub scoring_code_hash: [u8; 32],
    /// M-05: the `IssuerConfig.config_version` that was active when this
    /// certificate was issued. Stamped here so an off-chain verifier
    /// replaying the cert knows WHICH config snapshot the cluster signed
    /// under — a future `update_issuer_config` rotation cannot
    /// retroactively change the interpretation of historical certs.
    /// Folded into `cert_payload_digest`, so the threshold signatures
    /// cryptographically attest to the snapshot too (a malicious issuer
    /// cannot lie about which version they used). Legacy v7 certs decode
    /// this as 0 — the pre-M-05 sentinel meaning "issued before the
    /// immutability tag existed".
    pub issuer_config_version: u32,
    /// Zero-padded reserve for small future fields without a realloc.
    /// Was 14 bytes pre-AW-03; 8 bytes are AW-03's baseline_commit_nonce;
    /// AW-04's scoring_code_hash was APPENDED (not carved from reserve)
    /// so this stayed at 6 bytes. M-05 carved 4 bytes for
    /// `issuer_config_version`; 2 bytes remain.
    pub _reserved:      [u8; 2],
}

impl HealthCertificate {
    /// The current layout version.
    /// v2: added signer_count field (consumes 1 byte of previously reserved space;
    /// total account size is unchanged at 170 bytes + 8-byte discriminator).
    /// v3: AW-01 — added input_commitment [u8;32] (consumes 32 bytes of
    /// previously reserved space; total account size unchanged at 170 + 8).
    /// v4: AW-01-EXT — added slot_anchor_slot (u64) and slot_anchor_hash
    /// ([u8;32]). 40 bytes appended; total account size grows from 170 to
    /// 210 (the previous _reserved was only 15 bytes so a realloc is
    /// implicit in the new space constant).
    /// v5: AW-01-EXT.6 — added challenge_state (1 byte, from _reserved).
    /// Total account size UNCHANGED at 210 — the byte was reserved.
    /// v6: AW-03 — added baseline_commit_nonce (8 bytes, from _reserved).
    /// Total account size UNCHANGED at 210 — the 8 bytes were reserved.
    /// v7: AW-04 — APPENDED scoring_code_hash ([u8; 32]). The previous
    /// _reserved was only 6 bytes, so the 32-byte hash forces a 210 -> 242
    /// account-size growth (an explicit realloc decision; the alternative
    /// of stashing it in OracleConfig would force every consumer into a
    /// cross-account read just to verify provenance and would lose the
    /// per-cert pinning if the config rotates after issuance).
    /// v8: M-05 — CARVED `issuer_config_version` ([u32]) from the v7
    /// `_reserved` (6 -> 2 bytes). Account size UNCHANGED at 242 — no
    /// realloc. The field is folded into `cert_payload_digest` so the
    /// cluster signatures cryptographically attest to the config
    /// snapshot the cert was issued under.
    pub const CURRENT_LAYOUT_VERSION: u8 = 8;

    /// The highest valid composite score. Mirrors the off-chain 0..1000 range.
    pub const MAX_SCORE: u16 = 1000;

    /// Data size in bytes, WITHOUT the 8-byte Anchor discriminator.
    ///   32 + 8 + 2 + 1 + 4 + 8 + 32 + 32 + 1 + 1 + 1 + 1  = 123
    /// + 32 input_commitment                                =  32  (AW-01)
    /// +  8 slot_anchor_slot                                =   8  (AW-01-EXT)
    /// + 32 slot_anchor_hash                                =  32  (AW-01-EXT)
    /// +  1 challenge_state                                 =   1  (AW-01-EXT.6)
    /// +  8 baseline_commit_nonce                           =   8  (AW-03)
    /// + 32 scoring_code_hash                               =  32  (AW-04, appended)
    /// +  4 issuer_config_version                           =   4  (M-05, carved)
    /// +  2 reserved                                        =   2  (was 6 pre-M-05)
    ///    = 242 (unchanged from v7 — M-05 carved from reserve)
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 + 8 + 2 + 1 + 4 + 8 + 32 + 32 + 1 + 1 + 1 + 1 + 32 + 8 + 32 + 1 + 8 + 32 + 4 + 2;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed prefix for a certificate.
    pub const SEED_PREFIX: &'static [u8] = b"cert";

    // =========================================================================
    // TA-6: cert-freshness contract.
    //
    // THE TRUST ASSUMPTION (audit)
    // -----------------------------
    //   "DeFi protocols implement freshness checks — not enforced by
    //   Helixor."
    //
    // The off-chain SafeCertReader (helixor-sdk/src/safe_reader.ts) DOES
    // enforce a 48h ceiling. But a raw-cert consumer that bypasses the
    // SDK gets only `issued_at` on chain and no on-chain
    // recommendation of how stale is too stale. The constants + helper
    // below put that contract IN the cert struct itself so any consumer
    // — Rust, Anchor CPI, or hand-written SDK — sees the same number.
    // =========================================================================

    /// TA-6: the authoritative maximum age (in seconds) after which a
    /// certificate is considered stale. Mirrors the SDK's
    /// `CERT_MAX_AGE_SECONDS` (48 * 3600 = 172_800). A raw-cert consumer
    /// SHOULD refuse certs older than this; a CPI consumer can call
    /// `is_fresh(&clock)` below.
    pub const MAX_AGE_SECONDS: i64 = 48 * 60 * 60;

    /// TA-6: pure freshness predicate. Returns true iff the certificate
    /// is at most `max_age_seconds` old at `now_unix`. A negative result
    /// (cert from the future) also reads as STALE so a clock-skew attack
    /// cannot smuggle a forged "young" cert past the gate.
    pub fn is_fresh_at(&self, now_unix: i64, max_age_seconds: i64) -> bool {
        if max_age_seconds < 0 {
            return false;
        }
        let age = now_unix.saturating_sub(self.issued_at);
        // Cert from the future ⇒ negative age ⇒ refuse.
        age >= 0 && age <= max_age_seconds
    }

    /// TA-6: convenience wrapper that uses `MAX_AGE_SECONDS`. Suitable
    /// for direct CPI consumers that have not adopted a custom age.
    pub fn is_fresh_default(&self, now_unix: i64) -> bool {
        self.is_fresh_at(now_unix, Self::MAX_AGE_SECONDS)
    }
}
