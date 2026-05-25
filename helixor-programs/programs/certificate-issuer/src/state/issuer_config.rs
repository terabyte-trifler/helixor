// =============================================================================
// programs/certificate-issuer/src/state/issuer_config.rs
//
// IssuerConfig — the singleton PDA holding the certificate-issuer authority.
//
//     seeds = ["issuer_config"]
//
// DAY-27 EXTENSION: 3-of-5 threshold signing
// ------------------------------------------
// Day 18 introduced this as a single-issuer config with a Day-18 comment:
// "In Phase 4 this becomes a threshold authority." Day 27 fulfills that.
//
// The config now carries the cluster's signing keys and the consensus
// threshold. `issue_certificate` enforces — as an Anchor constraint —
// that a certificate write CARRIES `threshold` valid Ed25519 signatures
// from these keys, over the canonical certificate payload. Two signatures
// out of 5 is rejected on-chain; three is accepted.
//
// The original `issuer_node` field is RETAINED. A 1-of-1 deployment (the
// pre-Phase-4 single oracle) is the degenerate case: cluster_keys = [
// issuer_node], threshold = 1. Nothing that read issuer_node breaks.
//
// SIZING A Vec IN AN ANCHOR ACCOUNT — same approach as OracleConfig
// (health-oracle, Day 23): an account's size is fixed at creation, so we
// reserve room for the MAXIMUM cluster size; the 4-byte Borsh length
// prefix records how many are in use.
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct IssuerConfig {
    /// Admin authority -- the key that may update this config.
    pub authority:     Pubkey,
    /// The PRIMARY issuer node (degenerate single-key deployment, retained
    /// for backward compatibility -- the account that initialises an epoch
    /// or pays rent. NOT the slashing authority for cert writes; cert
    /// writes are gated on the THRESHOLD signature set below.
    pub issuer_node:   Pubkey,
    /// The cluster's signing keys -- the 1..=MAX_CLUSTER_KEYS oracle
    /// pubkeys whose Ed25519 signatures count toward the threshold.
    /// A 1-key deployment is permitted (degenerate single-node case);
    /// 2-key is rejected (no meaningful threshold).
    pub cluster_keys:  Vec<Pubkey>,
    /// The number of distinct cluster-key signatures a cert write must
    /// carry. 3 of 5 in production.
    pub threshold:     u8,
    /// Canonical PDA bump.
    pub bump:          u8,
    /// VULN-16: the canonical health-oracle program ID — the only OTHER
    /// program allowed to CPI into `issue_certificate`. A direct
    /// (top-level) call to `issue_certificate` is also accepted (the
    /// Phase-4 cluster-direct path, gated by the threshold signatures);
    /// a CPI from any other program is rejected with
    /// `UntrustedCpiCaller`. Setting `Pubkey::default()` (all-zero)
    /// DISABLES the CPI allow-list — appropriate only for a deployment
    /// that never uses the CPI path, since the threshold sigs are still
    /// the primary gate.
    pub health_oracle_program_id: Pubkey,
}

impl IssuerConfig {
    /// The maximum cluster size; the account reserves room for this many
    /// pubkeys.
    pub const MAX_CLUSTER_KEYS: usize = 5;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    ///
    ///   8  discriminator
    /// + 32 authority
    /// + 32 issuer_node
    /// + 4  cluster_keys Vec length prefix
    /// + 32 * MAX_CLUSTER_KEYS   (reserved element slots)
    /// + 1  threshold
    /// + 1  bump
    /// + 32 health_oracle_program_id           (VULN-16)
    pub const SPACE: usize =
        8 + 32 + 32 + 4 + (32 * Self::MAX_CLUSTER_KEYS) + 1 + 1 + 32;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"issuer_config";

    /// True iff `key` is one of the cluster's signing keys.
    pub fn is_cluster_key(&self, key: &Pubkey) -> bool {
        self.cluster_keys.contains(key)
    }

    /// VULN-16: True iff the CPI allow-list is enabled (i.e. the operator
    /// configured a non-zero canonical health-oracle program ID). A
    /// disabled (zero) allow-list means CPI invocations from any program
    /// are refused unless the top-level call is `certificate_issuer`
    /// itself — the safe default for a deployment that does not use the
    /// CPI path at all.
    pub fn has_health_oracle_program(&self) -> bool {
        self.health_oracle_program_id != Pubkey::default()
    }
}
