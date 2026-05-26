// =============================================================================
// programs/certificate-issuer/src/lib.rs
//
// certificate-issuer — Helixor V2's second on-chain program.
//
// Doc 2 splits the Helixor protocol from one program into three:
//   - health-oracle       (registration + baseline commitment + scores)
//   - certificate-issuer  (THIS — the on-chain trust certificates)
//   - slash-authority     (Phase-3 later)
//
// Day 18 scaffolds certificate-issuer:
//   - HealthCertificate PDA — epoch-keyed (["cert", agent, epoch]), so the
//     per-epoch scoring HISTORY lives on chain, not just the latest cert.
//   - BaselineStats PDA     — per-agent (["baseline", agent]).
//   - IssuerConfig          — the singleton authority config.
//   - initialize_config / record_baseline / issue_certificate /
//     get_certificate instructions.
//
// Separate program => separate program ID. Replace the placeholder ID
// below with the deployed key when this is published to devnet.
// =============================================================================

// Anchor 0.30 emits internal cfgs such as `anchor-debug` from its derive
// macros. They are toolchain noise, not Helixor logic warnings. Keep the
// audit gate strict for our code while allowing those upstream macro cfgs.
#![allow(unexpected_cfgs, ambiguous_glob_reexports, clippy::diverging_sub_expression)]

use anchor_lang::prelude::*;

pub mod cpi_guard;
pub mod errors;
pub mod events;
pub mod instructions;
pub mod signing;
pub mod slot_anchor;
pub mod state;

use instructions::*;

declare_id!("Cert1xor11111111111111111111111111111111111");

#[program]
pub mod certificate_issuer {
    use super::*;

    /// One-time: create the IssuerConfig singleton.
    ///
    /// Day 27 extends this: the config now carries the cluster's signing
    /// keys and the threshold required for cert writes. `issuer_node` is
    /// retained for backward compatibility (single-key deployment / rent
    /// payer); `cluster_keys` + `threshold` are the Phase-4 BFT authority.
    ///
    /// VULN-16 (HIGH): the config also carries
    /// `health_oracle_program_id` — the canonical health-oracle program
    /// permitted to CPI into `issue_certificate`. Pass `Pubkey::default()`
    /// to refuse every CPI caller (safe for cluster-direct-only
    /// deployments). The check is enforced inside `issue_certificate`.
    pub fn initialize_config(
        ctx:                       Context<InitializeConfig>,
        issuer_node:               Pubkey,
        cluster_keys:              Vec<Pubkey>,
        threshold:                 u8,
        health_oracle_program_id:  Pubkey,
        // AW-01-EXT.6: third-party challenge-attester cluster. Pass
        // empty Vec + 0 threshold at deploy time to leave the
        // challenge ix disabled — the write-time `verify_slot_anchor`
        // check remains the active defence until attesters are wired.
        challenge_attester_keys:   Vec<Pubkey>,
        challenge_threshold:       u8,
    ) -> Result<()> {
        instructions::initialize_config::handler(
            ctx, issuer_node, cluster_keys, threshold, health_oracle_program_id,
            challenge_attester_keys, challenge_threshold,
        )
    }

    /// Create or rotate an agent's BaselineStats record. A certificate
    /// stamps the baseline_hash it derives from, so the baseline must be
    /// recorded before a certificate can be issued.
    pub fn record_baseline(
        ctx:                   Context<RecordBaseline>,
        agent_wallet:          Pubkey,
        baseline_hash:         [u8; 32],
        baseline_algo_version: u8,
        epoch:                 u64,
    ) -> Result<()> {
        instructions::record_baseline::handler(
            ctx, agent_wallet, baseline_hash, baseline_algo_version, epoch,
        )
    }

    /// Issue a HealthCertificate for an (agent, epoch). Write-once: the
    /// epoch-keyed PDA cannot be re-issued or mutated once created.
    ///
    /// AW-01: `input_commitment` is the 32-byte cluster-majority commitment
    /// over the canonical input transactions + windows the cluster scored.
    /// It is folded into the cert-payload digest so the threshold
    /// signatures attest to the INPUTS — not just to cluster agreement on
    /// a derived score. A zero commitment is rejected.
    ///
    /// AW-01-EXT: `slot_anchor_slot` + `slot_anchor_hash` is the Solana
    /// `(slot, block_hash)` the cluster pinned at scoring time. Folded
    /// into the digest AND verified against the SlotHashes sysvar — so
    /// Solana's own ledger becomes a third independent source of truth
    /// beyond the cluster's RPC fleet. A zero anchor is rejected.
    pub fn issue_certificate(
        ctx:              Context<IssueCertificate>,
        epoch:            u64,
        score:            u16,
        alert_tier:       u8,
        flags:            u32,
        immediate_red:    bool,
        input_commitment: [u8; 32],
        slot_anchor_slot: u64,
        slot_anchor_hash: [u8; 32],
    ) -> Result<()> {
        instructions::issue_certificate::handler(
            ctx, epoch, score, alert_tier, flags, immediate_red,
            input_commitment, slot_anchor_slot, slot_anchor_hash,
        )
    }

    /// Read a HealthCertificate, surfacing its contents as a structured
    /// `CertificateRead` event. (Off-chain callers can also just fetch the
    /// PDA directly — this instruction is for CPI / transaction-shaped reads.)
    pub fn get_certificate(
        ctx:          Context<GetCertificate>,
        agent_wallet: Pubkey,
        epoch:        u64,
    ) -> Result<()> {
        instructions::get_certificate::handler(ctx, agent_wallet, epoch)
    }

    /// AW-01-EXT.6 — file a challenge against a certificate's slot anchor.
    ///
    /// The challenger submits M-of-N Ed25519 precompile signatures from the
    /// configured `challenge_attester_keys` cluster over the canonical
    /// challenge digest (sha256("helixor-aw01-ext-challenge" || cert_pubkey
    /// || true_block_hash)). The handler:
    ///   1. requires the challenge cluster to be configured;
    ///   2. requires the cert to be v4+ (has a slot anchor) and unchallenged;
    ///   3. enforces a 90-day challenge window from cert issuance;
    ///   4. counts distinct attester signatures over the canonical digest;
    ///   5. compares `true_block_hash` to the cert's `slot_anchor_hash`:
    ///        - DIFFERS → Upheld   (cert REPUDIATED, event emitted)
    ///        - EQUALS  → Rejected (frivolous, challenger rent consumed)
    ///   6. writes the ChallengeRecord PDA (init-once, prevents replay).
    ///
    /// See `launch/design/aw01_ext_discrepancy_challenge.md` for the
    /// full architectural motivation.
    pub fn challenge_certificate(
        ctx:             Context<ChallengeCertificate>,
        true_block_hash: [u8; 32],
    ) -> Result<()> {
        instructions::challenge_certificate::handler(ctx, true_block_hash)
    }
}
