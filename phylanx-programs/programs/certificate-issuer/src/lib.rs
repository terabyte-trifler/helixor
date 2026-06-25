// =============================================================================
// programs/certificate-issuer/src/lib.rs
//
// certificate-issuer — Phylanx V2's second on-chain program.
//
// Doc 2 splits the Phylanx protocol from one program into three:
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
// macros. They are toolchain noise, not Phylanx logic warnings. Keep the
// audit gate strict for our code while allowing those upstream macro cfgs.
#![allow(unexpected_cfgs, ambiguous_glob_reexports, clippy::diverging_sub_expression)]

use anchor_lang::prelude::*;

pub mod cpi_guard;
pub mod errors;
pub mod events;
pub mod instructions;
pub mod rotation;
pub mod signing;
pub mod slot_anchor;
pub mod state;

use instructions::*;

declare_id!("4bsGcUKUmvE7JHXEUFwnDYc9ejh4zfpuTuugz1ghMQW7");

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
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_config(
        ctx:                       Context<InitializeConfig>,
        issuer_node:               Pubkey,
        cluster_keys:              Vec<Pubkey>,
        threshold:                 u8,
        // H-5: one fault-domain id per cluster key (host/region). The
        // threshold is counted over distinct domains, so a quorum must span
        // `threshold` independent domains. Must be one id per key and span
        // at least `threshold` distinct domains.
        cluster_key_domains:       Vec<u16>,
        health_oracle_program_id:  Pubkey,
        // AW-01-EXT.6: third-party challenge-attester cluster. Pass
        // empty Vec + 0 threshold at deploy time to leave the
        // challenge ix disabled — the write-time `verify_slot_anchor`
        // check remains the active defence until attesters are wired.
        challenge_attester_keys:   Vec<Pubkey>,
        challenge_threshold:       u8,
    ) -> Result<()> {
        instructions::initialize_config::handler(
            ctx, issuer_node, cluster_keys, threshold, cluster_key_domains,
            health_oracle_program_id, challenge_attester_keys, challenge_threshold,
        )
    }

    /// Create or rotate an agent's BaselineStats record. A certificate
    /// stamps the baseline_hash it derives from, so the baseline must be
    /// recorded before a certificate can be issued.
    ///
    /// AW-03: `baseline_commit_nonce` is the `AgentRegistration.commit_nonce`
    /// at which `baseline_hash` was committed on the health-oracle program.
    /// Stored on BaselineStats and stamped onto every cert so a third-party
    /// verifier can derive the on-chain `BaselineDataAccount` PDA from
    /// `["baseline_data", agent, nonce_le]` and re-check
    /// `sha256(payload) == baseline_hash`. Must be non-zero and strictly
    /// monotonic versus the previously-stored nonce.
    pub fn record_baseline(
        ctx:                   Context<RecordBaseline>,
        agent_wallet:          Pubkey,
        baseline_hash:         [u8; 32],
        baseline_algo_version: u8,
        epoch:                 u64,
        baseline_commit_nonce: u64,
    ) -> Result<()> {
        instructions::record_baseline::handler(
            ctx, agent_wallet, baseline_hash, baseline_algo_version, epoch,
            baseline_commit_nonce,
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
        ctx:                      Context<IssueCertificate>,
        epoch:                    u64,
        score:                    u16,
        alert_tier:               u8,
        flags:                    u32,
        immediate_red:            bool,
        input_commitment:         [u8; 32],
        slot_anchor_slot:         u64,
        slot_anchor_hash:         [u8; 32],
        // AW-04: scoring-kernel source-bytes hash + canonical per-dimension
        // breakdown bytes. The handler computes `sha256(payload)` on chain,
        // writes it into the paired ScoreComponentsAccount, folds both
        // hashes into the cert digest the cluster signed, and refuses any
        // zero / empty / oversized AW-04 input.
        scoring_code_hash:        [u8; 32],
        score_components_payload: Vec<u8>,
        // Day 38 / Cert v2: the cluster's full diagnostic certificate —
        // u64 failure-mode bitmask, u32 remediation codes, 32-byte
        // diagnosis-payload hash, u8 taxonomy schema version. All four are
        // folded into `cert_payload_digest` so the threshold signatures
        // attest to them. The ix enforces the legacy invariant
        // `failure_mode_bitmask & 0xFFFF_FFFF == flags as u64` so every
        // v1..v8 consumer reading only `flags` continues to see consistent
        // data. Pre-Day-38 callers (none — Day 38 is the first version
        // exposing these args) would have passed `0, 0, [0; 32], 0`.
        failure_mode_bitmask:     u64,
        remediation_codes:        u32,
        diagnosis_payload_hash:   [u8; 32],
        taxonomy_version:         u8,
    ) -> Result<()> {
        instructions::issue_certificate::handler(
            ctx, epoch, score, alert_tier, flags, immediate_red,
            input_commitment, slot_anchor_slot, slot_anchor_hash,
            scoring_code_hash, score_components_payload,
            failure_mode_bitmask, remediation_codes, diagnosis_payload_hash,
            taxonomy_version,
        )
    }

    /// Read a HealthCertificate, surfacing its contents as a structured
    /// `CertificateRead` event. (Off-chain callers can also just fetch the
    /// PDA directly — this instruction is for CPI / transaction-shaped reads.)
    /// H-4: `max_age_seconds` adds an OPTIONAL on-chain freshness gate. Pass
    /// 0 to disable (legacy behaviour — the read succeeds if the PDA exists);
    /// pass a positive window to require the cert's `issued_at` be within it,
    /// else the read fails with `CertificateStale`. (Raw-PDA readers that skip
    /// this instruction MUST still enforce freshness themselves — see the
    /// `get_certificate` module docs.)
    pub fn get_certificate(
        ctx:             Context<GetCertificate>,
        agent_wallet:    Pubkey,
        epoch:           u64,
        max_age_seconds: i64,
    ) -> Result<()> {
        instructions::get_certificate::handler(ctx, agent_wallet, epoch, max_age_seconds)
    }

    /// AW-01-EXT.6 — file a challenge against a certificate's slot anchor.
    ///
    /// The challenger submits M-of-N Ed25519 precompile signatures from the
    /// configured `challenge_attester_keys` cluster over the canonical
    /// challenge digest (sha256("phylanx-aw01-ext-challenge" || cert_pubkey
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

    /// DBP-2 — Mint the on-chain "Verified Integrator" badge for a partner.
    ///
    /// The partner_wallet (transaction Signer) creates a per-partner
    /// VerifiedConsumer PDA at `["verified_consumer", partner_wallet]` that
    /// stamps the DBP-1 canonical `integration_hash` they attest to.
    /// Init-once: a second call by the same partner fails on Anchor init.
    ///
    /// See `launch/design/defi_bypass_resolution.md` and the runbook at
    /// `launch/runbooks/defi_bypass_response.md` for the full DBP closure.
    pub fn register_verified_consumer(
        ctx:              Context<RegisterVerifiedConsumer>,
        integration_hash: [u8; 32],
    ) -> Result<()> {
        instructions::register_verified_consumer::handler(ctx, integration_hash)
    }

    /// DBP-2 — Revoke a VerifiedConsumer badge.
    ///
    /// Two paths, both routed through this single ix:
    ///
    ///   * SELF-REVOKE: `signer == partner_wallet`, `revoke_reason == 1`
    ///     (PartnerSelfRevoke). Used when the partner is rotating to a
    ///     new manifest or deprecating an integration.
    ///
    ///   * ADMIN REVOKE: `signer == issuer_config.authority`,
    ///     `revoke_reason == 2` (AdminBadFaith) or `3` (AdminTerminated).
    ///     Used when a drain post-mortem traces back to the partner.
    ///
    /// The account is NOT closed — `state` flips to Revoked so downstream
    /// lending contracts can distinguish "had a badge, lost it" from
    /// "never had a badge."
    pub fn revoke_verified_consumer(
        ctx:           Context<RevokeVerifiedConsumer>,
        revoke_reason: u8,
    ) -> Result<()> {
        instructions::revoke_verified_consumer::handler(ctx, revoke_reason)
    }

    /// M-06 — Rotate the cluster signing keys with on-chain proof-of-
    /// possession.
    ///
    /// The audit finding ("rotation path commits new keys without proving
    /// knowledge of corresponding privkeys") motivates this design: every
    /// key in `new_cluster_keys` MUST produce a valid Ed25519 precompile
    /// signature over the canonical rotation digest in the SAME
    /// transaction. The digest binds (program_id, old_config_version,
    /// new_config_version, new_threshold, new_cluster_keys) so a signature
    /// captured for one rotation cannot be lifted into another.
    ///
    /// The handler also strictly increments `config_version`, which M-05
    /// bound into `cert_payload_digest` — so historical certs continue to
    /// verify under the OLD snapshot while new certs verify under the NEW
    /// snapshot. The two are cryptographically disjoint.
    pub fn rotate_cluster_keys(
        ctx:                 Context<RotateClusterKeys>,
        new_cluster_keys:    Vec<Pubkey>,
        new_threshold:       u8,
        // H-5: one fault-domain id per new key; the new cluster must span at
        // least `new_threshold` distinct domains.
        new_cluster_domains: Vec<u16>,
    ) -> Result<()> {
        instructions::rotate_cluster_keys::handler(
            ctx, new_cluster_keys, new_threshold, new_cluster_domains,
        )
    }

    /// M-6: authority-gated certificate invalidation — the on-chain recovery
    /// path for a bad-score cert. Flips the cert's challenge_state to
    /// `Invalidated` (repudiated) without mutating its signed content; the
    /// agent's next-epoch cert supersedes it. Gated on issuer_config.authority.
    pub fn invalidate_certificate(
        ctx: Context<InvalidateCertificate>,
    ) -> Result<()> {
        instructions::invalidate_certificate::handler(ctx)
    }

    /// H-3: two-step, time-locked transfer of the IssuerConfig admin
    /// authority. The current authority PROPOSES a successor; after a 48h
    /// timelock the successor ACCEPTS (proving it controls the key); the
    /// current authority may CANCEL a pending proposal in the window.
    /// Pre-H-3 `authority` was set once at init and could never change —
    /// a single compromised admin key had no remedy and a lost key bricked
    /// cluster rotation. See `transfer_authority.rs`.
    pub fn propose_authority_transfer(
        ctx:           Context<ProposeAuthorityTransfer>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::transfer_authority::propose_handler(ctx, new_authority)
    }

    /// H-3: the pending successor accepts the transfer after the timelock,
    /// atomically becoming the new `issuer_config.authority`.
    pub fn accept_authority_transfer(
        ctx: Context<AcceptAuthorityTransfer>,
    ) -> Result<()> {
        instructions::transfer_authority::accept_handler(ctx)
    }

    /// H-3: the current authority cancels a pending transfer before it is
    /// accepted (the veto path during the timelock window).
    pub fn cancel_authority_transfer(
        ctx: Context<CancelAuthorityTransfer>,
    ) -> Result<()> {
        instructions::transfer_authority::cancel_handler(ctx)
    }
}
