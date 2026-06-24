// =============================================================================
// programs/certificate-issuer/src/instructions/issue_certificate.rs
//
// issue_certificate — write a HealthCertificate for an (agent, epoch).
//
//     seeds = ["cert", agent_pubkey, epoch]
//
// The certificate PDA is created with `init`. Because the epoch is in the
// seed, every epoch has its OWN account — and because `init` fails if the
// account already exists, a certificate is WRITE-ONCE: it can never be
// re-issued or mutated for an epoch once written. That immutability is the
// guarantee a certificate is meant to provide.
//
// AUTHORITY: only the configured issuer_node (from IssuerConfig) may issue.
//
// PRECONDITION: the agent must have a recorded BaselineStats — a certificate
// stamps the baseline_hash it derives from, so the baseline must exist.
//
// VALIDATION: the score must be in range, the alert tier must be a valid
// code, and the (score, alert) pair must be CONSISTENT — a GREEN alert with
// a score of 100 would be a malformed certificate and is rejected.
// =============================================================================

use anchor_lang::prelude::*;
use solana_program::{hash::hashv, sysvar::slot_hashes};

use crate::errors::CertificateError;
use crate::events::CertificateIssued;
use crate::slot_anchor::{verify_slot_anchor, ZERO_SLOT_ANCHOR_HASH};
use crate::state::{
    AlertTier, BaselineStats, HealthCertificate, IssuerConfig,
    ScoreComponentsAccount, MAX_SCORE_COMPONENTS_PAYLOAD_LEN,
};

// Re-export to satisfy the `address = solana_program::sysvar::slot_hashes::ID`
// constraint above — anchor-lang's `prelude` does not re-export
// `solana_program::sysvar` directly, so we name it explicitly. Keeping the
// `use` here documents the dependency at the instruction layer.
#[allow(dead_code)]
const _SLOT_HASHES_ID_REF: &solana_program::pubkey::Pubkey = &slot_hashes::ID;

/// The score thresholds the on-chain consistency check uses. These mirror
/// the off-chain scoring thresholds (scoring/composite.py: GREEN >= 700,
/// YELLOW >= 400). Kept as program constants so a certificate's stored
/// (score, alert) pair is verified, not trusted.
pub const GREEN_THRESHOLD:  u16 = 700;
pub const YELLOW_THRESHOLD: u16 = 400;

/// M-12 — canonical alert-vector hash.
///
/// `validate_score_alert` verifies the (score, alert_tier, immediate_red)
/// triplet is internally consistent, but does not produce a single
/// artifact a downstream consumer can use to detect serialization-layer
/// tamper on the alert vector. M-12 stamps a SHA-256 over the canonical
/// 8-byte representation of (score, alert_tier, flags, immediate_red)
/// into the `CertificateIssued` event so an off-chain consumer can
/// recompute and compare without having to reconstruct the full
/// `cert_payload_digest` (which would require cross-account reads of
/// baseline_stats, input_commitment, etc.).
///
/// CANONICAL BYTE LAYOUT (frozen; an off-chain re-implementation must
/// produce identical bytes):
///
/// ```text
/// [0..2]   score.to_be_bytes()         //  u16 big-endian
/// [2]      alert_tier                  //  raw byte
/// [3..7]   flags.to_be_bytes()         //  u32 big-endian
/// [7]      immediate_red ? 1 : 0       //  raw byte
/// ```
///
/// Total: exactly 8 bytes. SHA-256 of these 8 bytes is the
/// `alert_vector_hash`. The function is pure — unit-testable without a
/// runtime (see tests/m12_alert_vector_binding.rs).
///
/// WHY BIG-ENDIAN: matches `cert_payload_digest`'s encoding discipline so
/// the on-chain hashing convention is uniform across the certificate
/// surface — every cluster signer + verifier emits the same bytes.
pub fn compute_alert_vector_hash(
    score:         u16,
    alert_tier:    u8,
    flags:         u32,
    immediate_red: bool,
) -> [u8; 32] {
    let immediate_red_byte: u8 = if immediate_red { 1 } else { 0 };
    let h = hashv(&[
        &score.to_be_bytes(),       // 2 bytes
        &[alert_tier],              // 1 byte
        &flags.to_be_bytes(),       // 4 bytes
        &[immediate_red_byte],      // 1 byte
    ]);
    h.to_bytes()
}

#[derive(Accounts)]
#[instruction(
    epoch:                      u64,
    score:                      u16,
    alert_tier:                 u8,
    flags:                      u32,
    immediate_red:              bool,
    input_commitment:           [u8; 32],
    slot_anchor_slot:           u64,
    slot_anchor_hash:           [u8; 32],
    scoring_code_hash:          [u8; 32],
    score_components_payload:   Vec<u8>,
    failure_mode_bitmask:       u64,
    remediation_codes:          u32,
    diagnosis_payload_hash:     [u8; 32],
    taxonomy_version:           u8,
)]
pub struct IssueCertificate<'info> {
    /// The agent's baseline record. Must exist (record_baseline first).
    /// Declared first because the certificate PDA's seeds reference
    /// `baseline_stats.agent_wallet` — Anchor resolves accounts top-down.
    #[account(
        seeds = [
            BaselineStats::SEED_PREFIX,
            baseline_stats.agent_wallet.as_ref(),
        ],
        bump = baseline_stats.bump,
    )]
    pub baseline_stats: Account<'info, BaselineStats>,

    /// The certificate PDA for this (agent, epoch). Created here; `init`
    /// makes the certificate write-once — a second issue for the same
    /// (agent, epoch) fails because the account already exists.
    #[account(
        init,
        payer = issuer,
        space = HealthCertificate::SPACE,
        seeds = [
            HealthCertificate::SEED_PREFIX,
            baseline_stats.agent_wallet.as_ref(),
            &epoch.to_le_bytes(),
        ],
        bump,
    )]
    pub certificate: Account<'info, HealthCertificate>,

    /// AW-04: the paired ScoreComponentsAccount PDA for this (agent, epoch).
    /// Created alongside the cert; `init` makes the components account
    /// write-once just like the cert. The on-chain `sha256(payload) ==
    /// components_hash` check + the cluster-signed digest binding (via
    /// `cert_payload_digest`) jointly guarantee that the published
    /// per-dimension breakdown cannot drift from what the threshold
    /// signatures attest to.
    #[account(
        init,
        payer = issuer,
        space = ScoreComponentsAccount::space_for(score_components_payload.len()),
        seeds = [
            ScoreComponentsAccount::SEED_PREFIX,
            baseline_stats.agent_wallet.as_ref(),
            &epoch.to_le_bytes(),
        ],
        bump,
    )]
    pub score_components: Account<'info, ScoreComponentsAccount>,

    /// IssuerConfig — supplies the cluster's signing keys + threshold.
    /// The cluster signatures are what authorise the write; the signer
    /// below is only the fee/rent payer (anyone may submit as long as the
    /// threshold signatures are present).
    #[account(
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The submitter — pays rent + tx fee. Day 27 NO LONGER gates on this
    /// being a fixed authority; the cluster THRESHOLD SIGNATURES gate the
    /// write instead. Anyone may submit the ix as long as the tx carries
    /// `issuer_config.threshold` valid cluster-key Ed25519 precompile
    /// signatures over the canonical cert payload.
    #[account(mut)]
    pub issuer: Signer<'info>,

    /// CHECK: the Instructions sysvar — read inside the handler to find
    /// the Ed25519 precompile instructions that carry the cluster
    /// signatures. The handler verifies this is the right sysvar pubkey.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    /// CHECK: the SlotHashes sysvar — read inside the handler to verify
    /// the AW-01-EXT slot anchor. Anchor's `Sysvar` wrapper cannot load
    /// SlotHashes (it exceeds the 10 KB Sysvar cap), so the handler reads
    /// the AccountInfo's raw bytes directly. The `address` constraint
    /// pins the expected sysvar pubkey at the Anchor layer; the handler
    /// re-checks it inside `verify_slot_anchor` as defence in depth.
    #[account(address = solana_program::sysvar::slot_hashes::ID)]
    pub slot_hashes_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx:                      Context<IssueCertificate>,
    epoch:                    u64,
    score:                    u16,
    alert_tier:               u8,
    flags:                    u32,
    immediate_red:            bool,
    // AW-01: the 32-byte cluster-majority commitment over the canonical
    // input transactions + windows. The cluster only signs a cert if a
    // quorum agreed on this commitment; folding it into the digest binds
    // the threshold signatures to the INPUTS. Refused as zero — a
    // zero commitment would let a misconfigured submitter skip the
    // input-provenance binding.
    input_commitment:         [u8; 32],
    // AW-01-EXT: the Solana `(slot, block_hash)` the cluster pinned at
    // scoring time. Folded into the cert-payload digest AND verified
    // against the SlotHashes sysvar — Solana's own ledger is the third
    // independent source of truth beyond the cluster's RPC fleet.
    // Refused as zero hash, refused if not present in the sysvar window,
    // refused if hash mismatches what Solana itself recorded.
    slot_anchor_slot:         u64,
    slot_anchor_hash:         [u8; 32],
    // AW-04: the 32-byte SHA-256 over the canonical scoring kernel source
    // bytes + algo/weights version labels (see
    // `helixor-oracle/scoring/bundle_hash.py::compute_scoring_bundle_hash`).
    // Folded into the cert-payload digest AND stamped on the cert so any
    // consumer can clone helixor at the published tag, recompute the
    // bundle hash, and refuse the cert if they disagree. Refused as zero
    // — the legacy sentinel is for pre-AW-04 callers only and
    // post-deployment writes must always supply the real hash.
    scoring_code_hash:        [u8; 32],
    // AW-04: the canonical-JSON payload bytes produced by
    // `oracle/score_components.py::serialize_score_components`. The on-
    // chain handler computes `sha256(payload)` here and (a) writes the
    // bytes into the paired ScoreComponentsAccount, (b) folds the hash
    // into the cert digest so the threshold signatures attest to it,
    // (c) refuses the write if the hash drifts from what the cluster
    // signed. Refused as empty / oversize for the same reason as
    // BaselineDataAccount: drift from the canonical form is a bug
    // that must surface, not be silently truncated.
    score_components_payload: Vec<u8>,
    // Day 38 / Cert v2: per-bit failure-mode bitmask the cluster reached
    // per-bit majority consensus on. The low 32 bits MUST equal `flags
    // as u64` — the v1..v8 invariant that `flags` is a u32 view onto the
    // same failure-mode bit field. Enforced at this layer so every legacy
    // consumer that only reads `flags` continues to read consistent data.
    failure_mode_bitmask:     u64,
    // Day 38 / Cert v2: u32 bit-set of remediation codes the cluster
    // recommends for the failure modes in `failure_mode_bitmask`. Decoded
    // against the published taxonomy schema named by `taxonomy_version`.
    remediation_codes:        u32,
    // Day 38 / Cert v2: 32-byte SHA-256 over the canonical-JSON cluster
    // diagnosis payload (see oracle/cluster/aggregation.py
    // `_payload_hash_consensus`). The payload itself is published via the
    // off-chain diagnosis DA layer; this hash is the cryptographic
    // binding the threshold signatures attest to.
    diagnosis_payload_hash:   [u8; 32],
    // Day 38 / Cert v2: u8 schema version of the failure-mode taxonomy
    // the bitmask + remediation bits are decoded against. Folded into
    // the digest so the cluster signatures attest to the schema version
    // — a future taxonomy rotation cannot retroactively re-interpret a
    // historical cert's bitmask.
    taxonomy_version:         u8,
) -> Result<()> {
    // ── VULN-16: refuse a CPI from anything but the canonical health-oracle ─
    // BEFORE we touch the inputs, before we hit the threshold-sig check,
    // before we mutate the account. The check is a few cheap sysvar reads
    // and refuses the call early — an attacker-deployed program that
    // CPI-invokes us never reaches the signature path.
    crate::cpi_guard::assert_trusted_caller(
        &ctx.accounts.instructions_sysvar.to_account_info(),
        &ctx.accounts.issuer_config,
        &crate::ID,
    )?;

    // ── Validate the inputs ─────────────────────────────────────────────────
    require!(epoch > 0, CertificateError::ZeroEpoch);
    require!(
        score <= HealthCertificate::MAX_SCORE,
        CertificateError::ScoreOutOfRange,
    );

    let tier = AlertTier::from_u8(alert_tier)
        .ok_or(CertificateError::InvalidAlertTier)?;

    // The baseline must be real — record_baseline must have run, and it
    // refuses a zero hash, so a zero hash here means no baseline.
    require!(
        ctx.accounts.baseline_stats.baseline_hash != [0u8; 32],
        CertificateError::BaselineNotRecorded,
    );

    // AW-01: refuse a zero input_commitment. A SHA-256 over real inputs is
    // statistically never zero; a literal zero here means the off-chain
    // submitter skipped the per-node + cross-node input-provenance step
    // — which is the entire AW-01 fix. We MUST fail the write loudly so
    // a misconfigured deploy never silently bypasses the binding.
    require!(
        input_commitment != [0u8; 32],
        CertificateError::MissingInputCommitment,
    );

    // AW-01-EXT: refuse a zero slot-anchor hash, and verify the
    // `(slot, hash)` pair against the SlotHashes sysvar. A failure here
    // means EITHER the cluster's entire upstream view was forged (the
    // anchor it computed differs from Solana's own record) OR the cluster
    // submitted too late (the slot has aged out of the sysvar window).
    // In both cases the cert MUST NOT issue — re-pin a fresher anchor
    // and resubmit. This is the third source-of-truth check beyond the
    // off-chain per-node and cross-node commitment binding.
    require!(
        slot_anchor_hash != ZERO_SLOT_ANCHOR_HASH,
        CertificateError::MissingSlotAnchor,
    );
    verify_slot_anchor(
        &ctx.accounts.slot_hashes_sysvar.to_account_info(),
        slot_anchor_slot,
        &slot_anchor_hash,
    )?;

    // ── AW-04: scoring-engine provenance + components binding ───────────────
    // Refuse zero `scoring_code_hash` (no scoring-kernel provenance).
    // Refuse empty/oversize payload. Compute `score_components_hash` on
    // chain (NEVER trust a caller-supplied hash; the chain is the
    // ground-truth verifier) and use it in the digest below so the
    // threshold signatures attest to the on-chain bytes — drift between
    // off-chain payload and on-chain payload is impossible by
    // construction.
    require!(
        scoring_code_hash != [0u8; 32],
        CertificateError::MissingScoringCodeHash,
    );
    require!(
        !score_components_payload.is_empty(),
        CertificateError::ScoreComponentsPayloadEmpty,
    );
    require!(
        score_components_payload.len() <= MAX_SCORE_COMPONENTS_PAYLOAD_LEN,
        CertificateError::ScoreComponentsPayloadTooLarge,
    );
    let score_components_hash: [u8; 32] =
        hashv(&[&score_components_payload]).to_bytes();
    require!(
        score_components_hash != [0u8; 32],
        CertificateError::MissingScoreComponentsHash,
    );

    // ── Day 38: legacy invariant — flags is a u32 view onto the same bits ──
    // Every v1..v8 consumer reads `flags` (u32) as the failure-mode bitmask.
    // Day 38 widens it to a u64 (`failure_mode_bitmask`). The low 32 bits of
    // the wider field MUST equal the legacy `flags as u64` so a legacy
    // consumer that only reads `flags` continues to read consistent data —
    // a cluster that publishes mismatched values is refused here, not
    // silently allowed to drift the on-chain record from the legacy view.
    require!(
        failure_mode_bitmask & 0xFFFF_FFFFu64 == flags as u64,
        CertificateError::LegacyFlagsBitmaskMismatch,
    );

    // ── Verify the (score, alert) pair is consistent ────────────────────────
    // A certificate carries both the numeric score and the categorical
    // tier; storing an inconsistent pair would be a malformed attestation.
    // The IMMEDIATE_RED fast-path is the one exception: it forces RED
    // regardless of score, so a RED+high-score pair IS valid when
    // immediate_red is set.
    validate_score_alert(score, tier, immediate_red)?;

    // ── M-12: compute the canonical alert-vector hash from the INPUTS ───────
    // This is the hash we will (a) emit in `CertificateIssued` so off-chain
    // consumers have a single canonical artifact for tamper detection on
    // the alert vector, and (b) re-derive AFTER the cert write from the
    // WRITTEN cert account fields to catch any field-shadow / write-slot
    // bug a future refactor could introduce. The handler is the canonical
    // producer of this hash; computing it pre-write here pins what the
    // post-write recompute MUST match.
    let alert_vector_hash_from_inputs = compute_alert_vector_hash(
        score,
        tier.as_u8(),
        flags,
        immediate_red,
    );

    // ── DAY 27: verify the THRESHOLD SIGNATURES from the cluster ────────────
    // The cert payload (the canonical digest of agent/epoch/score/tier/
    // flags/baseline_hash/immediate_red) MUST have been signed by at least `threshold`
    // distinct cluster keys, via Ed25519 precompile instructions in this
    // same transaction. Below threshold -> InsufficientSignatures -> ix
    // fails. This is the on-chain enforcement of 3-of-5 (or whatever the
    // configured threshold is).
    // AW-03: bind the digest to the SPECIFIC baseline rotation. The cluster
    // wrote `baseline_commit_nonce` into BaselineStats on `record_baseline`;
    // we read it back here and fold it into the digest so the threshold
    // signatures attest to a fetchable on-chain DA account, not just to a
    // raw 32-byte hash. Legacy stats decode this as 0 (the pre-AW-03
    // sentinel — see BaselineStats docstring); 0 still folds in deterministically.
    let baseline_commit_nonce = ctx.accounts.baseline_stats.baseline_commit_nonce;
    // M-05: snapshot the current `IssuerConfig.config_version` and fold
    // it into the digest. The cluster's off-chain signer reads the same
    // value from the same on-chain account, so signatures over THIS
    // version verify here and only here. A future config rotation that
    // bumps `config_version` cannot retroactively re-interpret this cert.
    let issuer_config_version = ctx.accounts.issuer_config.config_version;

    let digest = crate::signing::cert_payload_digest(
        &ctx.accounts.baseline_stats.agent_wallet,
        epoch, score, alert_tier, flags,
        &ctx.accounts.baseline_stats.baseline_hash,
        immediate_red,
        &input_commitment,        // AW-01: binds the cluster's input view
        slot_anchor_slot,         // AW-01-EXT: binds the Solana slot anchor
        &slot_anchor_hash,
        baseline_commit_nonce,    // AW-03: binds the baseline rotation
        &scoring_code_hash,       // AW-04: binds the scoring-kernel source bytes
        &score_components_hash,   // AW-04: binds the per-dim breakdown
        issuer_config_version,    // M-05: binds the config snapshot
        failure_mode_bitmask,     // Day 38: binds the u64 failure-mode bitmask
        remediation_codes,        // Day 38: binds the u32 remediation codes
        &diagnosis_payload_hash,  // Day 38: binds the diagnosis payload
        taxonomy_version,         // Day 38: binds the taxonomy schema version
    );
    let valid_signers = crate::signing::verify_threshold_signatures(
        &digest,
        &ctx.accounts.issuer_config,
        &ctx.accounts.instructions_sysvar.to_account_info(),
    )?;

    // ── Write the certificate ───────────────────────────────────────────────
    let clock = Clock::get()?;
    let issued_at = clock.unix_timestamp;

    // ── H-4 / NSS-3: agent-age floor for a GREEN tier ──────────────────────
    // A GREEN ("fully trusted") certificate may NOT be issued for an agent
    // younger than MIN_GREEN_AGE_SECONDS (14 days) since its FIRST recorded
    // baseline. This is the on-chain backstop against set-up-and-borrow /
    // score-inflation: a brand-new wallet cannot present a GREEN cert even to
    // a consumer that reads the raw PDA and bypasses the off-chain SDK. The
    // floor is anchored on the tamper-proof `BaselineStats.first_recorded_at`
    // Clock timestamp, NOT on a caller-supplied epoch. (YELLOW/RED carry no
    // age floor; the IMMEDIATE_RED fast-path forces RED, never GREEN.)
    if tier == AlertTier::Green {
        require!(
            green_age_floor_satisfied(
                ctx.accounts.baseline_stats.first_recorded_at,
                issued_at,
            ),
            CertificateError::AgentTooYoungForGreen,
        );
    }

    let cert = &mut ctx.accounts.certificate;

    cert.agent_wallet      = ctx.accounts.baseline_stats.agent_wallet;
    cert.epoch             = epoch;
    cert.score             = score;
    cert.alert_tier        = tier.as_u8();
    cert.flags             = flags;
    cert.issued_at         = issued_at;
    cert.issuer            = ctx.accounts.issuer.key();
    cert.baseline_hash     = ctx.accounts.baseline_stats.baseline_hash;
    cert.immediate_red     = immediate_red;
    cert.bump              = ctx.bumps.certificate;
    cert.layout_version    = HealthCertificate::CURRENT_LAYOUT_VERSION;
    cert.signer_count      = valid_signers;
    cert.input_commitment  = input_commitment;       // AW-01
    cert.slot_anchor_slot  = slot_anchor_slot;       // AW-01-EXT
    cert.slot_anchor_hash  = slot_anchor_hash;       // AW-01-EXT
    // AW-03: stamp the baseline rotation onto the cert so SDK consumers
    // can derive the BaselineDataAccount PDA without re-reading
    // BaselineStats (whose nonce may have rotated forward after issuance).
    cert.baseline_commit_nonce = baseline_commit_nonce;
    // AW-04: stamp the scoring-kernel source-bytes hash onto the cert. The
    // hash is folded into the digest above so the threshold signatures
    // attest to it; storing it on the cert lets any consumer verify
    // provenance with a single account read (no cross-account fetch of
    // a config or a registry — old certs remain verifiable even if a
    // future deploy rotates a config).
    cert.scoring_code_hash     = scoring_code_hash;
    // M-05: stamp the config snapshot onto the cert. The version was
    // already folded into the digest above so the cluster signatures
    // attest to it; storing it here lets a consumer reading just the
    // cert account look up the exact historical `IssuerConfig` snapshot
    // (e.g. in an off-chain mirror) without re-deriving it from the
    // current on-chain config.
    cert.issuer_config_version = issuer_config_version;
    // Day 38 / Cert v2: stamp the cluster-diagnosis fields. All four
    // were folded into the digest above, so the threshold signatures
    // cryptographically attest to them. Storing them on the cert lets
    // an off-chain consumer fetch the full diagnostic certificate in
    // ONE account read — no need to reconstruct anything from off-chain
    // sources to know what the cluster claimed went wrong.
    cert.failure_mode_bitmask   = failure_mode_bitmask;
    cert.remediation_codes      = remediation_codes;
    cert.diagnosis_payload_hash = diagnosis_payload_hash;
    cert.taxonomy_version       = taxonomy_version;

    // AW-04: populate the paired ScoreComponentsAccount. Write-once at
    // init; the on-chain `sha256(payload) == components_hash` invariant
    // is the chain's ground-truth check that the published bytes match
    // the cluster-signed digest.
    let components = &mut ctx.accounts.score_components;
    components.agent_wallet    = ctx.accounts.baseline_stats.agent_wallet;
    components.epoch           = epoch;
    components.components_hash = score_components_hash;
    components.computed_at     = clock.unix_timestamp;
    components.payload         = score_components_payload;
    components.bump            = ctx.bumps.score_components;
    components.layout_version  = ScoreComponentsAccount::CURRENT_LAYOUT_VERSION;

    // ── M-12: post-write recompute the alert-vector hash from the WRITTEN
    // cert account fields and assert it equals the input-args hash. This
    // catches a future refactor that field-shadow-writes the wrong cert
    // slot (e.g. swapping `cert.score = ...` with `cert.flags = ...`) so
    // the event cannot carry an alert_vector_hash that disagrees with
    // the on-chain stored bytes a consumer would read.
    let alert_vector_hash_from_cert = compute_alert_vector_hash(
        cert.score,
        cert.alert_tier,
        cert.flags,
        cert.immediate_red,
    );
    require!(
        alert_vector_hash_from_cert == alert_vector_hash_from_inputs,
        CertificateError::InvalidAlertVectorBinding,
    );

    emit!(CertificateIssued {
        agent_wallet:  cert.agent_wallet,
        epoch,
        score,
        alert_tier:    cert.alert_tier,
        flags,
        immediate_red,
        issuer:        cert.issuer,
        issued_at:     cert.issued_at,
        alert_vector_hash: alert_vector_hash_from_cert,
    });

    msg!(
        "certificate issued: agent={} epoch={} score={} tier={:?} signers={}/{}",
        cert.agent_wallet, epoch, score, tier,
        valid_signers, ctx.accounts.issuer_config.threshold,
    );
    Ok(())
}

/// Verify a (score, alert_tier) pair is internally consistent.
///
/// Pure — extracted so it is unit-testable without a runtime (see
/// tests/certificate_logic.rs).
///
///   GREEN  needs score >= GREEN_THRESHOLD
///   YELLOW needs YELLOW_THRESHOLD <= score < GREEN_THRESHOLD
///   RED    needs score < YELLOW_THRESHOLD
///
/// EXCEPTION: when `immediate_red` is set, the security fast-path forced a
/// RED tier irrespective of the numeric score — so RED is valid at ANY
/// score. immediate_red therefore only ever RELAXES the check (toward RED).
pub fn validate_score_alert(
    score:         u16,
    tier:          AlertTier,
    immediate_red: bool,
) -> Result<()> {
    // The fast-path forced RED — any score is consistent with that.
    if immediate_red {
        require!(
            tier == AlertTier::Red,
            CertificateError::InconsistentScoreAlert,
        );
        return Ok(());
    }

    let consistent = match tier {
        AlertTier::Green  => score >= GREEN_THRESHOLD,
        AlertTier::Yellow => (YELLOW_THRESHOLD..GREEN_THRESHOLD).contains(&score),
        AlertTier::Red    => score < YELLOW_THRESHOLD,
    };
    require!(consistent, CertificateError::InconsistentScoreAlert);
    Ok(())
}

/// H-4 / NSS-3 — pure agent-age floor predicate for a GREEN certificate.
///
/// Returns true iff a GREEN tier is permitted for an agent whose FIRST
/// baseline was recorded at `first_recorded_at` (unix seconds), for a cert
/// being issued at `issued_at` (unix seconds). Split out so it is
/// unit-testable without an Anchor `Context`.
///
///   * `first_recorded_at == 0` is the legacy / grandfather sentinel (pre-H-4
///     accounts, or the zeroed reserve): the floor is SKIPPED. This is safe
///     because a fresh post-H-4 agent always receives a real Clock timestamp
///     on its first `record_baseline`, so an attacker's new wallet can never
///     present 0.
///   * `saturating_sub` makes a pathological future `first_recorded_at` read
///     as age 0 — fail-closed for GREEN.
pub fn green_age_floor_satisfied(first_recorded_at: i64, issued_at: i64) -> bool {
    if first_recorded_at == 0 {
        return true;
    }
    issued_at.saturating_sub(first_recorded_at) >= HealthCertificate::MIN_GREEN_AGE_SECONDS
}
