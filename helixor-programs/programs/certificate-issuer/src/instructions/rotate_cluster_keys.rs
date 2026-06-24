// =============================================================================
// programs/certificate-issuer/src/instructions/rotate_cluster_keys.rs
//
// M-06 — Rotate the cluster signing keys with on-chain PROOF-OF-POSSESSION.
//
// Pre-M-06 there was no rotation instruction at all; in practice this meant
// the only way to change `cluster_keys` was to redeploy IssuerConfig (a
// painful, full-cutover migration). The audit flagged the LATENT risk:
// whenever someone DID add a rotation handler, the obvious naive design
// ("admin authority signer + new key list -> overwrite") admits the
// fat-finger / hostile-key / replay attacks documented in `rotation.rs`.
//
// This handler ships rotation the right way:
//
//   1. Admin authority signs the tx (the existing IssuerConfig.authority).
//   2. The new cluster set is validated against the SAME shape rules as
//      `initialize_config` (size in {1, 3..=5}, no dups, threshold range,
//      strict-majority for BFT clusters).
//   3. Every key in the NEW set must produce a valid Ed25519 precompile
//      signature over the canonical `rotation_digest(program_id,
//      old_version, new_version, new_threshold, new_keys)` — see
//      `rotation.rs` for the digest layout and PoP semantics.
//   4. config_version is strictly incremented (saturating in the sense
//      that the u32 ceiling is a hard error, not a wrap).
//   5. A `ClusterKeysRotated` event records the (old, new) versions.
//
// M-05 INTEROP
// ------------
// `config_version` is folded into `cert_payload_digest`. Bumping it here
// means historical certs (signed against the OLD version) STILL verify —
// the cluster's recorded signatures hash against `old_config_version`, so
// `verify_threshold_signatures` against a historical cert re-derives the
// SAME bytes if (and only if) the verifier supplies the old version. A
// post-rotation cert hashes against `new_config_version` and verifies
// against the NEW cluster. The two snapshots are cleanly disjoint.
// =============================================================================

use anchor_lang::prelude::*;

use crate::errors::CertificateError;
use crate::events::ClusterKeysRotated;
use crate::rotation::{rotation_digest, verify_rotation_pop};
use crate::state::IssuerConfig;

#[derive(Accounts)]
pub struct RotateClusterKeys<'info> {
    /// IssuerConfig — the singleton being mutated. Authority gate is
    /// applied in the handler (Anchor's `has_one = authority` would
    /// pin only the authority field; we want a stricter check that
    /// the signer is the SAME key).
    #[account(
        mut,
        seeds = [IssuerConfig::SEED],
        bump  = issuer_config.bump,
    )]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The admin signer. Must equal `issuer_config.authority`.
    pub authority: Signer<'info>,

    /// CHECK: the Instructions sysvar — required so `verify_rotation_pop`
    /// can walk the transaction's instructions to find the per-new-key
    /// Ed25519 precompile signatures. The address is pinned against the
    /// canonical sysvar ID so the caller cannot swap in a fake.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

pub fn handler(
    ctx:                 Context<RotateClusterKeys>,
    new_cluster_keys:    Vec<Pubkey>,
    new_threshold:       u8,
    // H-5: one fault-domain id per new key (see initialize_config). The new
    // cluster must span at least `new_threshold` distinct domains.
    new_cluster_domains: Vec<u16>,
) -> Result<()> {
    let config = &mut ctx.accounts.issuer_config;

    // ── 1. Authority gate ───────────────────────────────────────────────────
    require_keys_eq!(
        ctx.accounts.authority.key(),
        config.authority,
        CertificateError::NotIssuerAuthority,
    );

    // ── 2. New-cluster shape rules (mirror initialize_config) ───────────────
    require!(
        !new_cluster_keys.is_empty()
            && new_cluster_keys.len() <= IssuerConfig::MAX_CLUSTER_KEYS,
        CertificateError::InvalidClusterSize,
    );
    require!(
        new_cluster_keys.len() != 2,
        CertificateError::InvalidClusterSize,
    );
    for i in 0..new_cluster_keys.len() {
        for j in (i + 1)..new_cluster_keys.len() { // audit: bounded by Vec.len()
            require!(
                new_cluster_keys[i] != new_cluster_keys[j],
                CertificateError::DuplicateClusterKey,
            );
        }
    }
    // H-01: defer to the centralised strict-majority helper. Both write
    // paths (initialize_config + rotate_cluster_keys) call the same
    // helper so they cannot drift.
    require!(
        IssuerConfig::is_strict_majority_threshold(new_threshold, new_cluster_keys.len()),
        CertificateError::InvalidThreshold,
    );

    // ── 2a. H-2: BFT no-downgrade floor ─────────────────────────────────────
    // The strict-majority + `!= 2` checks above still permit collapsing a
    // BFT cluster all the way to a SINGLE key (size 1, threshold 1) — and the
    // M-06 proof-of-possession is trivially satisfiable by the attacker's own
    // key. A compromised `authority` could therefore rotate a 3-of-5 quorum
    // to 1-of-1 and forge every certificate with one signature. Forbid it:
    // once the CURRENT cluster is BFT (>= MIN_BFT_CLUSTER_KEYS), the NEW
    // cluster must remain BFT. `config.cluster_keys` still holds the OLD set
    // here (the commit at step 6 has not run yet).
    //
    // initialize_config may legitimately bootstrap a degenerate single-issuer
    // cluster (size 1); such a sub-BFT cluster may still rotate in place
    // (1 -> 1 key swap) or PROMOTE to BFT (1 -> {3,4,5}). It simply cannot be
    // the *source* of a downgrade, because it was never BFT to begin with.
    // Shrinking WITHIN the BFT range (e.g. 5 -> 3 to decommission nodes) stays
    // allowed — only dropping below the floor is refused.
    require!(
        IssuerConfig::rotation_preserves_bft_floor(
            config.cluster_keys.len(),
            new_cluster_keys.len(),
        ),
        CertificateError::ClusterBftFloorViolation,
    );

    // ── 2b. H-5: fault-domain map for the new cluster ───────────────────────
    // One domain id per new key, and the new cluster must span at least
    // `new_threshold` distinct domains (else the rotation would brick cert
    // issuance under the domain-diversity quorum rule).
    require!(
        new_cluster_domains.len() == new_cluster_keys.len(),
        CertificateError::ClusterDomainsLengthMismatch,
    );
    require!(
        IssuerConfig::config_distinct_domain_count(&new_cluster_domains)
            >= new_threshold as usize,
        CertificateError::InsufficientDomainDiversity,
    );

    // ── 3. Reject no-op rotations ───────────────────────────────────────────
    // A rotation that changes neither keys nor threshold is operationally
    // pointless AND would consume a config_version slot without buying any
    // security. Reject so an indexer reading the on-chain event log sees
    // EVERY config_version bump as a real key/threshold change.
    let same_keys = config.cluster_keys == new_cluster_keys;
    let same_threshold = config.threshold == new_threshold;
    require!(
        !(same_keys && same_threshold),
        CertificateError::RotationNoOpRejected,
    );

    // ── 4. Bump config_version with overflow guard ──────────────────────────
    let old_config_version = config.config_version;
    let new_config_version = old_config_version
        .checked_add(1)
        .ok_or(CertificateError::RotationConfigVersionOverflow)?;

    // ── 5. PoP: every new key must sign the rotation digest ─────────────────
    let digest = rotation_digest(
        ctx.program_id,
        old_config_version,
        new_config_version,
        new_threshold,
        &new_cluster_keys,
    );
    verify_rotation_pop(
        &digest,
        &new_cluster_keys,
        &ctx.accounts.instructions_sysvar.to_account_info(),
    )?;

    // ── 6. Commit + audit-trail event ───────────────────────────────────────
    let new_cluster_size = new_cluster_keys.len() as u8;
    config.cluster_keys        = new_cluster_keys;
    config.threshold           = new_threshold;
    config.config_version      = new_config_version;
    // H-5: rotate the fault-domain map alongside the keys.
    config.cluster_key_domains = new_cluster_domains;

    let clock = Clock::get()?;
    emit!(ClusterKeysRotated {
        authority:          ctx.accounts.authority.key(),
        old_config_version,
        new_config_version,
        new_cluster_size,
        new_threshold,
        rotated_at_unix:    clock.unix_timestamp,
    });

    msg!(
        "cluster_keys rotated: config_version {} -> {}, {}-key cluster, threshold {}-of-{}",
        old_config_version, new_config_version,
        new_cluster_size, new_threshold, new_cluster_size,
    );
    Ok(())
}
