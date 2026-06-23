// =============================================================================
// programs/certificate-issuer/tests/certificate_logic.rs
//
// Pure unit tests for the Day-18 certificate-issuer logic. These don't spin
// up a runtime — they exercise the layout constants, the AlertTier codec,
// and the score/alert consistency check in isolation. Full on-chain
// behaviour (PDA derivation, init-once, authority gating) is exercised by
// the TypeScript integration test (tests/certificate_issuer.integration.ts).
// =============================================================================

use anchor_lang::prelude::Pubkey;

use certificate_issuer::errors::CertificateError;
use certificate_issuer::instructions::issue_certificate::{
    validate_score_alert, GREEN_THRESHOLD, YELLOW_THRESHOLD,
};
use certificate_issuer::instructions::record_baseline::{
    check_baseline_commit_nonce_monotonic, check_baseline_epoch_monotonic,
    is_authorised_baseline_writer,
};
use certificate_issuer::state::{AlertTier, BaselineStats, HealthCertificate, IssuerConfig};

// =============================================================================
// Layout constants
// =============================================================================

#[test]
fn health_certificate_size_constants_are_correct() {
    //   32 + 8 + 2 + 1 + 4 + 8 + 32 + 32 + 1 + 1 + 1 + 1 = 123  (signer_count added v2)
    // + 32 input_commitment       (AW-01,     v3)        =  32
    // +  8 slot_anchor_slot       (AW-01-EXT, v4)        =   8
    // + 32 slot_anchor_hash       (AW-01-EXT, v4)        =  32
    // +  1 challenge_state        (AW-01-EXT.6, v5)      =   1
    // +  8 baseline_commit_nonce  (AW-03,     v6)        =   8  (from reserve)
    // + 32 scoring_code_hash      (AW-04,     v7)        =  32  (appended; +32 growth)
    // +  4 issuer_config_version  (M-05,      v8)        =   4  (carved from reserve)
    // +  1 taxonomy_version       (Day 38,    v9)        =   1  (carved from reserve)
    // +  8 failure_mode_bitmask   (Day 38,    v9)        =   8  (appended)
    // +  4 remediation_codes      (Day 38,    v9)        =   4  (appended)
    // + 32 diagnosis_payload_hash (Day 38,    v9)        =  32  (appended)
    // +  1 reserved                                       =   1
    // = 286 (was 242 at v8; +44 from Day 38 appends, _reserved 2 -> 1 for taxonomy carve)
    assert_eq!(HealthCertificate::SIZE_WITHOUT_DISCRIMINATOR, 286);
    assert_eq!(HealthCertificate::SPACE, 294);          // + 8 discriminator
}

#[test]
fn baseline_stats_size_constants_are_correct() {
    //   32 + 32 + 1 + 8 + 32 + 8 + 1 + 1 = 115
    // + 32 reserved                       =  32
    // = 147
    assert_eq!(BaselineStats::SIZE_WITHOUT_DISCRIMINATOR, 147);
    assert_eq!(BaselineStats::SPACE, 155);              // + 8 discriminator
}

#[test]
fn issuer_config_size_is_correct() {
    // Day 27 extends IssuerConfig with cluster_keys + threshold.
    // VULN-16 extends it further with health_oracle_program_id.
    // AW-01-EXT.6 extends it again with challenge_attester_keys + threshold.
    // M-05 appends config_version (u32) to bind the cluster signatures to
    // a specific IssuerConfig snapshot — every cert-write stamps the
    // current value and folds it into the digest.
    // H-3 appends pending_authority (32) + authority_transfer_eta (i64, 8)
    // for the two-step admin-authority transfer:
    //   8 disc + 32 authority + 32 issuer_node
    // + 4 Vec prefix + 32*5 cluster_keys reserved + 1 threshold + 1 bump
    // + 32 health_oracle_program_id
    // + 4 Vec prefix + 32*5 challenge_attester_keys reserved + 1 challenge_threshold
    // + 4 config_version                                              (M-05)
    // + 32 pending_authority + 8 authority_transfer_eta               (H-3)
    // = 479
    assert_eq!(
        IssuerConfig::SPACE,
        8 + 32 + 32 + 4 + (32 * 5) + 1 + 1 + 32 + 4 + (32 * 5) + 1 + 4 + 32 + 8,
    );
    assert_eq!(IssuerConfig::SPACE, 479);
}

#[test]
fn layout_versions_are_current() {
    // v2: signer_count added to HealthCertificate (1 byte from reserved).
    // v3: AW-01 — input_commitment added (32 bytes from reserved).
    // v4: AW-01-EXT — slot_anchor (40 bytes: 8B slot + 32B hash).
    // v5: AW-01-EXT.6 — challenge_state (1 byte, from reserved; same size as v4).
    // v6: AW-03 — baseline_commit_nonce (8 bytes, from reserved; same size as v5).
    // v7: AW-04 — scoring_code_hash (32 bytes APPENDED; size 210 -> 242).
    // v8: M-05 — issuer_config_version (u32) CARVED from the v7 _reserved
    //     (6 -> 2 bytes). Account size UNCHANGED at 242 — no realloc.
    // v9: Day 38 / Cert v2 — taxonomy_version (u8) CARVED from the v8
    //     _reserved (2 -> 1 byte); failure_mode_bitmask (u64),
    //     remediation_codes (u32), diagnosis_payload_hash ([u8; 32])
    //     APPENDED. Account size GROWS 242 -> 286 (realloc on issuance).
    assert_eq!(HealthCertificate::CURRENT_LAYOUT_VERSION, 9);
    assert_eq!(BaselineStats::CURRENT_LAYOUT_VERSION, 1);
}

#[test]
fn seed_prefixes_are_stable() {
    assert_eq!(HealthCertificate::SEED_PREFIX, b"cert");
    assert_eq!(BaselineStats::SEED_PREFIX, b"baseline");
    assert_eq!(IssuerConfig::SEED, b"issuer_config");
}

// =============================================================================
// AlertTier codec
// =============================================================================

#[test]
fn alert_tier_round_trips() {
    for tier in [AlertTier::Green, AlertTier::Yellow, AlertTier::Red] {
        assert_eq!(AlertTier::from_u8(tier.as_u8()), Some(tier));
    }
}

#[test]
fn alert_tier_codes_are_stable() {
    assert_eq!(AlertTier::Green.as_u8(), 0);
    assert_eq!(AlertTier::Yellow.as_u8(), 1);
    assert_eq!(AlertTier::Red.as_u8(), 2);
}

#[test]
fn alert_tier_rejects_invalid_code() {
    assert_eq!(AlertTier::from_u8(3), None);
    assert_eq!(AlertTier::from_u8(255), None);
}

// =============================================================================
// validate_score_alert — the score/alert consistency check
// =============================================================================

#[test]
fn green_alert_needs_high_score() {
    // GREEN at a high score — consistent.
    assert!(validate_score_alert(916, AlertTier::Green, false).is_ok());
    assert!(validate_score_alert(GREEN_THRESHOLD, AlertTier::Green, false).is_ok());
    // GREEN at a low score — inconsistent.
    assert!(validate_score_alert(500, AlertTier::Green, false).is_err());
}

#[test]
fn yellow_alert_needs_mid_score() {
    assert!(validate_score_alert(550, AlertTier::Yellow, false).is_ok());
    assert!(validate_score_alert(YELLOW_THRESHOLD, AlertTier::Yellow, false).is_ok());
    // Too high for YELLOW.
    assert!(validate_score_alert(900, AlertTier::Yellow, false).is_err());
    // Too low for YELLOW.
    assert!(validate_score_alert(100, AlertTier::Yellow, false).is_err());
}

#[test]
fn red_alert_needs_low_score() {
    assert!(validate_score_alert(120, AlertTier::Red, false).is_ok());
    assert!(validate_score_alert(YELLOW_THRESHOLD - 1, AlertTier::Red, false).is_ok());
    // A RED alert at a high score, WITHOUT immediate_red, is inconsistent.
    assert!(validate_score_alert(900, AlertTier::Red, false).is_err());
}

#[test]
fn immediate_red_forces_red_at_any_score() {
    // The IMMEDIATE_RED fast-path forces RED regardless of score — so a
    // RED tier at a HIGH score IS consistent when immediate_red is set.
    assert!(validate_score_alert(950, AlertTier::Red, true).is_ok());
    assert!(validate_score_alert(0, AlertTier::Red, true).is_ok());
}

#[test]
fn immediate_red_still_requires_red_tier() {
    // immediate_red only ever relaxes TOWARD red — it cannot make a
    // GREEN/YELLOW tier valid.
    assert!(validate_score_alert(950, AlertTier::Green, true).is_err());
    assert!(validate_score_alert(550, AlertTier::Yellow, true).is_err());
}

#[test]
fn threshold_boundaries_are_exact() {
    // Exactly at GREEN_THRESHOLD → GREEN ok, YELLOW not.
    assert!(validate_score_alert(GREEN_THRESHOLD, AlertTier::Green, false).is_ok());
    assert!(validate_score_alert(GREEN_THRESHOLD, AlertTier::Yellow, false).is_err());
    // One below → YELLOW ok, GREEN not.
    assert!(validate_score_alert(GREEN_THRESHOLD - 1, AlertTier::Yellow, false).is_ok());
    assert!(validate_score_alert(GREEN_THRESHOLD - 1, AlertTier::Green, false).is_err());
}

// =============================================================================
// VULN-06 — record_baseline authority gating
// =============================================================================

fn cfg_with(cluster_keys: Vec<Pubkey>) -> IssuerConfig {
    IssuerConfig {
        authority:                Pubkey::new_unique(),
        issuer_node:              Pubkey::new_unique(),
        cluster_keys,
        threshold:                3,
        bump:                     255,
        // VULN-16: tests for VULN-06 baseline-writer logic do not touch
        // the CPI path, so a zero allow-list is the right default.
        health_oracle_program_id: Pubkey::default(),
        // AW-01-EXT.6: baseline-writer tests are orthogonal to challenges
        // — leave the attester cluster empty + threshold 0.
        challenge_attester_keys:  Vec::new(),
        challenge_threshold:      0,
        // M-05: baseline-writer tests don't exercise the digest path; pin
        // to the genesis snapshot.
        config_version:           1,
        // H-3: no authority transfer pending.
        pending_authority:        Pubkey::default(),
        authority_transfer_eta:   0,
    }
}

#[test]
fn baseline_writer_accepts_the_agent_itself() {
    // Audit mitigation: signer == agent owner is allowed even when the
    // signer is in no cluster set.
    let agent = Pubkey::new_unique();
    let cfg = cfg_with(vec![Pubkey::new_unique(); 5]);
    assert!(is_authorised_baseline_writer(&agent, &agent, &cfg));
}

#[test]
fn baseline_writer_accepts_a_cluster_key() {
    // Audit mitigation: signer in cluster_keys (i.e., is_oracle_node).
    let agent = Pubkey::new_unique();
    let signer = Pubkey::new_unique();
    let cfg = cfg_with(vec![
        Pubkey::new_unique(), signer, Pubkey::new_unique(),
    ]);
    assert!(is_authorised_baseline_writer(&signer, &agent, &cfg));
}

#[test]
fn baseline_writer_rejects_a_random_signer() {
    // The core VULN-06 invariant: an arbitrary key cannot overwrite an
    // agent's baseline.
    let agent = Pubkey::new_unique();
    let stranger = Pubkey::new_unique();
    let cfg = cfg_with(vec![Pubkey::new_unique(), Pubkey::new_unique()]);
    assert!(!is_authorised_baseline_writer(&stranger, &agent, &cfg));
}

#[test]
fn baseline_writer_rejects_the_admin_authority() {
    // Tightening: the IssuerConfig's `authority` (admin) is NOT a baseline
    // writer unless it is ALSO a cluster key. Admins manage config; they
    // do not get to silently rotate per-agent baselines.
    let agent = Pubkey::new_unique();
    let cfg = cfg_with(vec![Pubkey::new_unique(), Pubkey::new_unique()]);
    let admin = cfg.authority;
    assert!(!is_authorised_baseline_writer(&admin, &agent, &cfg));
}

#[test]
fn baseline_writer_rejects_the_lone_issuer_node() {
    // Tightening: the single `issuer_node` rent-payer is NOT itself a
    // sufficient baseline writer in the BFT deployment. It must also be
    // listed in `cluster_keys`. (This pins the move away from the
    // pre-VULN-06 single-key gate.)
    let agent = Pubkey::new_unique();
    let cfg = cfg_with(vec![Pubkey::new_unique(), Pubkey::new_unique()]);
    let issuer_node_only = cfg.issuer_node;
    assert!(!is_authorised_baseline_writer(&issuer_node_only, &agent, &cfg));
}

// =============================================================================
// VULN-06 — append-only / monotonic-epoch invariant
// =============================================================================

/// Anchor stamps `AnchorError.error_code_number` as the enum discriminant
/// plus an internal offset (`ERROR_CODE_OFFSET = 6000`). The integration
/// test matches on the FORMATTED message (which carries the raw 6041 /
/// 6042 / 6043 number), but at the API surface we compare to the runtime
/// value — so canonicalise via this helper.
fn err_matches(e: anchor_lang::error::Error, code: CertificateError) -> bool {
    match e {
        anchor_lang::error::Error::AnchorError(a) => {
            a.error_code_number == code as u32 + anchor_lang::error::ERROR_CODE_OFFSET
        }
        _ => panic!("expected AnchorError, got: {e:?}"),
    }
}

#[test]
fn first_record_is_always_permitted() {
    // `stored_epoch == 0` is the "never recorded" sentinel; any positive
    // new epoch is allowed.
    assert!(check_baseline_epoch_monotonic(0, 1).is_ok());
    assert!(check_baseline_epoch_monotonic(0, 999_999).is_ok());
}

#[test]
fn same_epoch_rotation_is_refused() {
    // Audit mitigation: "can't change baseline more than once per epoch".
    let err = check_baseline_epoch_monotonic(7, 7).unwrap_err();
    assert!(err_matches(err, CertificateError::BaselineRotationTooSoon));
}

#[test]
fn earlier_epoch_rotation_is_refused() {
    let err = check_baseline_epoch_monotonic(10, 9).unwrap_err();
    assert!(err_matches(err, CertificateError::BaselineEpochNotMonotonic));
    let err = check_baseline_epoch_monotonic(10, 1).unwrap_err();
    assert!(err_matches(err, CertificateError::BaselineEpochNotMonotonic));
}

#[test]
fn strictly_later_epoch_rotation_is_allowed() {
    assert!(check_baseline_epoch_monotonic(7, 8).is_ok());
    assert!(check_baseline_epoch_monotonic(7, 100).is_ok());
}

#[test]
fn vuln06_error_codes_are_stable() {
    // Stability test — these codes are consumed by off-chain tooling and
    // the integration test, so they must not be silently renumbered.
    assert_eq!(CertificateError::UnauthorizedBaselineWriter as u32, 6040);
    assert_eq!(CertificateError::BaselineRotationTooSoon as u32, 6041);
    assert_eq!(CertificateError::BaselineEpochNotMonotonic as u32, 6042);
}

// ── AW-03: baseline_commit_nonce append-only monotonicity ──────────────────

#[test]
fn first_aw03_record_is_always_permitted() {
    // `stored_nonce == 0` is the legacy / never-recorded sentinel; any
    // positive new nonce is permitted on the first AW-03 write.
    assert!(check_baseline_commit_nonce_monotonic(0, 1).is_ok());
    assert!(check_baseline_commit_nonce_monotonic(0, u64::MAX).is_ok());
}

#[test]
fn aw03_same_nonce_is_refused() {
    // A same-nonce rotation would mask a stale DA pointer.
    let err = check_baseline_commit_nonce_monotonic(7, 7).unwrap_err();
    assert!(err_matches(err, CertificateError::BaselineCommitNonceNotMonotonic));
}

#[test]
fn aw03_lower_nonce_is_refused() {
    let err = check_baseline_commit_nonce_monotonic(10, 9).unwrap_err();
    assert!(err_matches(err, CertificateError::BaselineCommitNonceNotMonotonic));
    let err = check_baseline_commit_nonce_monotonic(10, 0).unwrap_err();
    // Note: 0 against a non-zero stored value is still a non-monotonic
    // attempt — the handler's separate ZeroBaselineCommitNonce gate catches
    // a fresh write of 0 upstream; this check exists for the rotation path.
    assert!(err_matches(err, CertificateError::BaselineCommitNonceNotMonotonic));
}

#[test]
fn aw03_strictly_higher_nonce_is_allowed() {
    assert!(check_baseline_commit_nonce_monotonic(7, 8).is_ok());
    assert!(check_baseline_commit_nonce_monotonic(7, 100).is_ok());
}

#[test]
fn aw03_error_codes_are_stable() {
    // The on-chain numbering is consumed by the SDK + audit gate.
    assert_eq!(CertificateError::ZeroBaselineCommitNonce as u32, 6090);
    assert_eq!(CertificateError::BaselineCommitNonceNotMonotonic as u32, 6091);
}
