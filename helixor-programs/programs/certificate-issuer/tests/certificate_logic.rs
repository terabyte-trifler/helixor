// =============================================================================
// programs/certificate-issuer/tests/certificate_logic.rs
//
// Pure unit tests for the Day-18 certificate-issuer logic. These don't spin
// up a runtime — they exercise the layout constants, the AlertTier codec,
// and the score/alert consistency check in isolation. Full on-chain
// behaviour (PDA derivation, init-once, authority gating) is exercised by
// the TypeScript integration test (tests/certificate_issuer.integration.ts).
// =============================================================================

use certificate_issuer::instructions::issue_certificate::{
    validate_score_alert, GREEN_THRESHOLD, YELLOW_THRESHOLD,
};
use certificate_issuer::state::{AlertTier, BaselineStats, HealthCertificate, IssuerConfig};

// =============================================================================
// Layout constants
// =============================================================================

#[test]
fn health_certificate_size_constants_are_correct() {
    //   32 + 8 + 2 + 1 + 4 + 8 + 32 + 32 + 1 + 1 + 1 = 122
    // + 48 reserved                                   =  48
    // = 170
    assert_eq!(HealthCertificate::SIZE_WITHOUT_DISCRIMINATOR, 170);
    assert_eq!(HealthCertificate::SPACE, 178);          // + 8 discriminator
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
    // Day 27 extends IssuerConfig with cluster_keys + threshold:
    //   8 disc + 32 authority + 32 issuer_node
    // + 4 Vec prefix + 32*5 reserved key slots + 1 threshold + 1 bump = 238
    assert_eq!(IssuerConfig::SPACE, 8 + 32 + 32 + 4 + (32 * 5) + 1 + 1);
    assert_eq!(IssuerConfig::SPACE, 238);
}

#[test]
fn layout_versions_start_at_one() {
    assert_eq!(HealthCertificate::CURRENT_LAYOUT_VERSION, 1);
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
