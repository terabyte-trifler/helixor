// =============================================================================
// programs/certificate-issuer/tests/ta6_freshness.rs
//
// TA-6: cert-freshness contract.
//
// Pure tests for HealthCertificate::is_fresh_at / is_fresh_default.
// Pins the 48h ceiling and the future-cert refusal — the SDK's
// SafeCertReader already enforces this off-chain; these tests put the
// same number on the on-chain struct so a raw-cert CPI consumer reads
// the contract directly from the program.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use certificate_issuer::state::HealthCertificate;

fn cert_at(issued_at: i64) -> HealthCertificate {
    HealthCertificate {
        agent_wallet:          Pubkey::default(),
        epoch:                 1,
        score:                 700,
        alert_tier:            0,
        flags:                 0,
        issued_at,
        issuer:                Pubkey::default(),
        baseline_hash:         [0u8; 32],
        immediate_red:         false,
        bump:                  255,
        layout_version:        HealthCertificate::CURRENT_LAYOUT_VERSION,
        signer_count:          3,
        input_commitment:      [0u8; 32],
        slot_anchor_slot:      0,
        slot_anchor_hash:      [0u8; 32],
        challenge_state:       0,
        baseline_commit_nonce: 0,
        scoring_code_hash:     [0u8; 32],
        issuer_config_version: 1,
        taxonomy_version:       0,
        failure_mode_bitmask:   0,
        remediation_codes:      0,
        diagnosis_payload_hash: [0u8; 32],
        _reserved:             [0u8; 1],
    }
}

#[test]
fn max_age_is_48_hours() {
    // Mirrors phylanx-sdk/src/safe_reader.ts CERT_MAX_AGE_SECONDS.
    assert_eq!(HealthCertificate::MAX_AGE_SECONDS, 48 * 60 * 60);
}

#[test]
fn cert_just_issued_is_fresh() {
    let now = 1_700_000_000_i64;
    let cert = cert_at(now);
    assert!(cert.is_fresh_default(now));
}

#[test]
fn cert_at_exactly_max_age_is_still_fresh() {
    // Inclusive boundary: age == MAX_AGE_SECONDS is FRESH (the cutoff
    // applies on the next second). Pinned so a future refactor doesn't
    // turn this into an off-by-one rejection of borderline-recent certs.
    let now = 2_000_000_000_i64;
    let cert = cert_at(now - HealthCertificate::MAX_AGE_SECONDS);
    assert!(cert.is_fresh_default(now));
}

#[test]
fn cert_one_second_past_max_age_is_stale() {
    let now = 2_000_000_000_i64;
    let cert = cert_at(now - HealthCertificate::MAX_AGE_SECONDS - 1);
    assert!(!cert.is_fresh_default(now));
}

#[test]
fn future_cert_is_not_fresh() {
    // Defence against clock-skew + forged-future-timestamp: a cert from
    // "the future" reads as STALE regardless of how close to `now`.
    let now = 2_000_000_000_i64;
    let cert = cert_at(now + 1);
    assert!(!cert.is_fresh_default(now));
}

#[test]
fn custom_max_age_respected() {
    // A specialised consumer (e.g. a high-frequency DEX) wants tighter
    // staleness. The custom-bound helper enforces it.
    let now = 2_000_000_000_i64;
    let cert = cert_at(now - 60); // 60s old
    assert!(cert.is_fresh_at(now, 120));   // 2 min ceiling — fresh
    assert!(!cert.is_fresh_at(now, 30));   // 30 s ceiling — stale
}

#[test]
fn negative_max_age_treated_as_zero_window() {
    // Defensive: a caller passing a negative max_age (signed-int
    // underflow, misconfig) does NOT get a "stale = false ⇒ accept all"
    // path. Always returns false.
    let now = 1_000_000_i64;
    let cert = cert_at(now);
    assert!(!cert.is_fresh_at(now, -1));
}
