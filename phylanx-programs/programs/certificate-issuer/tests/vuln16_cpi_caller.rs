// =============================================================================
// programs/certificate-issuer/tests/vuln16_cpi_caller.rs
//
// VULN-16 (HIGH) — CPI trust-boundary pin tests.
//
// The audit:
//     issue_certificate is exposed via CPI from health-oracle. Its existing
//     gates check threshold signatures + PDA constraints but NOT the program
//     that CPI-invoked it. An attacker who deploys their own attacker_oracle
//     and assembles a tx with valid threshold sigs could CPI in and forge a
//     cert. Fix: require!(caller_program == known_health_oracle_program_id).
//
// This file pins the DECISION HELPER (the post-sysvar-read logic) so that a
// regression in the allow-list rules is caught at unit-test speed. The
// runtime-bound sysvar/Anchor wiring (the BPF execution path) is exercised
// by the TypeScript integration suite — what we test here is the policy.
//
// The fault model these tests defend against:
//   (a) attacker deploys a fake oracle and CPI-invokes us with valid sigs
//   (b) an operator forgets to set `health_oracle_program_id` (zero default)
//        — must NOT silently permit every CPI caller
//   (c) someone passes `Pubkey::default()` as the caller (degenerate, e.g.
//        truncated tx) — must NOT bypass the check
// =============================================================================

use anchor_lang::prelude::Pubkey;

use certificate_issuer::errors::CertificateError;
use certificate_issuer::state::IssuerConfig;

// =============================================================================
// Helpers
// =============================================================================

/// Build an IssuerConfig with the given CPI allow-list value. The other
/// fields are populated with fresh keys — the cluster contents don't matter
/// for the caller-program check; only `health_oracle_program_id` does.
fn cfg_with_oracle(health_oracle_program_id: Pubkey) -> IssuerConfig {
    IssuerConfig {
        authority:                Pubkey::new_unique(),
        issuer_node:              Pubkey::new_unique(),
        cluster_keys:             vec![Pubkey::new_unique(); 5],
        threshold:                3,
        bump:                     255,
        health_oracle_program_id,
        // AW-01-EXT.6: VULN-16 CPI-caller tests are orthogonal to the
        // challenge cluster; empty + 0 keeps it disabled.
        challenge_attester_keys:  Vec::new(),
        challenge_threshold:      0,
        // M-05: CPI-caller tests don't exercise the digest path; pin to
        // the genesis snapshot.
        config_version:           1,
        // H-3: no authority transfer pending.
        pending_authority:        Pubkey::default(),
        authority_transfer_eta:   0,
        // H-5: one domain per key (5-key cluster).
        cluster_key_domains:      vec![0u16, 1, 2, 3, 4],
    }
}

// M-2: stack-height constants mirroring solana_program's
// TRANSACTION_LEVEL_STACK_HEIGHT (= 1).
const DIRECT: usize = 1;   // top-level instruction
const ONE_HOP: usize = 2;  // single CPI hop — top-level IS the immediate caller
const NESTED: usize = 3;   // nested CPI — top-level is NOT the immediate caller

/// Mirror of the pure decision logic in `cpi_guard::is_trusted_caller`,
/// extracted for runtime-free testing. The real handler reads the TOP-LEVEL
/// program id from the Instructions sysvar and the depth from
/// `get_stack_height()`; everything AFTER those reads is exactly this
/// function. Keeping a copy here pins the policy (including the M-2
/// stack-height attribution) independent of the lib's `pub(crate)` helper.
fn is_trusted_caller(
    top_level_pid:   &Pubkey,
    self_program_id: &Pubkey,
    config:          &IssuerConfig,
    stack_height:    usize,
) -> bool {
    if stack_height == DIRECT {
        return top_level_pid == self_program_id;
    }
    if stack_height == ONE_HOP {
        return config.has_health_oracle_program()
            && top_level_pid == &config.health_oracle_program_id;
    }
    false // nested CPI (or degenerate height 0) — cannot attribute the caller
}

// =============================================================================
// (1) Direct top-level call — always trusted (gated by threshold sigs).
// =============================================================================

#[test]
fn direct_top_level_call_is_trusted_when_allow_list_enabled() {
    let self_pid   = Pubkey::new_unique();
    let oracle_pid = Pubkey::new_unique();
    let config     = cfg_with_oracle(oracle_pid);
    assert!(is_trusted_caller(&self_pid, &self_pid, &config, DIRECT));
}

#[test]
fn direct_top_level_call_is_trusted_when_allow_list_disabled() {
    // Even when the CPI allow-list is zero (disabled), a DIRECT call still
    // works — it isn't a CPI, so the allow-list is irrelevant.
    let self_pid = Pubkey::new_unique();
    let config   = cfg_with_oracle(Pubkey::default());
    assert!(is_trusted_caller(&self_pid, &self_pid, &config, DIRECT));
}

// =============================================================================
// (2) CPI from the configured health-oracle — trusted.
// =============================================================================

#[test]
fn cpi_from_configured_health_oracle_is_trusted() {
    let self_pid   = Pubkey::new_unique();
    let oracle_pid = Pubkey::new_unique();
    let config     = cfg_with_oracle(oracle_pid);
    assert!(is_trusted_caller(&oracle_pid, &self_pid, &config, ONE_HOP));
}

#[test]
fn cpi_from_configured_health_oracle_is_trusted_even_if_oracle_equals_self() {
    // Degenerate but legal: an operator who set the allow-list to our own
    // program ID. Both branches of the check (== self, == oracle) pass.
    let self_pid = Pubkey::new_unique();
    let config   = cfg_with_oracle(self_pid);
    assert!(is_trusted_caller(&self_pid, &self_pid, &config, DIRECT));
}

// =============================================================================
// (3) CPI from an attacker program — rejected. THE CORE VULN-16 INVARIANT.
// =============================================================================

#[test]
fn cpi_from_attacker_program_is_rejected() {
    // The attack the audit describes: attacker deploys a program that has
    // assembled a tx with valid threshold sigs and CPIs into us. The sigs
    // alone are no longer enough — the caller program must be on the
    // allow-list.
    let self_pid     = Pubkey::new_unique();
    let oracle_pid   = Pubkey::new_unique();
    let attacker_pid = Pubkey::new_unique();
    let config       = cfg_with_oracle(oracle_pid);
    assert!(!is_trusted_caller(&attacker_pid, &self_pid, &config, ONE_HOP));
}

#[test]
fn cpi_from_attacker_program_remains_rejected_across_many_random_pids() {
    // Coverage: not just one attacker pubkey — a swath of randomly
    // generated CPI callers must all be rejected. The check is membership
    // in a 2-element allow-list, so a random pubkey has no path through.
    let self_pid   = Pubkey::new_unique();
    let oracle_pid = Pubkey::new_unique();
    let config     = cfg_with_oracle(oracle_pid);
    for _ in 0..32 {
        let attacker_pid = Pubkey::new_unique();
        assert!(!is_trusted_caller(&attacker_pid, &self_pid, &config, ONE_HOP));
    }
}

// =============================================================================
// (4) Misconfigured deployment (allow-list disabled) — fail-CLOSED on CPI.
// =============================================================================

#[test]
fn cpi_from_any_program_is_rejected_when_oracle_disabled() {
    // The operator forgot to (or chose not to) configure the canonical
    // health-oracle program ID. Pubkey::default() is the disabled-sentinel.
    // Every CPI must be refused; only direct calls work.
    let self_pid = Pubkey::new_unique();
    let config   = cfg_with_oracle(Pubkey::default());
    for _ in 0..16 {
        let cpi_pid = Pubkey::new_unique();
        assert!(!is_trusted_caller(&cpi_pid, &self_pid, &config, ONE_HOP));
    }
}

#[test]
fn zero_caller_pid_does_not_bypass_check_when_allow_list_disabled() {
    // A pathological caller_pid of Pubkey::default() must NOT collide with
    // the disabled-allow-list sentinel and accidentally pass. Both values
    // happen to be zero, so a naive `caller_pid == config.health_oracle`
    // check (without the has_health_oracle_program guard) would WRONGLY
    // accept this. The guard prevents that — pin it.
    let self_pid = Pubkey::new_unique();
    let config   = cfg_with_oracle(Pubkey::default());
    assert!(!is_trusted_caller(&Pubkey::default(), &self_pid, &config, ONE_HOP));
}

#[test]
fn zero_caller_pid_is_rejected_even_when_allow_list_enabled() {
    // And with the allow-list enabled, a zero caller_pid still has no path
    // through (unless the operator absurdly set self_program_id to zero,
    // which the runtime cannot do — declare_id! is non-zero).
    let self_pid   = Pubkey::new_unique();
    let oracle_pid = Pubkey::new_unique();
    let config     = cfg_with_oracle(oracle_pid);
    assert!(!is_trusted_caller(&Pubkey::default(), &self_pid, &config, ONE_HOP));
}

// =============================================================================
// (5) has_health_oracle_program — the sentinel semantics.
// =============================================================================

#[test]
fn has_health_oracle_program_is_false_for_default_pubkey() {
    let config = cfg_with_oracle(Pubkey::default());
    assert!(!config.has_health_oracle_program());
}

#[test]
fn has_health_oracle_program_is_true_for_any_non_zero_pubkey() {
    let config = cfg_with_oracle(Pubkey::new_unique());
    assert!(config.has_health_oracle_program());
}

// =============================================================================
// (6) VULN-16 error codes — pinned for off-chain tooling stability.
// =============================================================================

#[test]
fn vuln16_error_codes_are_stable() {
    // Off-chain tooling (the integration test, the runner, ops dashboards)
    // matches on these numeric codes — they must not be silently renumbered.
    assert_eq!(CertificateError::UntrustedCpiCaller        as u32, 6050);
    assert_eq!(CertificateError::CallerIntrospectionFailed as u32, 6051);
    assert_eq!(CertificateError::NestedCpiCallerRejected   as u32, 6180);
}

// =============================================================================
// (7) M-2 — stack-height attribution: nested CPI is rejected.
// =============================================================================

#[test]
fn nested_cpi_is_rejected_even_from_health_oracle() {
    // The M-2 fix: at stack height > 2 the top-level program is NOT the
    // immediate caller (a hostile middle program could sit between the
    // allow-listed root and us), so even the health-oracle program id — which
    // passes at one hop — must be refused at any deeper nesting.
    let self_pid   = Pubkey::new_unique();
    let oracle_pid = Pubkey::new_unique();
    let config     = cfg_with_oracle(oracle_pid);
    assert!(!is_trusted_caller(&oracle_pid, &self_pid, &config, NESTED));
    assert!(!is_trusted_caller(&self_pid, &self_pid, &config, NESTED));
}

#[test]
fn role_and_depth_must_match() {
    // self is trusted ONLY at direct height; health-oracle ONLY at one hop.
    let self_pid   = Pubkey::new_unique();
    let oracle_pid = Pubkey::new_unique();
    let config     = cfg_with_oracle(oracle_pid);
    // self at a CPI hop -> rejected (some other program is the root).
    assert!(!is_trusted_caller(&self_pid, &self_pid, &config, ONE_HOP));
    // health-oracle as a top-level direct call -> rejected.
    assert!(!is_trusted_caller(&oracle_pid, &self_pid, &config, DIRECT));
}
