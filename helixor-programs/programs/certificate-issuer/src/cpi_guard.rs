// =============================================================================
// programs/certificate-issuer/src/cpi_guard.rs — VULN-16 MITIGATION.
//
// THE AUDIT FINDING (paraphrased)
// -------------------------------
// HIGH. `issue_certificate` is exposed via CPI from `health-oracle::submit_score`.
// Its existing gates check the THRESHOLD SIGNATURES (Ed25519 precompile) and
// the PDA constraints — but NOT the program that CPI-invoked it. An attacker
// who deploys their own `attacker_oracle` program and somehow assembles a
// transaction that includes valid threshold signatures could CPI into
// `issue_certificate` from that fake program. The certificate would issue —
// "it came from some program that brought valid sigs". This is the classic
// "CPI trust boundary that many Solana protocols get wrong".
//
// THE GUARD (this file)
// ---------------------
// `assert_trusted_caller` reads the current TOP-LEVEL instruction from the
// Instructions sysvar and rejects any caller that is not on the allow-list:
//
//   - certificate_issuer::ID itself — a direct call (no CPI). The
//     cluster-direct path in Phase 4. Already gated by threshold sigs.
//
//   - `config.health_oracle_program_id` — the canonical health-oracle
//     program, the one Anchor IDL teaches the cluster to use. The legacy
//     CPI submit-score path.
//
// Any other top-level program ID is rejected with `UntrustedCpiCaller`.
// A misconfigured deployment that left `health_oracle_program_id` zero is
// in the SAFEST possible state — every CPI is refused; only direct calls
// work.
//
// WHY TOP-LEVEL, NOT IMMEDIATE-PARENT
// -----------------------------------
// Solana's sysvar exposes the TOP-LEVEL instruction. The architecture is
// single-level: `issue_certificate` is either (a) called directly, or (b)
// called via a single CPI hop from `health-oracle`. There is no nested CPI
// route in the protocol design — neither program CPIs into a program that
// CPIs into us. So top-level = immediate caller in every legitimate path,
// and the simpler check is the right one. If multi-level CPI ever becomes
// part of the protocol, this helper changes; the call site does not.
//
// DETERMINISM
// -----------
// Pure given (sysvar_account_info, allow-list). No clock, no randomness;
// the check resolves identically on every cluster node.
// =============================================================================

use anchor_lang::prelude::*;
use solana_instructions_sysvar::{
    load_current_index_checked,
    load_instruction_at_checked,
    ID as INSTRUCTIONS_ID,
};

use crate::errors::CertificateError;
use crate::state::IssuerConfig;


/// Verify the program that CPI-invoked us — or the user that called us
/// directly — is on the configured trust list.
///
/// Allow list (any one is sufficient):
///   * the certificate-issuer program itself (the call is top-level,
///     i.e. NOT a CPI — gated by threshold sigs as usual);
///   * the `health_oracle_program_id` recorded in `config` (the canonical
///     CPI path from `health-oracle::submit_score`).
///
/// Rejects with `UntrustedCpiCaller` for any other top-level program.
/// Rejects with `CallerIntrospectionFailed` if the sysvar cannot be read —
/// we refuse to issue a cert if we cannot attribute the caller, fail-closed.
pub fn assert_trusted_caller(
    instructions_sysvar:  &AccountInfo,
    config:               &IssuerConfig,
    self_program_id:      &Pubkey,
) -> Result<()> {
    // Sanity-check the sysvar account — same check `signing.rs` runs.
    // We fail-closed here because mistaking some other account for the
    // sysvar would silently skip the entire caller check.
    require!(
        instructions_sysvar.key == &INSTRUCTIONS_ID,
        CertificateError::WrongInstructionsSysvar,
    );

    // The CURRENT top-level instruction is the OUTER ix being processed.
    // For a direct call: program_id == self (certificate_issuer).
    // For a CPI: program_id == the program that invoked our CPI entry.
    let current_idx = load_current_index_checked(instructions_sysvar)
        .map_err(|_| error!(CertificateError::CallerIntrospectionFailed))?;
    let top_level = load_instruction_at_checked(
        current_idx as usize, instructions_sysvar,
    ).map_err(|_| error!(CertificateError::CallerIntrospectionFailed))?;
    let caller_pid = top_level.program_id;

    // Direct top-level call to certificate_issuer — always permitted.
    // (The threshold-sig check is the substantive gate for this path.)
    if &caller_pid == self_program_id {
        return Ok(());
    }

    // CPI path — only the canonical health-oracle program is permitted.
    // A zero (Pubkey::default()) allow-list value means "no CPI caller
    // is permitted"; the safe default for a deployment that does not
    // use the CPI path at all.
    if config.has_health_oracle_program()
        && caller_pid == config.health_oracle_program_id
    {
        return Ok(());
    }

    msg!(
        "VULN-16: refusing CPI caller {} — allow-list = self {} + health_oracle {}",
        caller_pid,
        self_program_id,
        if config.has_health_oracle_program() {
            config.health_oracle_program_id.to_string()
        } else {
            "<disabled>".to_string()
        },
    );
    err!(CertificateError::UntrustedCpiCaller)
}


// =============================================================================
// Tests — pure, runtime-free coverage of the trust-list decision logic.
// =============================================================================

#[cfg(test)]
mod tests {
    //! These tests target the decision logic (`is_trusted_caller`) directly.
    //! `assert_trusted_caller` is a thin wrapper that adds the sysvar read +
    //! the error mapping; the runtime-bound paths are exercised by the
    //! integration tests in `tests/cpi_guard_logic.rs`, which can shape an
    //! AccountInfo without the BPF runtime.

    use super::*;

    /// Pure decision helper — extracted so the trust check can be tested
    /// without an AccountInfo. Mirrors the exact logic in
    /// `assert_trusted_caller` after the sysvar has been read.
    pub(crate) fn is_trusted_caller(
        caller_pid:      &Pubkey,
        self_program_id: &Pubkey,
        config:          &IssuerConfig,
    ) -> bool {
        if caller_pid == self_program_id {
            return true;
        }
        if config.has_health_oracle_program()
            && caller_pid == &config.health_oracle_program_id
        {
            return true;
        }
        false
    }

    fn cfg(health_oracle_program_id: Pubkey) -> IssuerConfig {
        IssuerConfig {
            authority: Pubkey::new_unique(),
            issuer_node: Pubkey::new_unique(),
            cluster_keys: vec![Pubkey::new_unique(); 3],
            threshold: 2,
            bump: 255,
            health_oracle_program_id,
            // AW-01-EXT.6: CPI-caller tests are orthogonal to challenges;
            // leave the attester cluster disabled.
            challenge_attester_keys: Vec::new(),
            challenge_threshold: 0,
            // M-05: CPI-guard tests are orthogonal to the config-snapshot
            // version; pin the genesis value.
            config_version: 1,
            // H-3: no authority transfer pending.
            pending_authority: Pubkey::default(),
            authority_transfer_eta: 0,
        }
    }

    #[test]
    fn direct_call_is_trusted() {
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(is_trusted_caller(&self_pid, &self_pid, &config));
    }

    #[test]
    fn cpi_from_configured_health_oracle_is_trusted() {
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(is_trusted_caller(&oracle_pid, &self_pid, &config));
    }

    #[test]
    fn cpi_from_attacker_program_is_rejected() {
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let attacker_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(!is_trusted_caller(&attacker_pid, &self_pid, &config));
    }

    #[test]
    fn cpi_from_any_program_is_rejected_when_oracle_disabled() {
        // Zero health_oracle_program_id = CPI allow-list disabled.
        // The safe default — every CPI is refused.
        let self_pid = Pubkey::new_unique();
        let any_pid = Pubkey::new_unique();
        let config = cfg(Pubkey::default());
        assert!(!is_trusted_caller(&any_pid, &self_pid, &config));
        // Self is still trusted (direct call).
        assert!(is_trusted_caller(&self_pid, &self_pid, &config));
    }

    #[test]
    fn zero_caller_pid_is_rejected() {
        // A degenerate caller_pid of Pubkey::default() must not
        // accidentally pass even when the allow-list is disabled (which
        // also uses Pubkey::default()).
        let self_pid = Pubkey::new_unique();
        let config = cfg(Pubkey::default());
        assert!(!is_trusted_caller(&Pubkey::default(), &self_pid, &config));
    }
}
