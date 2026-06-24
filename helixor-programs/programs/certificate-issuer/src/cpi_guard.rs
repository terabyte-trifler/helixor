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
use solana_program::instruction::{get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};

use crate::errors::CertificateError;
use crate::state::IssuerConfig;


/// Verify the program that CPI-invoked us — or the user that called us
/// directly — is on the configured trust list.
///
/// M-2 — IMMEDIATE-CALLER ATTRIBUTION VIA STACK HEIGHT
/// ---------------------------------------------------
/// The instructions sysvar only exposes the TOP-LEVEL instruction, which is
/// the immediate caller ONLY when there is at most one CPI hop. A nested CPI
/// (A → B → issue_certificate, A allow-listed, B hostile) would otherwise see
/// A (trusted) and pass, even though B is the real caller. We pin the depth
/// with `get_stack_height()` so the top-level program is provably the
/// immediate caller, and fail closed on anything deeper:
///
///   * stack height == TRANSACTION_LEVEL_STACK_HEIGHT (1): WE are the
///     top-level instruction — a direct call. Permitted iff the top-level
///     program is certificate-issuer itself (the threshold-sig check is the
///     substantive gate for this path).
///   * stack height == TRANSACTION_LEVEL_STACK_HEIGHT + 1 (2): exactly one CPI
///     hop. We sit one level below the transaction root, so the top-level
///     program IS our immediate caller. Permitted iff it is the configured
///     `health_oracle_program_id` (the canonical submit-score CPI path).
///   * stack height > 2: a NESTED CPI. The top-level is no longer our
///     immediate caller and the sysvar cannot attribute who is — there is no
///     legitimate nested path, so reject with `NestedCpiCallerRejected`.
///
/// Rejects with `UntrustedCpiCaller` for a single-hop CPI from any other
/// program, `NestedCpiCallerRejected` for >1 hop, and
/// `CallerIntrospectionFailed` if the sysvar cannot be read — all fail-closed.
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

    let stack_height = get_stack_height();

    // The CURRENT top-level instruction is the transaction-root ix.
    let current_idx = load_current_index_checked(instructions_sysvar)
        .map_err(|_| error!(CertificateError::CallerIntrospectionFailed))?;
    let top_level = load_instruction_at_checked(
        current_idx as usize, instructions_sysvar,
    ).map_err(|_| error!(CertificateError::CallerIntrospectionFailed))?;
    let top_level_pid = top_level.program_id;

    if is_trusted_caller(&top_level_pid, self_program_id, config, stack_height) {
        return Ok(());
    }

    // Distinguish the failure modes for diagnostics.
    if stack_height > TRANSACTION_LEVEL_STACK_HEIGHT + 1 {
        msg!(
            "M-2: refusing NESTED CPI to issue_certificate — stack height {} > 2; \
             the top-level program {} is not the immediate caller",
            stack_height, top_level_pid,
        );
        return err!(CertificateError::NestedCpiCallerRejected);
    }

    msg!(
        "VULN-16: refusing caller {} (stack height {}) — allow-list = self {} + health_oracle {}",
        top_level_pid,
        stack_height,
        self_program_id,
        if config.has_health_oracle_program() {
            config.health_oracle_program_id.to_string()
        } else {
            "<disabled>".to_string()
        },
    );
    err!(CertificateError::UntrustedCpiCaller)
}

/// M-2 — the pure trust decision, given the transaction's TOP-LEVEL program
/// id, our own program id, the config, and the current CPI stack height.
/// Extracted so the full decision (including the stack-height attribution
/// that the old helper omitted) is unit-testable without a BPF runtime or a
/// shaped AccountInfo.
///
/// See `assert_trusted_caller` for the rationale on each branch.
pub(crate) fn is_trusted_caller(
    top_level_pid:   &Pubkey,
    self_program_id: &Pubkey,
    config:          &IssuerConfig,
    stack_height:    usize,
) -> bool {
    if stack_height == TRANSACTION_LEVEL_STACK_HEIGHT {
        // Direct call: we ARE the top-level instruction.
        return top_level_pid == self_program_id;
    }
    if stack_height == TRANSACTION_LEVEL_STACK_HEIGHT + 1 {
        // Single CPI hop: the top-level program IS our immediate caller.
        return config.has_health_oracle_program()
            && top_level_pid == &config.health_oracle_program_id;
    }
    // Nested CPI (or a degenerate height 0): cannot attribute the caller.
    false
}


// =============================================================================
// Tests — pure, runtime-free coverage of the trust-list decision logic.
// =============================================================================

#[cfg(test)]
mod tests {
    //! These tests target the decision logic (`is_trusted_caller`) directly,
    //! including the M-2 stack-height attribution. `assert_trusted_caller` is
    //! a thin wrapper around it (sysvar read, `get_stack_height()` syscall,
    //! error mapping); the full runtime path is exercised by the on-chain
    //! smoke test (a direct top-level call at stack height 1).

    use super::*;

    const DIRECT: usize = TRANSACTION_LEVEL_STACK_HEIGHT;        // 1
    const ONE_HOP: usize = TRANSACTION_LEVEL_STACK_HEIGHT + 1;   // 2
    const NESTED: usize = TRANSACTION_LEVEL_STACK_HEIGHT + 2;    // 3

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
            // H-5: one domain per key (irrelevant to CPI-guard tests).
            cluster_key_domains: vec![0u16, 1, 2],
        }
    }

    #[test]
    fn direct_call_is_trusted() {
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(is_trusted_caller(&self_pid, &self_pid, &config, DIRECT));
    }

    #[test]
    fn cpi_from_configured_health_oracle_is_trusted() {
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(is_trusted_caller(&oracle_pid, &self_pid, &config, ONE_HOP));
    }

    #[test]
    fn cpi_from_attacker_program_is_rejected() {
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let attacker_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(!is_trusted_caller(&attacker_pid, &self_pid, &config, ONE_HOP));
    }

    #[test]
    fn cpi_from_any_program_is_rejected_when_oracle_disabled() {
        // Zero health_oracle_program_id = CPI allow-list disabled.
        // The safe default — every CPI is refused.
        let self_pid = Pubkey::new_unique();
        let any_pid = Pubkey::new_unique();
        let config = cfg(Pubkey::default());
        assert!(!is_trusted_caller(&any_pid, &self_pid, &config, ONE_HOP));
        // Self is still trusted (direct call).
        assert!(is_trusted_caller(&self_pid, &self_pid, &config, DIRECT));
    }

    #[test]
    fn zero_caller_pid_is_rejected() {
        // A degenerate top_level_pid of Pubkey::default() must not
        // accidentally pass even when the allow-list is disabled (which
        // also uses Pubkey::default()).
        let self_pid = Pubkey::new_unique();
        let config = cfg(Pubkey::default());
        assert!(!is_trusted_caller(&Pubkey::default(), &self_pid, &config, DIRECT));
        assert!(!is_trusted_caller(&Pubkey::default(), &self_pid, &config, ONE_HOP));
    }

    // ── M-2: stack-height attribution ───────────────────────────────────────

    #[test]
    fn nested_cpi_is_rejected_even_from_health_oracle() {
        // The core M-2 fix: at stack height > 2 the top-level program is NOT
        // the immediate caller, so even the health-oracle program id (which
        // would pass at one hop) must be refused.
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(!is_trusted_caller(&oracle_pid, &self_pid, &config, NESTED));
        assert!(!is_trusted_caller(&self_pid, &self_pid, &config, NESTED));
    }

    #[test]
    fn self_at_cpi_height_is_rejected() {
        // certificate-issuer is only trusted as the TOP-LEVEL (direct) caller.
        // Seeing self at one CPI hop (height 2) means some other program is the
        // root — not a legitimate path — so it must be refused.
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(!is_trusted_caller(&self_pid, &self_pid, &config, ONE_HOP));
    }

    #[test]
    fn health_oracle_at_direct_height_is_rejected() {
        // Conversely, health-oracle is only trusted as the immediate CPI
        // caller (height 2), never as a top-level direct call (height 1).
        let self_pid = Pubkey::new_unique();
        let oracle_pid = Pubkey::new_unique();
        let config = cfg(oracle_pid);
        assert!(!is_trusted_caller(&oracle_pid, &self_pid, &config, DIRECT));
    }

    #[test]
    fn degenerate_zero_stack_height_is_rejected() {
        let self_pid = Pubkey::new_unique();
        let config = cfg(Pubkey::new_unique());
        assert!(!is_trusted_caller(&self_pid, &self_pid, &config, 0));
    }
}
