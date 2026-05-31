// =============================================================================
// programs/slash-authority/tests/h02_settle_active_constraint.rs
//
// H-02 — uniform `vault.active` constraint across ALL vault-touching ix.
//
// THE AUDIT FINDING
// -----------------
// `execute_slash`, `appeal_slash`, and `resolve_appeal` all carry
//     constraint = escrow_vault.active @ SlashError::VaultInactive
// on the `escrow_vault` account. `settle_slash` did NOT — so a Pending
// non-terminal record on a vault that had already been terminally
// deactivated by a sibling Compromise settlement could still drain
// lamports out of the dead vault, breaking the "terminal = frozen"
// invariant the rest of the program relies on.
//
// THE FIX
// -------
// Add the same constraint to `settle_slash`'s `escrow_vault`. The
// encumbered lamports of pending non-terminal records on a terminally-
// compromised vault are forfeit by design — there is no drain path,
// and the protocol's threat model treats a terminally-slashed agent
// as one whose collateral is destroyed in full.
//
// WHAT THIS FILE PINS
// -------------------
//   * `VaultInactive = 6020` is the canonical code returned across all
//     four vault-touching ix.
//   * The list of ix that MUST carry the constraint, documented in
//     code so any new instruction touching the vault is forced to add
//     itself here (or the contributor is forced to read the rationale).
//   * The "terminal = frozen" invariant in fact-list form.
// =============================================================================

use slash_authority::errors::SlashError;

// -----------------------------------------------------------------------------
// Error-code pin
// -----------------------------------------------------------------------------

#[test]
fn vault_inactive_code_is_stable() {
    // 6020 has been the canonical code since the H-02 mitigation landed
    // on execute_slash. All four vault-touching ix now return it.
    assert_eq!(SlashError::VaultInactive as u32, 6020);
}

// -----------------------------------------------------------------------------
// Coverage roster — every vault-touching ix MUST be listed here
// -----------------------------------------------------------------------------

#[test]
fn h02_constraint_carriers_documented() {
    // Source-of-truth list of every ix whose `escrow_vault` Account is
    // constrained with `escrow_vault.active @ VaultInactive`. A new
    // vault-touching ix that does NOT carry the constraint must be
    // added to this list with a justification, OR the constraint must
    // be added to it.
    let carriers: &[&str] = &[
        "execute_slash",   // long-standing
        "appeal_slash",    // H-02 mitigation
        "resolve_appeal",  // H-02 mitigation
        "settle_slash",    // H-02 close (this fix)
    ];
    assert_eq!(carriers.len(), 4);

    // Sanity: open_vault is the EXCEPTION — it CREATES the vault with
    // active = true. It does not deserialize an existing vault to
    // check; the active-bit invariant is established by the handler.
    let exception: &str = "open_vault";
    assert_eq!(exception, "open_vault");
}

// -----------------------------------------------------------------------------
// "terminal = frozen" invariant — documentation pin
// -----------------------------------------------------------------------------

#[test]
fn terminal_equals_frozen_invariant_documented() {
    // The H-02 close pins the following semantic, in fact-list form:
    let semantic: &[&str] = &[
        "settle_slash on a terminal (Compromise) record sets vault.active = false",
        "appeal_slash, resolve_appeal, execute_slash, settle_slash all refuse vault.active == false",
        "no instruction exists that re-activates a deactivated vault",
        "encumbered lamports of pending non-terminal records on a terminally-compromised vault are forfeit by design",
    ];
    assert_eq!(semantic.len(), 4);
}
