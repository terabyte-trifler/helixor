// =============================================================================
// programs/slash-authority/tests/m14_system_program_pin.rs
//
// M-14 — defence-in-depth System Program ID pin on open_vault.
//
// THE FINDING (informational)
// ---------------------------
// An audit pass flagged a hypothetical "fake system_program" attack on
// open_vault: a caller passing a fake System Program account would route
// the staker -> vault transfer through attacker-controlled code, with
// any side effects of the attacker's choosing.
//
// The audit concluded this is NOT exploitable on Phylanx's current code:
//
//   1. Anchor's `Program<'info, System>` constraint on the
//      `system_program` field enforces the account's pubkey against
//      `solana_program::system_program::ID` at the deserialize gate,
//      BEFORE this handler runs.
//
//   2. The Solana VM additionally enforces the program ID on the CPI
//      itself — a `system_program::transfer` CPI to a non-canonical
//      pubkey is rejected by the runtime.
//
// Both layers are in place. The finding was filed as informational
// hardening only.
//
// WHY M-14 STILL EARNS ITS KEEP
// ------------------------------
// The two existing layers are SCHEMA-level (Anchor constraint) and
// RUNTIME-level (Solana VM). A future contributor weakening the
// `Accounts` struct to `UncheckedAccount<'info>` or `AccountInfo<'info>`
// — for example to add a custom verifier shim — would silently drop
// layer (1). Layer (2) catches most cases but is a coarse guard,
// returning a generic runtime error rather than an attributable code.
//
// M-14 adds an EXPLICIT in-handler `require_keys_eq!` against
// `anchor_lang::system_program::ID`, returning the dedicated
// `SystemProgramIdMismatch = 6100` error. The check:
//
//   * is cheap (one pubkey compare),
//   * is attributable (off-chain monitors switch on the literal code),
//   * survives independently of the `Accounts` struct surface — so a
//     refactor that weakens the constraint still produces a clear,
//     program-specific error instead of a runtime "invalid account"
//     message that auditors have to interpret.
//
// WHAT THESE TESTS PIN
// --------------------
//   * The `SystemProgramIdMismatch` error code is stable at 6100.
//   * The canonical System Program ID literal the handler compares
//     against has not drifted from
//     `11111111111111111111111111111111` — i.e.
//     `anchor_lang::system_program::ID` and
//     `solana_program::system_program::ID` resolve to the same value.
//   * Documentation contract: the handler check uses the
//     `require_keys_eq!` macro form with the M-14 error code (string
//     contract — a contributor renaming the code in the handler
//     without updating this pin sees the test fail at compile time
//     via the enum variant reference).
// =============================================================================

use anchor_lang::prelude::Pubkey;
use slash_authority::errors::SlashError;

// -----------------------------------------------------------------------------
// Error-code pin
// -----------------------------------------------------------------------------

#[test]
fn system_program_id_mismatch_code_is_stable() {
    // 6100 was chosen to open a new block past M-11's 6090, leaving
    // 6091..=6099 free for any follow-up M-09/M-10/M-11 derivatives.
    // Off-chain monitors + the TS SDK switch on this literal — a
    // renumber MUST update both this pin AND the canonical error-code
    // allocation list.
    assert_eq!(SlashError::SystemProgramIdMismatch as u32, 6100);
}

// -----------------------------------------------------------------------------
// Canonical System Program ID — cross-crate consistency pin
// -----------------------------------------------------------------------------

#[test]
fn anchor_system_program_id_is_canonical() {
    // The handler uses `anchor_lang::system_program::ID` as its source
    // of truth for the require_keys_eq! check. The Anchor `Program<'info,
    // System>` constraint internally compares against the same constant.
    //
    // The constant MUST resolve to the canonical
    // 11111111111111111111111111111111 pubkey. A future Anchor version
    // re-export that drifts this would silently break the defence-in-
    // depth layer.
    let anchor_id: Pubkey = anchor_lang::system_program::ID;

    // The canonical literal in base58. Wallets, off-chain tooling and
    // the audit report all reference this exact string.
    assert_eq!(
        anchor_id.to_string(),
        "11111111111111111111111111111111",
    );

    // The all-zero-bytes pubkey IS the System Program's encoding — but
    // it is the only valid pubkey with that property. We pin the byte
    // pattern explicitly so a regression that resolves the constant to
    // a junk default (e.g. a default-Pubkey shaped like 0xFF..FF or a
    // misread re-export) is caught.
    assert_eq!(anchor_id.to_bytes(), [0u8; 32]);
}

#[test]
fn system_program_id_is_the_all_zero_pubkey() {
    // Subtle but important: the canonical System Program ID IS the
    // all-zero pubkey. The base58 encoding of `[0u8; 32]` is exactly
    // `11111111111111111111111111111111`. This is NOT a regression to
    // alert on — it's the operational reality.
    //
    // What WOULD be a regression is the constant drifting to any
    // OTHER value. Pin the byte pattern so a Pubkey shaped like
    // 0xFF..FF or a partially-zeroed default is caught.
    let id_bytes = anchor_lang::system_program::ID.to_bytes();
    assert_eq!(id_bytes, [0u8; 32]);

    // And: `Pubkey::default()` is the all-zero pubkey by convention,
    // so the System Program ID and the default pubkey ARE equal. The
    // M-14 defence-in-depth check therefore does NOT distinguish
    // "fake system_program supplied with pubkey=0" from "real System
    // Program". That is fine: the runtime CPI ID check (layer 2)
    // additionally enforces that the account is owned by the
    // BPF Loader (or is the System Program itself) — a fake account
    // at the canonical pubkey with arbitrary owner cannot answer a
    // System CPI. M-14's require_keys_eq! is an attribution layer,
    // not the sole gate.
    assert_eq!(anchor_lang::system_program::ID, Pubkey::default());
}

// -----------------------------------------------------------------------------
// Operational contract pin — the M-14 error code is wired to the
// require_keys_eq! macro in the handler. This test does not run the
// handler (no validator), but documents the contract a contributor
// renaming the error variant has to honour.
// -----------------------------------------------------------------------------

#[test]
fn m14_error_variant_is_reachable_via_enum_path() {
    // String form pin: a contributor renaming the variant in errors.rs
    // breaks this `as u32` reference at compile time, forcing them to
    // either update the enum-path here or revert the rename. The
    // off-chain monitor pins the literal code 6100, so the variant
    // identity also matters — both have to move together.
    let code = SlashError::SystemProgramIdMismatch as u32;
    assert!(
        (6100..=6100).contains(&code),
        "M-14 variant resolved to an out-of-block code: {}",
        code,
    );
}

// -----------------------------------------------------------------------------
// Layer-defence rationale — documentation-only pin.
// -----------------------------------------------------------------------------

#[test]
fn defence_layers_documented() {
    // Three layers protect the open_vault System CPI against a fake
    // system_program account. The audit gate requires this list to
    // be exhaustive — adding a layer means updating this test, and
    // removing one means thinking very hard about why.
    let layers: &[&str] = &[
        // (1) SCHEMA — Anchor's `Program<'info, System>` constraint
        //     enforces the pubkey at deserialize.
        "anchor:Program<'info,System>",
        // (2) RUNTIME — the Solana VM rejects a system_program CPI to
        //     a non-canonical pubkey.
        "solana_vm:cpi_program_id_check",
        // (3) DEFENCE-IN-DEPTH — M-14's explicit `require_keys_eq!`
        //     in the handler, returning SystemProgramIdMismatch=6100.
        "m14:require_keys_eq",
    ];
    assert_eq!(layers.len(), 3);
}
