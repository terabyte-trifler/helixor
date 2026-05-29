// =============================================================================
// programs/certificate-issuer/tests/m09_get_certificate_pda_bind.rs
//
// M-09 — bind the CertificateRead event to the canonical
// `["cert", agent_wallet, epoch_le]` PDA on chain.
//
// Pre-M-09 the event was informational only: a downstream indexer reading
// `CertificateRead { agent_wallet, epoch, score, … }` had no way to PROVE
// the event came from the canonical certificate PDA. Anchor's `seeds=`
// constraint validates the account at resolution time, but:
//   * a future refactor that drops the constraint would bypass the check
//     silently;
//   * a future ix that emitted the same event shape from a non-canonical
//     account would have fooled every consumer at runtime.
//
// M-09 closes the gap with two reinforcing guards:
//   (1) `get_certificate` explicitly recomputes the canonical PDA from
//       (SEED_PREFIX, agent_wallet, epoch_le, cert.bump, program_id) and
//       `require_keys_eq!`s it — so a refactor that breaks the `seeds=`
//       invariant still fails with `CertificatePdaMismatch` (6130).
//   (2) The `CertificateRead` event payload carries the canonical PDA
//       pubkey AND the emitting program ID, so a downstream consumer can
//       independently call
//       `find_program_address([SEED_PREFIX, agent_wallet, epoch_le], program_id)`
//       and verify the result equals `certificate` — using ONLY the event,
//       no out-of-band trust.
//
// These tests pin:
//   * the new `CertificatePdaMismatch` error code (= 6130);
//   * the `CertificateRead` event surface via a struct-literal type pin
//     (so a refactor that removes / renames the new fields fails here
//     rather than silently breaking the indexer);
//   * the seed prefix used for the canonical derivation;
//   * round-tripping a `find_program_address` derivation against a
//     known (agent_wallet, epoch) — proving the indexer's verification
//     algorithm is implementable from public knowledge.
// =============================================================================

use anchor_lang::prelude::Pubkey;
use certificate_issuer::errors::CertificateError;
use certificate_issuer::events::CertificateRead;
use certificate_issuer::state::HealthCertificate;

// -----------------------------------------------------------------------------
// Error-code pin
// -----------------------------------------------------------------------------

#[test]
fn certificate_pda_mismatch_code_is_stable() {
    // 6130 was chosen to start a fresh decade above the M-06 block
    // (6120..6122), keeping the M-09 audit code visually distinct from the
    // rotation block. The off-chain monitor + TS SDK switch on this literal
    // — a refactor that renumbers MUST update both this pin AND the
    // canonical error-code allocation list.
    assert_eq!(CertificateError::CertificatePdaMismatch as u32, 6130);
}

// -----------------------------------------------------------------------------
// Seed-prefix pin (kept distinct from the broader certificate_logic test so
// an M-09-specific regression fails this file, not an unrelated logic file).
// -----------------------------------------------------------------------------

#[test]
fn certificate_seed_prefix_matches_indexer_derivation() {
    // The off-chain indexer's verification algorithm reads
    // `(agent_wallet, epoch, program_id)` off the event payload and calls
    // `find_program_address(["cert", agent_wallet, epoch_le], program_id)`.
    // If the on-chain seed prefix ever changes, the indexer's derivation
    // silently produces the wrong PDA — this pin makes that drift a
    // compile-time / test-time failure rather than a quiet split-brain.
    assert_eq!(HealthCertificate::SEED_PREFIX, b"cert");
}

// -----------------------------------------------------------------------------
// CertificateRead event — field surface pin
// -----------------------------------------------------------------------------

#[test]
fn certificate_read_event_carries_canonical_pda_and_program_id() {
    // Struct-literal type pin: this file does not compile if the M-09
    // `certificate` or `program_id` field is removed or renamed. The
    // off-chain indexer dispatches on the event SCHEMA, so silently
    // dropping either field would break every consumer at runtime — pin
    // it at compile time instead.
    let _ev = CertificateRead {
        certificate:   Pubkey::default(),
        program_id:    Pubkey::default(),
        agent_wallet:  Pubkey::default(),
        epoch:         0,
        score:         0,
        alert_tier:    0,
        flags:         0,
        immediate_red: false,
        issued_at:     0,
    };
}

#[test]
fn certificate_read_event_round_trips_pda_field() {
    // Sanity: the value the test writes survives the move into the event
    // struct (catches an accidental field shadow / reorder bug where the
    // event compiles but stores the program_id in the certificate slot
    // or vice versa).
    let cert_pda   = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();
    let ev = CertificateRead {
        certificate:   cert_pda,
        program_id,
        agent_wallet:  Pubkey::default(),
        epoch:         42,
        score:         700,
        alert_tier:    1,
        flags:         0,
        immediate_red: false,
        issued_at:     1_700_000_000,
    };
    assert_eq!(ev.certificate, cert_pda);
    assert_eq!(ev.program_id, program_id);
    assert_eq!(ev.epoch, 42);
}

// -----------------------------------------------------------------------------
// Indexer-side verification — proves the algorithm is implementable from
// the event payload alone.
// -----------------------------------------------------------------------------

#[test]
fn indexer_can_rederive_certificate_pda_from_event_payload() {
    // Walks the algorithm an off-chain indexer SHOULD run on every
    // CertificateRead it sees:
    //   (a) Read `(agent_wallet, epoch, program_id, certificate)` from the
    //       event payload.
    //   (b) Compute the canonical PDA from `(SEED_PREFIX, agent_wallet,
    //       epoch_le, program_id)` via `find_program_address`.
    //   (c) Assert it equals the `certificate` field.
    //
    // We don't have a real program_id in a unit test, so we fake one and
    // verify the round-trip. The fact that a unit test CAN do this is the
    // point: no out-of-band trust is required.
    let agent_wallet = Pubkey::new_unique();
    let epoch: u64   = 17;
    // Any pubkey works as the synthetic program id — the test exercises
    // the determinism of `find_program_address`, not Anchor's program-id
    // wiring.
    let program_id   = Pubkey::new_unique();

    let (canonical_pda, _bump) = Pubkey::find_program_address(
        &[
            HealthCertificate::SEED_PREFIX,
            agent_wallet.as_ref(),
            &epoch.to_le_bytes(),
        ],
        &program_id,
    );

    // Build the event the way the on-chain handler would.
    let ev = CertificateRead {
        certificate:   canonical_pda,
        program_id,
        agent_wallet,
        epoch,
        score:         900,
        alert_tier:    0,
        flags:         0,
        immediate_red: false,
        issued_at:     0,
    };

    // What the indexer does:
    let (rederived, _bump) = Pubkey::find_program_address(
        &[
            HealthCertificate::SEED_PREFIX,
            ev.agent_wallet.as_ref(),
            &ev.epoch.to_le_bytes(),
        ],
        &ev.program_id,
    );
    assert_eq!(rederived, ev.certificate);
}

#[test]
fn indexer_rejects_an_event_whose_pda_does_not_match_its_seeds() {
    // The negative leg of the verification algorithm: if some future ix
    // emits a CertificateRead whose `certificate` field is NOT the
    // canonical PDA for `(agent_wallet, epoch, program_id)`, the indexer
    // rejects it. This test exercises the very check the indexer is
    // expected to perform.
    let agent_wallet = Pubkey::new_unique();
    let epoch: u64   = 9;
    let program_id   = Pubkey::new_unique();
    let attacker_pda = Pubkey::new_unique(); // NOT the canonical PDA

    let ev = CertificateRead {
        certificate:   attacker_pda,
        program_id,
        agent_wallet,
        epoch,
        score:         1000,
        alert_tier:    0,
        flags:         0,
        immediate_red: false,
        issued_at:     0,
    };

    let (canonical, _bump) = Pubkey::find_program_address(
        &[
            HealthCertificate::SEED_PREFIX,
            ev.agent_wallet.as_ref(),
            &ev.epoch.to_le_bytes(),
        ],
        &ev.program_id,
    );
    assert_ne!(canonical, ev.certificate);
}
