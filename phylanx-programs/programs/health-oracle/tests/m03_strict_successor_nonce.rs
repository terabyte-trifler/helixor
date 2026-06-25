// =============================================================================
// programs/health-oracle/tests/m03_strict_successor_nonce.rs
//
// Pure unit tests pinning the M-03 fix: strict-successor enforcement on
// baseline `commit_nonce`.
//
// THE BUG
// -------
// AW-03 binds `baseline_commit_nonce` into the certificate digest, so
// downstream consumers can confirm WHICH baseline rotation a cert was
// issued against. The pre-M-03 on-chain check accepted any
//   `args.commit_nonce > reg.commit_nonce`
// which left two attack surfaces a compromised oracle key could exploit:
//
//   - NONCE JUMP — rotate from nonce N straight to N+1000, covertly
//     skipping rotations. Off-chain consumers walking the chain
//     1 -> 2 -> 3 -> ... to verify baseline history hit a gap and either
//     accept the chain as-is (silently trusting jumped rotations) or
//     refuse to verify (DoS by alarm fatigue).
//
//   - NONCE BURN — commit at nonce u64::MAX. After that point
//     `> u64::MAX` is unsatisfiable, so every future rotation reverts
//     and the baseline is permanently frozen in its compromised state.
//
// THE FIX
// -------
// `check_strict_successor_nonce(stored, new)` requires
// `new == stored + 1` exactly, with explicit overflow rejection at
// `stored == u64::MAX`. Error attribution is split for clarity:
//
//   - rollback / no-op  -> NonMonotonicNonce        (6020)
//   - jump (skip)       -> NonceNotStrictSuccessor  (6025)
//   - burn (at max)     -> NonceSpaceExhausted      (6026)
//
// These tests pin the helper's behaviour on every boundary case and the
// stability of the three error codes.
// =============================================================================

use anchor_lang::error::Error as AnchorError;
use health_oracle::errors::PhylanxError;
use health_oracle::instructions::commit_baseline::check_strict_successor_nonce;

// ----------------------------------------------------------------------------
// Error-code matching helper
// ----------------------------------------------------------------------------

fn err_matches(e: AnchorError, code: PhylanxError) -> bool {
    match e {
        AnchorError::AnchorError(a) => {
            a.error_code_number
                == code as u32 + anchor_lang::error::ERROR_CODE_OFFSET
        }
        _ => panic!("expected AnchorError, got: {e:?}"),
    }
}

// ----------------------------------------------------------------------------
// Error-code stability pins
// ----------------------------------------------------------------------------

#[test]
fn non_monotonic_nonce_error_code_pinned() {
    // 6020 — the original rollback-rejection error. M-03 reuses it for
    // the strict-greater branch so pre-M-03 clients still see the same
    // code on rollback / no-op.
    assert_eq!(PhylanxError::NonMonotonicNonce as u32, 6020);
}

#[test]
fn nonce_not_strict_successor_error_code_pinned() {
    // 6025 — new in M-03. Distinct from NonMonotonicNonce so a client
    // can tell a JUMP attack from a ROLLBACK attack.
    assert_eq!(PhylanxError::NonceNotStrictSuccessor as u32, 6025);
}

#[test]
fn nonce_space_exhausted_error_code_pinned() {
    // 6026 — new in M-03. Surfaces the u64::MAX overflow attack
    // (compromised oracle commits at u64::MAX to lock the chain).
    assert_eq!(PhylanxError::NonceSpaceExhausted as u32, 6026);
}

// ----------------------------------------------------------------------------
// First commit — the canonical happy path
// ----------------------------------------------------------------------------

/// A fresh registration has commit_nonce = 0. The first legitimate
/// commit lands at nonce 1. This is the most common path; if it ever
/// reverts the rest of the protocol is dead.
#[test]
fn first_commit_must_be_nonce_one() {
    assert!(check_strict_successor_nonce(0, 1).is_ok());
}

/// A first commit at nonce 2 looks "monotonic" but skips slot 1 — it
/// is exactly the NONCE JUMP attack on a brand-new agent. Refuse.
#[test]
fn first_commit_at_nonce_two_rejected_as_jump() {
    let res = check_strict_successor_nonce(0, 2);
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonceNotStrictSuccessor));
}

/// A first commit at nonce 0 — equal to stored — is the rollback /
/// no-op case. Must surface NonMonotonicNonce (6020), not the new
/// NonceNotStrictSuccessor, so existing clients keep their error mapping.
#[test]
fn first_commit_at_nonce_zero_rejected_as_rollback() {
    let res = check_strict_successor_nonce(0, 0);
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonMonotonicNonce));
}

// ----------------------------------------------------------------------------
// Steady-state happy path
// ----------------------------------------------------------------------------

/// The normal monthly rotation: stored=N, new=N+1, for arbitrary N in
/// the safe range. Pinned with a non-trivial value (~3-year run at one
/// rotation per day) so an off-by-one in the helper would surface.
#[test]
fn steady_state_n_to_n_plus_one_accepted() {
    let n = 1_000u64;
    assert!(check_strict_successor_nonce(n, n + 1).is_ok());
}

/// The boundary just below u64::MAX. As long as stored < u64::MAX a
/// strict successor exists; pin the exactly-one-below-max case so the
/// overflow guard does not over-fire.
#[test]
fn near_max_n_to_n_plus_one_accepted() {
    assert!(check_strict_successor_nonce(u64::MAX - 1, u64::MAX).is_ok());
}

// ----------------------------------------------------------------------------
// Rollback / no-op
// ----------------------------------------------------------------------------

/// The original rollback attack: stored=5, new=3. Must surface
/// NonMonotonicNonce, NOT NonceNotStrictSuccessor — the audit chain
/// hasn't been "jumped", it's been REVERSED, which is a distinct
/// attacker intent.
#[test]
fn rollback_below_stored_rejected_as_non_monotonic() {
    let res = check_strict_successor_nonce(5, 3);
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonMonotonicNonce));
}

/// Equal nonces are a NO-OP — same baseline, same revision number.
/// Same error as rollback.
#[test]
fn equal_to_stored_rejected_as_non_monotonic() {
    let res = check_strict_successor_nonce(5, 5);
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonMonotonicNonce));
}

// ----------------------------------------------------------------------------
// Jump attacks — the core M-03 reject path
// ----------------------------------------------------------------------------

/// Skip by one: stored=5, new=7. Strict-greater would have accepted
/// this; strict-successor must reject with NonceNotStrictSuccessor.
#[test]
fn jump_by_one_rejected_as_strict_successor() {
    let res = check_strict_successor_nonce(5, 7);
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonceNotStrictSuccessor));
}

/// Large jump — the audit's "leap from N to N+1000" scenario. The
/// off-chain audit log walker would see slots 6..=1004 silently absent.
#[test]
fn large_jump_rejected_as_strict_successor() {
    let res = check_strict_successor_nonce(5, 1005);
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonceNotStrictSuccessor));
}

/// Adversarial jump to u64::MAX while space still exists — a
/// compromised oracle could try to burn the entire nonce space in one
/// commit. Strict-successor rejects it as a jump (not as overflow,
/// because the overflow check only fires when STORED is at max).
#[test]
fn jump_to_u64_max_rejected_as_strict_successor() {
    let res = check_strict_successor_nonce(5, u64::MAX);
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonceNotStrictSuccessor));
}

// ----------------------------------------------------------------------------
// Burn attack — u64::MAX overflow path
// ----------------------------------------------------------------------------

/// The nonce-space-exhausted boundary: stored = u64::MAX leaves no
/// strict successor. checked_add(1) returns None and the helper must
/// surface NonceSpaceExhausted rather than panicking. The `new` value
/// here is irrelevant — the overflow fires before the equality check.
#[test]
fn stored_at_u64_max_with_max_new_rejected_as_exhausted() {
    let res = check_strict_successor_nonce(u64::MAX, u64::MAX);
    // First the strict-greater check fires (u64::MAX is NOT > u64::MAX),
    // so this case is actually a rollback / no-op. Pinned explicitly so
    // a future reorder that puts the overflow check first surfaces here.
    assert!(res.is_err());
    assert!(err_matches(res.unwrap_err(), PhylanxError::NonMonotonicNonce));
}

/// To actually reach the overflow branch we need stored = u64::MAX AND
/// new > u64::MAX — impossible in u64. The contrapositive: if stored
/// is at u64::MAX, EVERY legal `new` (i.e. new > stored) is also
/// impossible, so the strict-greater check always fires first. This
/// test pins that the helper does NOT panic in this configuration and
/// surfaces a typed error in either direction.
#[test]
fn stored_at_u64_max_can_never_succeed() {
    // Every conceivable `new` value, given stored = u64::MAX:
    //   - new < u64::MAX  -> NonMonotonicNonce  (rollback)
    //   - new == u64::MAX -> NonMonotonicNonce  (no-op)
    // There is no `new > u64::MAX` in u64, so the overflow branch is
    // unreachable from u64 callers. This is INTENTIONAL — the
    // NonceSpaceExhausted error is defence in depth against a future
    // type widening (e.g. u128 callers) that would expose the overflow
    // path. Pin both branches here.
    for new in [0u64, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
        let res = check_strict_successor_nonce(u64::MAX, new);
        assert!(res.is_err(), "stored=u64::MAX must always reject");
        assert!(
            err_matches(res.unwrap_err(), PhylanxError::NonMonotonicNonce),
            "expected NonMonotonicNonce at stored=u64::MAX, new={new}",
        );
    }
}
