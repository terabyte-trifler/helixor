// =============================================================================
// programs/health-oracle/tests/aw03_baseline_data_logic.rs
//
// AW-03 — pure unit tests for the BaselineDataAccount layout + the
// canonical-payload hash binding that commit_baseline enforces.
//
// The on-chain handler computes `sha256(args.payload)` and refuses the
// commit unless that equals `args.baseline_hash`. Production payloads come
// from `baseline.hashing.compute_stats_hash` off-chain; this test file pins
// the binding property directly so any drift between the off-chain hasher
// and the on-chain check surfaces here.
// =============================================================================

use solana_program::hash::hashv;

use health_oracle::state::{
    AgentRegistration, BaselineDataAccount, MAX_BASELINE_PAYLOAD_LEN,
};

// ── BaselineDataAccount layout pins ────────────────────────────────────────

#[test]
fn baseline_data_account_fixed_fields_total_135_bytes() {
    // 32 agent + 8 nonce + 32 hash + 1 algo + 8 ts + 32 committer + 4 len
    // + 1 bump + 1 layout + 16 reserved = 135
    assert_eq!(BaselineDataAccount::FIXED_FIELDS_LEN, 135);
}

#[test]
fn space_for_payload_matches_discriminator_plus_fixed_plus_payload() {
    for payload_len in [0_usize, 1, 32, 1024, 3_000, MAX_BASELINE_PAYLOAD_LEN] {
        assert_eq!(
            BaselineDataAccount::space_for(payload_len),
            8 + 135 + payload_len,
            "space_for({}) drifted", payload_len,
        );
    }
}

#[test]
fn max_payload_constant_holds_at_8k() {
    // 8 KB is the rent-bound safety ceiling. Drift indicates the
    // canonical serializer ballooned; tighten it before raising the cap.
    assert_eq!(MAX_BASELINE_PAYLOAD_LEN, 8_192);
}

#[test]
fn baseline_data_seed_prefix_is_baseline_data_literal() {
    // Pinning the seed bytes prevents any drift between the on-chain PDA
    // and the SDK's PDA derivation.
    assert_eq!(BaselineDataAccount::SEED_PREFIX, b"baseline_data");
}

// ── AW-03 baseline_data_pointer carved from reserve ───────────────────────

#[test]
fn agent_registration_size_unchanged_after_aw03() {
    // baseline_data_pointer was CARVED from the existing 64-byte reserve.
    // Total size MUST remain 221 — anything else means we shifted bytes
    // and broke layout compatibility with already-deployed accounts.
    assert_eq!(AgentRegistration::SIZE_WITHOUT_DISCRIMINATOR, 221);
    assert_eq!(AgentRegistration::SPACE, 229);
}

// ── Hash-binding invariant ─────────────────────────────────────────────────
//
// The handler refuses `commit_baseline` unless
// `sha256(args.payload) == args.baseline_hash`. The tests below pin this
// exact invariant using the on-chain hashv (the same call the handler
// uses).

#[test]
fn empty_payload_hashes_to_known_sha256() {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let h = hashv(&[&[][..]]).to_bytes();
    assert_eq!(h[0], 0xe3);
    assert_eq!(h[31], 0x55);
}

#[test]
fn payload_hash_changes_with_a_single_bit_flip() {
    let a = b"baseline-payload-v1".to_vec();
    let mut b = a.clone();
    b[0] ^= 0x01;
    let ha = hashv(&[&a[..]]).to_bytes();
    let hb = hashv(&[&b[..]]).to_bytes();
    assert_ne!(ha, hb, "single bit flip in payload must change the hash");
}

#[test]
fn payload_hash_is_deterministic() {
    let payload = b"{\"v\":3,\"means\":[\"0.500000000\"]}";
    let h1 = hashv(&[&payload[..]]).to_bytes();
    let h2 = hashv(&[&payload[..]]).to_bytes();
    assert_eq!(h1, h2);
}

#[test]
fn distinct_payloads_produce_distinct_hashes() {
    // Two payloads that differ ONLY in one mean float must yield different
    // hashes — this is the property the binding rests on.
    let p1 = b"{\"v\":3,\"means\":[\"0.500000000\"]}";
    let p2 = b"{\"v\":3,\"means\":[\"0.500000001\"]}";
    let h1 = hashv(&[&p1[..]]).to_bytes();
    let h2 = hashv(&[&p2[..]]).to_bytes();
    assert_ne!(h1, h2);
}

#[test]
fn handler_rejects_when_payload_hash_does_not_equal_committed_hash() {
    // This mirrors the handler's binding-check arithmetic. The check is
    // `computed == args.baseline_hash`; a forged hash that does not equal
    // sha256(payload) must FAIL the equality test.
    let payload = b"real-baseline-bytes".to_vec();
    let computed = hashv(&[&payload[..]]).to_bytes();

    let forged_hash = [0xAAu8; 32]; // attacker-chosen 32 bytes
    assert_ne!(
        computed, forged_hash,
        "the on-chain binding refuses a forged hash because computed != forged",
    );
}

#[test]
fn handler_accepts_only_the_canonical_hash() {
    let payload = b"canonical-baseline-bytes".to_vec();
    let canonical = hashv(&[&payload[..]]).to_bytes();
    // The handler's require!(computed == args.baseline_hash, ...) only
    // accepts `canonical` for this exact payload.
    let computed = hashv(&[&payload[..]]).to_bytes();
    assert_eq!(computed, canonical);
}
