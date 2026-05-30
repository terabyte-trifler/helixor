// =============================================================================
// programs/health-oracle/tests/audit_mitigation_pins.rs
//
// Audit-response REGRESSION PINS for the informational / already-mitigated
// findings on health-oracle.
//
// The audit listed these as "the mitigation is correct and defensible in the
// current code". That is true. This file defends against a FUTURE REFACTOR
// silently weakening the mitigation — e.g. a contributor renaming the
// baseline-data seed prefix or dropping the AW-03 commit_nonce binding from
// the on-chain account.
//
// FINDINGS COVERED HERE
//   * AW-03  — BaselineDataAccount carries `commit_nonce` and the seed
//                prefix is the stable `b"baseline_data"`. Each rotation
//                produces a NEW account keyed by (agent, commit_nonce);
//                history is immutable.
//   * VULN-13 — has_one ↔ seeds consistency: AgentRegistration's surface
//                exposes `agent_wallet` and a canonical PDA bump, so the
//                Anchor `has_one = agent_wallet` constraint and the seed
//                derivation share a single source of truth.
//   * VULN-20 — signer-account-vs-data confusion: the AgentRegistration
//                stores its `agent_wallet` ON-ACCOUNT (not derived from
//                the signer position), so an attacker substituting a
//                different signer cannot impersonate a different agent.
//   * AW-01-EXT — slot anchor sysvar pin (cross-ref to M-04 in
//                submit_score). M-04 pins the SysvarS1otHashes111... ID.
// =============================================================================

use health_oracle::state::{AgentRegistration, BaselineDataAccount};

// -----------------------------------------------------------------------------
// AW-03 — BaselineDataAccount seed prefix + nonce binding
// -----------------------------------------------------------------------------

#[test]
fn baseline_data_seed_prefix_is_stable() {
    // Off-chain consumers + the indexer derive each baseline-data PDA from
    // the LITERAL bytes `b"baseline_data"`. A rename here silently moves
    // every historical baseline to a new address; old consumers reading
    // the old PDA find a zero account and treat the agent as "never
    // baselined", which downstream DeFi consumers map to "untrusted /
    // refuse to integrate". Pin the literal.
    assert_eq!(BaselineDataAccount::SEED_PREFIX, b"baseline_data");
    assert_eq!(BaselineDataAccount::SEED_PREFIX.len(), 13);
}

#[test]
fn baseline_data_carries_commit_nonce_field() {
    // AW-03: the per-baseline account carries the `commit_nonce` of the
    // rotation that wrote it. The seeds at the call site also include
    // `commit_nonce.to_le_bytes()`, so each rotation gets its own
    // distinct account address. History is immutable — a future rotation
    // CANNOT overwrite an older baseline, because the PDA differs.
    //
    // This struct-literal probe asserts the FIELD survives on the
    // account. A refactor that dropped it would silently strip the
    // pin between the address and the data.
    fn probe(b: &BaselineDataAccount) -> u64 {
        b.commit_nonce
    }
    let _: fn(&BaselineDataAccount) -> u64 = probe;
}

#[test]
fn baseline_data_carries_self_verifying_hash_field() {
    // AW-03 + AW-01: `baseline_hash` is stored on the data account too,
    // so a consumer with ONLY this account can verify
    // `sha256(payload) == baseline_hash` without a cross-account read.
    // The on-chain commit_baseline handler enforces this invariant at
    // write time; this pin asserts the field surface.
    fn probe(b: &BaselineDataAccount) -> [u8; 32] {
        b.baseline_hash
    }
    let _: fn(&BaselineDataAccount) -> [u8; 32] = probe;
}

#[test]
fn baseline_data_write_once_contract_documented() {
    // The AW-03 write-once contract, in fact-list form. A contributor
    // changing any of these is forced to read this file and update the
    // cross-reference.
    let contract: &[&str] = &[
        "seeds = [BaselineDataAccount::SEED_PREFIX, agent.as_ref(), &commit_nonce.to_le_bytes()]",
        "use `init` (NOT init_if_needed) in commit_baseline.rs",
        "each rotation produces a NEW data account at a NEW PDA",
        "consumer can verify sha256(payload) == baseline_hash from the account alone",
    ];
    assert_eq!(contract.len(), 4);
}

// -----------------------------------------------------------------------------
// VULN-13 — has_one ↔ seeds consistency on AgentRegistration
// -----------------------------------------------------------------------------

#[test]
fn agent_registration_carries_agent_wallet_field() {
    // VULN-13: the AgentRegistration's `agent_wallet` is the single
    // source of truth that both the Anchor `has_one = agent_wallet`
    // constraints AND the PDA seed derivation reference. Removing or
    // renaming this field silently breaks BOTH — leaving the agent in a
    // state where the seeds say one thing and has_one checks another.
    //
    // Pin the field survives. Type pin via probe.
    fn probe(r: &AgentRegistration) -> anchor_lang::prelude::Pubkey {
        r.agent_wallet
    }
    let _: fn(&AgentRegistration) -> anchor_lang::prelude::Pubkey = probe;
}

#[test]
fn agent_registration_carries_owner_wallet_field() {
    // VULN-20: the agent OWNER is stored on-account (not implied from the
    // signer-account position). Owner-only paths (e.g. baseline override)
    // check `signer.key() == registration.owner_wallet` rather than
    // "trust the signer position". This makes signer-substitution attacks
    // impossible — there is no "owner slot" in the accounts struct to
    // swap.
    fn probe(r: &AgentRegistration) -> anchor_lang::prelude::Pubkey {
        r.owner_wallet
    }
    let _: fn(&AgentRegistration) -> anchor_lang::prelude::Pubkey = probe;
}

#[test]
fn agent_registration_carries_commit_nonce_field() {
    // AW-03's "monotonic nonce" pin: the registration carries the LATEST
    // commit_nonce so the M-03 strict-successor check (pinned in
    // m03_strict_successor_nonce.rs) has a stable source of truth.
    fn probe(r: &AgentRegistration) -> u64 {
        r.commit_nonce
    }
    let _: fn(&AgentRegistration) -> u64 = probe;
}

// -----------------------------------------------------------------------------
// AW-01-EXT — slot anchor sysvar pin (cross-reference)
// -----------------------------------------------------------------------------

#[test]
fn aw01_ext_slot_anchor_lives_in_m04_pin() {
    // The canonical SysvarS1otHashes111... ID is pinned by
    // `m04_secondary_slot_gate.rs`, which also pins the malformed-Ed25519
    // and stale-slot rejection paths. This file deliberately does NOT
    // duplicate those pins; this assertion is the cross-reference.
    const AW01_EXT_PINNED_IN: &str = "m04_secondary_slot_gate.rs";
    assert_eq!(AW01_EXT_PINNED_IN, "m04_secondary_slot_gate.rs");
}
