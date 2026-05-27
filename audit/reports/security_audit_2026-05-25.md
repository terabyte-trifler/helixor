# Helixor Security Audit Snapshot — 2026-05-25

## Scope

Audited the Helixor V2 monorepo across:

- `helixor-programs` Anchor programs
- `helixor-oracle` scoring, cluster, signing, and gRPC node code
- `helixor-api`, `helixor-indexer`, `helixor-sdk`, `helixor-web`
- `helixor-integration` hardening scripts
- `audit/` launch and audit gates

## High-Impact Findings Fixed

### 1. Certificate digest did not bind the baseline hash

Risk: a valid 3-of-5 cluster signature over `(agent, epoch, score, alert, flags, immediate_red)` could be replayed against a different baseline context because the signed payload did not include `baseline_hash`.

Fix:

- Added `baseline_hash` to the Rust `cert_payload_digest`.
- Added `baseline_hash` to Python `cert_signing.py`.
- Pipeline now computes each wallet's baseline hash and includes it in `SubmittableCertificate`.
- Added tests proving digest changes when the baseline hash changes.

### 2. Oracle challenges were marked verified without on-chain artifacts

Risk: `challenge_oracle` treated `ConflictingScores` and `PhantomAgent` as self-verifying, but the program did not independently load/verify referenced median, certificate, or registration artifacts. This could overstate proof strength and create unsafe oracle-slashing assumptions.

Fix:

- Challenges now record evidence as `Pending`.
- `ProofType::is_onchain_verifiable()` returns false for current proof types.
- Documentation/comments now state that referenced artifacts must be supplied and verified before a challenge is slash-authoritative.
- Tests updated to assert pending status.

### 3. Production oracle gRPC could run without mutual TLS

Risk: direct gRPC score exchange is acceptable for local/dev, but production plaintext peer transport weakens cluster confidentiality and integrity.

Fix:

- Added TLS material support to `GrpcTransport`.
- Added secure server mode with client certificate verification in `run_cluster_node.py`.
- Production (`mainnet-beta` with explicit opt-in) refuses to start unless TLS cert, key, and CA cert paths are configured.
- Added a network guard test for production plaintext refusal.

### 4. VULN-01 replay guard for threshold certificate signatures

Risk reviewed: an attacker could try to replay three legitimate historical Ed25519 precompile instructions, signed by cluster keys over an old certificate digest, while calling `issue_certificate` for a different agent/epoch/score payload.

Resolution:

- Confirmed the on-chain verifier recomputes the canonical digest from the current `issue_certificate` accounts and arguments.
- Confirmed every counted Ed25519 precompile must have `record.message == expected_digest`; valid signatures over any other digest are filtered out.
- Confirmed cross-instruction references are rejected through the `0xFFFF` same-instruction sentinel checks.
- Refactored the tally logic into a pure helper and added cargo-runnable regression tests for historical-digest replay and mixed correct/replayed signatures.
- Added an Anchor integration regression that constructs the exact bad transaction shape: 3 valid cluster signatures over a historical/mismatched digest plus an `issue_certificate` for a different payload. Expected result: `InsufficientSignatures`.

## Dependency Fixes Applied

- `helixor-programs`: upgraded on-chain dependencies from `anchor-lang 0.30.1` / `solana-program 1.18.26` to `anchor-lang 1.0.2` / `solana-program 3.0.0`; this removes `curve25519-dalek 3.2.1` and resolves `RUSTSEC-2024-0344`.
- `helixor-api`: upgraded FastAPI/Starlette path; `pip-audit` clean.
- `helixor-web`: upgraded to a Next.js canary release that removes the vulnerable PostCSS dependency; `npm audit` clean.
- `helixor-sdk`: added `uuid` override; `npm audit` clean.
- `helixor-integration`: upgraded Vitest/Vite path and added overrides for `uuid`, `ws`, and `esbuild`; `npm audit` clean.

## Audit Gates Passing

- Hardening sweep: 0 HARD findings, 2 documented design-intent SOFT findings.
- Entrypoint guard audit: all 3 Python entrypoints guarded.
- Secret hygiene: no committed secrets, no committed `.env`, oracle authority key loaded from env path.
- Rust tests: `cargo test --workspace` passes.
- Rust clippy: passes with Anchor macro cfg noise explicitly allowed.
- Rust audit: `cargo audit` passes; it reports one allowed unmaintained warning for `bincode 1.3.3` through Solana 3, but no vulnerability failure.
- Oracle tests: 1155 passing.
- API tests: 69 passing.
- Indexer tests: 95 passing.
- SDK tests/build: passing.
- Web audit/typecheck/build: passing.
- Cluster load/chaos: 1000 certs, node killed mid-run, passes.
- Trident gate: compatibility smoke passes with current CLI.

## Resolved RustSec Blocker

`cargo audit` previously failed because `anchor-lang 0.30.1` / `solana-program 1.18.26` transitively pulled `curve25519-dalek 3.2.1` (`RUSTSEC-2024-0344`).

Resolution:

- Migrated to `anchor-lang 1.0.2` and `solana-program 3.0.0`.
- Added Borsh 1 explicit discriminant serialization annotations for all explicit-code enums.
- Updated Solana 3 instruction sysvar / Ed25519 precompile imports.
- Updated Anchor 1 `CpiContext::new` call sites to pass program IDs rather than `AccountInfo`.
- Re-ran `cargo clippy`, `cargo test`, and `cargo audit` successfully.

Remaining dependency note:

`cargo audit` still prints one allowed warning for unmaintained `bincode 1.3.3` through Solana 3. It is not a vulnerability failure under the current advisory policy.

## Local Secret Note

`helixor-e2e/.env` exists locally but is ignored by `helixor-e2e/.gitignore` and is not tracked.

## Adversarial-Audit Findings — Verified-Invalid

### C-01: `advance_epoch` ↔ `submit_score` epoch-boundary race

The Top-50 adversarial review listed C-01 (Critical) — the conjecture that an
operator submitting a score at the epoch boundary could interleave with an
`advance_epoch` tick and write the score into a stale or pruned epoch
bucket. After tracing the actual code path the finding is **VERIFIED INVALID
— the protocol fails closed in every ordering.**

Verification chain:

- **Account-locking serialises the race.** `advance_epoch` declares
  `epoch_state` `mut` (write-lock); `submit_score` declares it read-only
  (read-lock). Solana's runtime conflicts write-lock against read-lock on
  the same account, so the two instructions cannot execute in parallel
  within a slot — ordering is total.
- **The on-chain counter check rejects stale epochs.**
  `submit_score::handler` enforces
  `require!(epoch == epoch_state.current_epoch, EpochMismatch)`. If
  `advance_epoch` lands first, `current_epoch = N+1` and any caller
  passing `epoch = N` reverts.
- **The cluster-signed digest is bound to `epoch`.**
  `cert_payload_digest` in `certificate-issuer/src/signing.rs` folds
  `epoch` into the bytes the cluster signs over. If a caller mutates the
  `epoch` parameter to match the post-tick counter, the digest rebuilt
  inside `issue_certificate` no longer matches any cluster signature →
  the Ed25519 precompile check fails → the CPI reverts → the entire
  `submit_score` transaction reverts atomically.

The cross-program failure is therefore atomic and observable; no half-state,
no silent corruption, no forged cert is producible by this race. The worst
case is liveness churn (the cluster must re-sign for the new epoch), and
even that requires the racer to be a cluster member with `advance_epoch`
authority — i.e. a self-DoS, not an external attack.

Defence-in-depth pins added:

- `helixor-programs/programs/health-oracle/tests/epoch_logic.rs::c01_advance_digest_separates_pre_and_post_tick_attestations`
  asserts the advance digest differs across the exact pre-tick / post-tick
  pair the race posits. A future refactor that weakened the per-tick
  binding would fail this test.
- Existing pins relied on for the close-out:
  `certificate-issuer/tests/threshold_logic.rs::digest_changes_with_epoch`
  (cert-side epoch binding) and
  `health-oracle/tests/epoch_logic.rs::aw02_digest_changes_for_different_current_epochs`
  /
  `aw02_digest_changes_for_different_target_epochs` (advance-side per-tick
  binding).

No production-code change is required. Per the project guidance
("don't add validation for scenarios that can't happen"), the on-chain
checks already covering the impossibility have not been duplicated.
