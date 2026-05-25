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
