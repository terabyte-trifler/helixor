# Helixor V2 — Day 29 Audit Readiness

This directory is the audit-readiness package. It bundles everything an
external security auditor needs to verify the Helixor on-chain programs
before mainnet: programmatic hardening checks, fuzz harnesses, load
tests, CVE scans, deployed-artifact verification, and the upgrade
authority transfer runbook.

## Quick start

```bash
bash audit/run_all.sh
```

Runs every gate this environment supports and prints a single PASS/FAIL.
The local path now executes every gate instead of skipping: Trident runs
the generated fuzz target, API/DB load tests start local smoke targets
when staging credentials are absent, and `.so` verification deploys the
audited artifacts to a disposable local validator before comparing
on-chain ProgramData bytes. Production-sized gates can be dialed up with
the environment variables shown below.

## What's gated, and where it runs

| Gate                                 | Runner                       | Where it executes |
|--------------------------------------|------------------------------|--------------------|
| 1. Programmatic hardening sweep      | `hardening_check.py`         | CI + local (Python) |
| 2. cargo clippy `-D warnings`        | workspace lints table        | CI + local (Rust) |
| 3. cargo audit                       | CVE scan                     | CI + local (Rust) |
| 4. Trident fuzz                      | `trident/run_fuzz.sh`        | local + dedicated runner |
| 5. Cluster load + chaos              | `load_tests/test_cluster_under_load.py` | CI + local |
| 6. API load                          | `load_tests/api_load.py`     | local smoke + dedicated runner |
| 7. DB stress                         | `load_tests/db_stress.py`    | local smoke + dedicated runner |
| 8. Squads 3-of-5 authority transfer  | `multisig/transfer_upgrade_authority.ts` | deploy step |
| 9. `.so` byte-match                  | `artifact_verification/deploy_and_verify_local.sh` / `verify_so_match.ts` | local validator + post-deploy |

CI (`.github/workflows/audit.yml`) sustains gates 1-5 plus the Python and
Rust test suites. The same scripts support longer pre-mainnet runs by
raising iteration counts, row counts, request duration, or pointing the
artifact verifier at an already deployed cluster.

## Programmatic hardening — runs here

`hardening_check.py` walks every Rust source file in the three programs
and checks six categories:

1. **Naked `unwrap()` / `expect()`** in production code — HARD
2. **Canonical PDA bumps** — every `bump` reference matches an accepted
   form (Anchor 0.30 `ctx.bumps.<name>`, stored bump on account, `bump,`
   in the seeds attribute)
3. **Unchecked arithmetic** — naked `+`/`-`/`*`/`/` flagged; safe forms
   are `checked_*` / `saturating_*` / `wrapping_*` / `// audit:` explicit
   allow
4. **`overflow-checks = true`** on the release profile (workspace
   Cargo.toml)
5. **Authority constraints** on sensitive instructions — every sensitive
   ix carries a `Signer<'info>` AND a `constraint = / has_one = /
   pubkey-check`, OR is an `init` admin handler (one-shot creation), OR
   is in the documented design-intent allowlist (`issue_certificate` uses
   threshold sigs; `challenge_oracle` is permissionless by design)
6. **Workspace lints table** — `[workspace.lints.clippy] all = "deny"`
   and `unused_must_use = "deny"`

Findings are HARD (blocking) or SOFT (review). Output goes to
`audit/reports/hardening.json` and stdout. Day 29 currently reports:

```
TOTAL: 0 HARD findings, 2 SOFT findings
✅ CLEAN — no blocking findings.
```

The 2 SOFT findings are the documented design-intent allowlist entries
(`issue_certificate` + `challenge_oracle`).

## Reports

All gate outputs land in `audit/reports/`:

```
audit/reports/
├── hardening.json       — full hardening sweep
├── fuzz_coverage.json   — per-handler fuzz coverage   (after Trident run)
├── fuzz_crashes/        — persisted crashing inputs   (empty = pass)
├── api_load.json        — API throughput + latencies  (after API load)
├── db_stress.json       — DB insert + read latencies  (after DB stress)
├── so_match.json        — local vs deployed byte-match (post-deploy)
└── multisig_transfer.json — upgrade-authority transfer log
```

## Runbook for the audit operator

```bash
# 1. local clean checkout
git clone <repo> && cd helixor

# 2. programmatic gates (no external services)
bash audit/run_all.sh

# 3. fuzz
bash audit/trident/run_fuzz.sh                         # local gate, default 1000 iterations
HELIXOR_TRIDENT_ITERATIONS=10000000 bash audit/trident/run_fuzz.sh

# 4. load tests against staging deployment
export HELIXOR_API_URL=https://api.staging.helixor.xyz
export DATABASE_URL=postgres://...
python3 audit/load_tests/api_load.py --base-url "$HELIXOR_API_URL" \
    --rate 4 --duration 3600              # 1-hour full load
python3 audit/load_tests/db_stress.py --rows 50_000_000

# 5. transfer upgrade authority to Squads vault
npx ts-node audit/multisig/transfer_upgrade_authority.ts \
    --vault <SquadsVaultPDA> \
    --keypair ~/.config/solana/deployer.json \
    --cluster mainnet-beta \
    --execute

# 6. verify deployed .so matches local build
# local audit path: deploys the local .so files to a disposable validator,
# then verifies the on-chain ProgramData bytes match the local artifacts.
bash audit/artifact_verification/deploy_and_verify_local.sh

# deployed cluster path:
cd helixor-programs && anchor build --verifiable
cd ../audit/artifact_verification && \
    npx ts-node verify_so_match.ts --cluster mainnet-beta

# 7. file every report under audit/reports/ with the audit log
```

## What's in the box

```
audit/
├── README.md                         — this file
├── run_all.sh                        — one-shot driver
├── hardening_check.py                — the programmatic sweep
├── trident/
│   ├── README.md
│   ├── Trident.toml
│   ├── run_fuzz.sh
│   └── targets/<program>/fuzz_target.rs
├── load_tests/
│   ├── test_cluster_under_load.py    — runs in CI; 1000 certs / chaos
│   ├── api_load.py                   — 10K queries/h harness
│   └── db_stress.py                  — 50M row stress harness
├── multisig/
│   └── transfer_upgrade_authority.ts — Squads 3-of-5 transfer
├── artifact_verification/
│   ├── deploy_and_verify_local.sh    — local validator deploy + byte-match
│   └── verify_so_match.ts            — deployed vs local .so check
└── reports/                          — all gate outputs land here
```
