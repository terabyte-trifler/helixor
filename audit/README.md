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
External gates (Trident, deployed-API load, deployed-`.so` verification,
multisig transfer) are explicitly **skipped with reasons** when the
relevant tool or credentials aren't present, rather than silently
passing.

## What's gated, and where it runs

| Gate                                 | Runner                       | Where it executes |
|--------------------------------------|------------------------------|--------------------|
| 1. Programmatic hardening sweep      | `hardening_check.py`         | CI + local (Python) |
| 2. cargo clippy `-D warnings`        | workspace lints table        | CI + local (Rust) |
| 3. cargo audit                       | CVE scan                     | CI + local (Rust) |
| 4. Trident fuzz 10M                  | `trident/run_fuzz.sh`        | dedicated runner |
| 5. Cluster load + chaos              | `load_tests/test_cluster_under_load.py` | CI + local |
| 6. API load 10K/h                    | `load_tests/api_load.py`     | dedicated runner |
| 7. DB stress 50M rows                | `load_tests/db_stress.py`    | dedicated runner |
| 8. Squads 3-of-5 authority transfer  | `multisig/transfer_upgrade_authority.ts` | deploy step |
| 9. Deployed `.so` byte-match         | `artifact_verification/verify_so_match.ts` | post-deploy |

CI (`.github/workflows/audit.yml`) sustains gates 1-3, 5, plus the Python
and Rust test suites. The longer-running and credentialled gates (4, 6-9)
run on dedicated triggers or pre-mainnet checklists.

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

# 3. fuzz (dedicated runner, ~6h)
bash audit/trident/run_fuzz.sh

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
│   └── verify_so_match.ts            — deployed vs local .so check
└── reports/                          — all gate outputs land here
```
