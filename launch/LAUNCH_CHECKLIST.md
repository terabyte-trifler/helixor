# Helixor V2 — Launch Checklist

The pre-mainnet gate. Every box must be ticked, with the linked artefact,
**before** an `HELIXOR_MAINNET_OK=1` flag is added to any production env
file.

## 1 — Audit gates (Day 29-31)

- [ ] `audit/run_all.sh` passes locally — 14 PASSED, 0 SKIPPED
- [ ] `audit/hardening_check.py` reports **0 HARD findings**
      → `audit/reports/hardening.json`
- [ ] `audit/entrypoint_guard_audit.py` clean — every entrypoint (cluster
      node, read API) calls `enforce_network_guard`
- [ ] `cargo clippy --workspace -- -D warnings` clean on rust toolchain
- [ ] `cargo audit --deny warnings` clean (no CVEs against pinned deps)
- [ ] `cargo test --workspace` passes (Rust pure-logic + integration)
- [ ] **Trident fuzz 10M iterations clean** — zero panics, full handler
      coverage → `audit/reports/fuzz_coverage.json` exists,
      `audit/reports/fuzz_crashes/` empty
- [ ] **API load 10K req/h sustained for 1h** against the deployed API —
      p95 < 500ms, server_error_rate < 0.1%
      → `audit/reports/api_load.json`
- [ ] **DB stress 50M rows ingested** — throughput ≥ 10K rows/s,
      read p95 < 100ms → `audit/reports/db_stress.json`
- [ ] **Cluster chaos test green in CI** — 20 epochs × 50 agents with
      mid-run kill, all certs threshold-signed
- [ ] **Read API tests green** — `cd helixor-api && pytest` passes,
      including the Timescale/Postgres-backed repository path
- [ ] External security audit report received, all findings addressed
- [ ] Internal review of every `// audit:` annotation in the codebase

## 2 — Devnet bake (≥ 30 days)

- [ ] 3-of-5 cluster deployed to devnet
- [ ] No `ProductionRefusalTriggered` alert in the period
- [ ] No `ChallengeOracleFiled` (or all were intentional adversarial tests)
- [ ] At least **one full chaos rehearsal** — kill a node mid-day,
      confirm cluster recovers, postmortem filed
- [ ] **Continuous cert production** for the bake period — no quorum
      gaps > 5 minutes
- [ ] Indexer hypertable size projected within 24-month plan
- [ ] Detection version stable for the last 7 days (no rollbacks)

## 3 — Mainnet pre-deploy

- [ ] All 5 oracle node host machines provisioned in 5 different regions
- [ ] All 5 oracle keypairs generated, **stored only in sealed locations**
      (HSM / hardware wallet), pubkeys committed to git for reference
- [ ] Squads 3-of-5 multisig vault created via Squads CLI
      → vault pubkey recorded in `launch/deploy/manifest.json`
- [ ] All 5 multisig members have hardware wallets, have signed a test
      tx to confirm key custody
- [ ] **Mainnet runbook reviewed by lead** + filed on-call rotation
- [ ] Monitoring stack (Prometheus + Alertmanager) live and tested in
      dev — every alert in `launch/monitoring/alerts.yml` fired
      manually at least once
- [ ] Backup RPC endpoints configured (`SOLANA_RPC_URL` has a fallback)
- [ ] Fee-payer account funded with > 30 days of cert-write SOL
- [ ] **Postmortem template** in `incidents/` reviewed by team

## 4 — Mainnet deploy (canary)

See `launch/CANARY_ROLLOUT.md` for the phased plan. The checklist here is
the entry gate.

- [ ] `bash launch/deploy/deploy_programs.sh --cluster mainnet-beta --mainnet-ok`
      runs with no errors
- [ ] `launch/deploy/manifest.json` records all 3 program IDs and SHA256s
- [ ] `audit/artifact_verification/verify_so_match.ts` confirms
      deployed `.so` matches local build, all 3 programs
- [ ] `bash launch/deploy/initialize_configs.sh --cluster mainnet-beta
      --mainnet-ok ...` initialises all 3 configs
- [ ] **Upgrade authority transferred to the Squads vault** —
      `audit/multisig/transfer_upgrade_authority.ts --execute` clean,
      `audit/reports/multisig_transfer.json` records all 3 transfers,
      `verify_so_match.ts` confirms the new authority on-chain
- [ ] First mainnet node brought up with `HELIXOR_MAINNET_OK=1` in
      `/etc/helixor/oracle-node-0.env`, journalctl shows the
      `network_guard: ... PRODUCTION network ... explicit
      HELIXOR_MAINNET_OK=1 opt-in` line
- [ ] **The first epoch on mainnet completes** end-to-end, on-chain
      cert visible via explorer

## 5 — Post-launch (first 30 days)

- [ ] Daily review of `helixor_byzantine_flags_total` — flag count should
      be 0 or near 0 in steady state
- [ ] Daily review of `helixor_cert_submit_failures_total`
- [ ] Weekly rolling restart of one node at a time (confirms cluster
      tolerates planned restarts the same way it tolerates failures)
- [ ] Monthly cert byte-match re-verification — deployed `.so` still
      matches the audited build
- [ ] Open-rate-limit pressure release valves on the API — confirm
      rate-limit alerts fire correctly

---

## What "done" means

When every box above is ticked, the system is **ready for the public
agent registration window** — V2 launches.
