# Helixor V2 — Launch Checklist

The pre-mainnet gate. Every box must be ticked, with the linked artefact,
**before** an `HELIXOR_MAINNET_OK=1` flag is added to any production env
file.

## 1 — Audit gates (Day 29-31)

- [ ] `audit/run_all.sh` passes locally — 7 PASSED, externals skipped
- [ ] `audit/hardening_check.py` reports **0 HARD findings**
      → `audit/reports/hardening.json`
- [ ] **VULN-20 SQLi sweep clean** —
      `python3 audit/sql_injection_check.py --json audit/reports/sql_injection.json`
      reports **0 HARD findings**. Every `.execute(...)` in
      `helixor-oracle/db/`, `helixor-oracle/baseline/`, `helixor-api/api/`,
      and `helixor-indexer/` uses parameterised binding (`%s` + params
      sequence); no f-strings, no `.format()`, no `+` concatenation.
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
- [ ] **Read API tests green** — `cd helixor-api && pytest` passes
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

- [ ] **VULN-19 atomic deploy + transfer.** Run
      `bash launch/deploy/deploy_programs.sh --cluster mainnet-beta
      --mainnet-ok --squads-vault <pda> --squads-owner <pid,...>
      --deployer-keypair <path>` in a SINGLE command. The script:
      (1) pre-flights the Squads vault (writes
      `audit/reports/squads_vault_preflight.json`),
      (2) builds verifiably,
      (3) for each of the 3 programs: deploys → IMMEDIATELY transfers
      upgrade authority to the Squads vault → verifies on-chain, and
      (4) emits `audit/reports/deploy_verified.json` only when all 3
      programs' authorities equal the vault. The deployer hot key
      MUST NOT be the upgrade authority for any program at the end of
      this step.
- [ ] `launch/deploy/manifest.json` records all 3 program IDs and SHA256s,
      AND each entry's `upgrade_authority` field equals the Squads vault
- [ ] `audit/artifact_verification/verify_so_match.ts` confirms
      deployed `.so` matches local build, all 3 programs
- [ ] `bash launch/deploy/initialize_configs.sh --cluster mainnet-beta
      --mainnet-ok ...` initialises all 3 configs
- [ ] `audit/reports/deploy_verified.json` exists — the safe-to-publish
      marker. Program IDs MUST NOT be announced publicly before this
      file is on disk.
- [ ] First mainnet node brought up with `HELIXOR_MAINNET_OK=1` in
      `/etc/helixor/oracle-node-0.env`, journalctl shows the
      `network_guard: ... PRODUCTION network ... explicit
      HELIXOR_MAINNET_OK=1 opt-in` line
- [ ] **VULN-17 Kafka auth.** Each oracle node's env file sets
      `KAFKA_SECURITY_PROTOCOL=SASL_SSL` (or `SSL` for mTLS-only
      brokers); journalctl shows the
      `kafka_security: service ... starting with 'SASL_SSL'` info
      line. NO node shows `HELIXOR_KAFKA_PLAINTEXT_OK=1` unless the
      cluster sits behind a private-link service mesh that
      authenticates the connection independently (record the
      justification in `audit/reports/kafka_plaintext_optin.md`).
- [ ] **VULN-18 scoring determinism.** Every oracle node runs on a
      Python interpreter in `SUPPORTED_PYTHON_VERSIONS` (currently
      `{(3, 12), (3, 13)}` — see `helixor-oracle/scoring/determinism.py`);
      journalctl shows the
      `scoring_determinism: service ... starting on PRODUCTION with
      pinned runtime python=...` warning line at startup. NO node
      shows `HELIXOR_SCORING_DETERMINISM_OK=1` unless the audited
      runtime has a CVE and the bypass is justified in
      `audit/reports/scoring_determinism_optin.md`. No node has
      `numpy`/`scipy`/`pandas`/`sklearn` in `sys.modules` at startup
      (the guard scans on every entrypoint).
- [ ] **VULN-20 wallet validation on the live API.** From an external
      host, `curl -i $HELIXOR_API_URL/agents/'%27%3B%20DROP%20TABLE%20agent_transactions%3B%20--'/health`
      returns `400 bad_request` (NOT 404, NOT 500). Confirms the
      base58 boundary check is in the deployed binary, not just the
      tests.
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
