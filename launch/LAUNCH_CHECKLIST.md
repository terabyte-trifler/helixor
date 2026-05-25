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
- [ ] **VULN-21 Ed25519 strictness sweep clean** —
      `python3 audit/ed25519_strictness_check.py --json audit/reports/ed25519_strictness.json`
      reports **0 HARD findings**. NO file under signing/verification
      paths uses any batch-verify primitive (`verify_batch`,
      `batch_verify`, `verify_strict_batch`, `verify_multi`,
      `multi_verify`, `VerifyBatch`), no Rust code calls a non-strict
      `ed25519_dalek::*.verify(...)` (only `verify_strict(`), and no
      Python code imports a non-OpenSSL Ed25519 library (`nacl.signing`,
      `pysodium`, `fastecdsa`). Off-chain (Python `cryptography`) and
      on-chain (Solana's Ed25519 precompile = ed25519-dalek strict)
      MUST share canonical-S semantics so a signature that passes
      client-side never fails the precompile.
- [ ] **VULN-22 scoring-algo version-pinning sweep clean** —
      `python3 audit/version_pinning_check.py --json audit/reports/version_pinning.json`
      reports **0 HARD findings**. `CommitRequest` and `RevealRequest`
      both carry `scoring_algo_version` + `scoring_weights_version`;
      `compute_commit_hash()` and `verify_reveal()` both accept an
      `algo_version=` kwarg that is folded into the sha256 input;
      `CommitRevealRound` exposes `pinned_algo_version` and
      `version_mismatched_nodes()`; `ByzantineEpochReport` carries
      `version_excluded_nodes`. A version-mismatched node MUST be
      silently excluded (no Byzantine flag, no strike, no slash) —
      slashing for "wrong scoring version" enables an upgrade-window
      grief attack against honest operators.
- [ ] **VULN-23 cert-consumption sweep clean** —
      `python3 audit/cert_consumption_check.py --json audit/reports/cert_consumption.json`
      reports **0 HARD findings**. The SDK exports `SafeCertReader` with
      `CERT_MAX_AGE_SECONDS = 48*60*60`, `MAX_SCORE_VELOCITY = 200`,
      `VELOCITY_WINDOW_EPOCHS = 3`, `MIN_HISTORY_REQUIRED = 2`, and
      enumerates `STALE_CERT` / `VELOCITY_EXCEEDED` /
      `INSUFFICIENT_HISTORY` reject reasons; the API exposes
      `compute_safe_score()` at the same constants and the
      `/agents/{wallet}/safe_score` route. A DeFi consumer that
      `import { SafeCertReader }` or `GET /agents/{wallet}/safe_score`
      gets freshness (≤ 48h) AND velocity (≤ 200/3 epochs) guards for
      free — the underlying VULN-23 attack chain (flash-loan score
      manipulation + DeFi drain) requires BOTH the off-chain
      `apply_delta_guard_rail` clamp AND a consumer-side velocity check
      because cert-account storage cannot carry `previous_score` without
      a backwards-incompatible migration.
- [ ] **VULN-25 supply-chain sweep clean** —
      `python3 audit/supply_chain_check.py --strict --json audit/reports/supply_chain.json`
      reports **0 HARD findings** (strict mode also fails on the
      `*-requirements-txt-missing` rules, which the default run_all
      sweep tolerates pre-release). Before mainnet:
        1. Run `bash scripts/regen_requirements.sh` to produce
           `helixor-{oracle,api,indexer}/requirements.txt` with full
           SHA256 hash closures via `pip-compile --generate-hashes`.
           Commit BOTH `.in` and `.txt` files.
        2. Verify `helixor-programs/Cargo.lock` is committed (it
           already is — Rust transitives are pinned).
        3. Confirm `oracle/cluster/signer.py` exports the `Signer`
           Protocol with `InProcessSigner` (default) and `HSMSigner`
           (production swap-in). `HSMSigner.sign` MUST raise
           `NotImplementedError` on the base class so a misconfigured
           production deploy that forgot the HSM subclass fails
           LOUDLY rather than silently falling back.
        4. Confirm `launch/deploy/systemd/oracle-node@.service`
           still carries the supply-chain hardening directives:
           `ReadOnlyPaths=/opt/helixor`, `SystemCallFilter=@system-service`,
           `CapabilityBoundingSet=` (empty), `MemoryDenyWriteExecute=true`,
           `ProtectSystem=strict`.
      Production install command (in the deploy script):
      `/opt/helixor/venv/bin/pip install --require-hashes --no-deps -r helixor-oracle/requirements.txt`.
      A hash drift (compromised mirror, MITM, registered ghost
      version) trips here BEFORE the bytes ever import.
- [ ] **VULN-24 adversarial-ML sweep clean** —
      `python3 audit/adversarial_ml_check.py --json audit/reports/adversarial_ml.json`
      reports **0 HARD findings**. All four mitigations against
      anomaly/drift evasion are wired:
        1. `detection/window_jitter.py` exposes `compute_window_jitter`
           keyed on `epoch_advance_seed` (the on-chain
           `EpochState.last_advanced_at`), `MAX_JITTER_SECONDS = 600`
        2. `scoring/composite.py` sets `MIN_ACTIVE_DETECTORS = 3` and
           ORs `FlagBit.ENSEMBLE_INCOMPLETE` when fewer dimensions
           produced a real result
        3. `scoring/_gaming.py` exposes
           `apply_dimension_delta_guard_rail` at `DIM_MAX_SCORE_DELTA = 250`
           (caller ORs `FlagBit.DIMENSION_CLAMPED`)
        4. `helixor-api/api/flag_obfuscation.py` exposes
           `compute_flag_token` + `popcount`; `HealthResponse` exposes
           `flag_set_token` + `flag_count` and NEVER the raw bitmask.
      Together the four mitigations break the per-epoch read-then-craft
      feedback loop that an RL-style adversarial-ML attacker depends on.
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
- [ ] **VULN-21 signature symmetry on the live cluster.** During the
      first mainnet epoch, journalctl on any cluster node shows the
      `threshold signatures verified: N of 5 (threshold 3)` line emitted
      by `certificate_issuer::signing::verify_threshold_signatures` —
      meaning the precompile accepted every signature the off-chain
      aggregator produced. If the precompile ever rejects an
      aggregator-emitted signature, the transaction aborts BEFORE the
      handler runs and this log line is absent — investigate the
      off-chain / on-chain Ed25519 library symmetry before continuing.
- [ ] **VULN-22 scoring-algo version pin live on the cluster.** Every
      oracle node in the first mainnet epoch logs the same
      `epoch %d (node %s): %d committed, %d verified, %d faulty,
      %d non-revealers, %d version-excluded, closed_by_quorum=%s` line
      with `version-excluded=0`. Any node with `version-excluded > 0`
      means a peer is on a stale (scoring_algo, scoring_weights)
      version — pause the rollout, finish the upgrade, do NOT slash
      the lagging node. A future scoring-algo upgrade MUST take effect
      at epoch N+1 via governance, not mid-epoch.
- [ ] **VULN-23 safe_score endpoint live.** From an external host,
      `curl -i $HELIXOR_API_URL/agents/<wallet>/safe_score` returns
      `200 OK` with a JSON body whose `ok` field is the discriminator.
      For a brand-new agent the body MUST be
      `{"ok": false, "reason": "INSUFFICIENT_HISTORY", ...}` — NOT a
      404, NOT a default-allow. The DeFi-integrator runbook
      (`launch/RUNBOOK_defi_integration.md`) MUST recommend
      `GET /agents/{wallet}/safe_score` or the SDK's `SafeCertReader`
      over the raw `getScore()` path; raw `getScore()` is for telemetry
      only, never for gating value transfer.
- [ ] **VULN-25 supply chain locked at runtime.** On each oracle host:
      `sudo systemctl show oracle-node@0 | grep -E '^(ReadOnlyPaths|SystemCallFilter|CapabilityBoundingSet|MemoryDenyWriteExecute)='`
      reports the exact directives from the committed unit file.
      `sudo systemd-analyze security oracle-node@0.service` reports
      an overall exposure score < 2.0 (SAFE). The deploy script's
      pip step used `--require-hashes` (grep the install log for
      the literal flag). `pip check` returns no inconsistencies.
      The per-host firewall (iptables/nftables — see
      `launch/runbooks/supply_chain.md`) drops all egress from the
      `helixor` UID except the documented RPC + indexer + peer-RPC
      destinations.
- [ ] **VULN-24 flag obfuscation live.** From an external host,
      `curl -s $HELIXOR_API_URL/agents/<wallet>/health | jq .` returns
      a body that contains `flag_set_token` (a 16-hex-char string) and
      `flag_count` (an int) but **NOT** a raw `flags` field. The same
      request issued twice for the same `(wallet, epoch)` MUST return
      the same `flag_set_token`; the same wallet at two different
      epochs MUST return different tokens even if the underlying
      bitmask is identical. If `flags` reappears on the wire, an
      adversarial-ML attacker can read back exactly which detectors
      fired and craft the next input around them — the on-chain
      bitmask layout stays unchanged, only the public read surface is
      obfuscated.
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
