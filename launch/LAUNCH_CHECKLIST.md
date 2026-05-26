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
- [ ] **AW-01 + AW-01-EXT input-provenance + slot-anchor sweep clean** —
      `python3 audit/input_provenance_check.py --json audit/reports/aw01_input_provenance.json`
      reports **0 HARD findings**. The sweep enforces that every cluster
      signing / certificate-issuing / score-submission callsite binds
      BOTH the AW-01 cluster-majority input commitment AND the
      AW-01-EXT Solana slot anchor (third source of truth), so a
      refactor cannot silently drop either binding and let an attacker
      poison upstream inputs without the on-chain signature catching it.
      Specifically:
        1. `oracle.cluster.cert_signing.cert_payload_digest` — every
           call passes the `input_commitment` AND the new
           `slot_anchor` positional (or the explicit
           `slot_anchor=` kwarg).
        2. `oracle.cluster.input_commitment.compute_input_commitment` —
           every call passes the new `slot_anchor` argument; the v2
           commitment folds the 40-byte `(slot, block_hash)` after the
           cross-node binding bytes.
        3. `health_oracle::submit_score` Anchor instruction — every
           TS `.submitScore(...)` callsite passes the
           `inputCommitment`, `slotAnchorSlot`, and `slotAnchorHash`
           arguments AND includes `slotHashesSysvar` in `.accounts({...})`.
        4. `certificate_issuer::issue_certificate` — every TS
           `.issueCertificate(...)` callsite passes the
           `inputCommitment`, `slotAnchorSlot`, and `slotAnchorHash`
           arguments AND includes `slotHashesSysvar` in `.accounts({...})`.
        5. Rust `cpi_issue_certificate(...)` callsite (the
           health-oracle → certificate-issuer CPI) supplies
           `input_commitment`, `slot_anchor_slot`, `slot_anchor_hash`
           verbatim AND forwards `slot_hashes_sysvar`.
      The on-chain `HealthCertificate` is at `layout_version = 4`;
      `signing.cert_payload_digest` in `certificate-issuer` folds
      BOTH the commitment AND the slot anchor into the signed digest;
      `verifyInputProvenance` + `verifyAgainstSolanaLedger` in
      `@helixor/sdk` reproduce them byte-for-byte from observable
      transactions and from the live SlotHashes sysvar. A DeFi
      consumer can detect a Geyser/Kafka/indexer poisoning attack
      AND a coordinated upstream RPC-fleet poisoning attack without
      trusting the cluster at all.
- [ ] **AW-01-EXT on-chain SlotHashes verification gate** —
      `certificate_issuer::slot_anchor::verify_slot_anchor` is wired
      into `issue_certificate::handler` and unit-tested for: matching
      anchor → accept; slot present but hash mismatched →
      `SlotAnchorHashMismatch` (12073); slot outside sysvar window →
      `SlotAnchorTooOld` (12072); zero-sentinel anchor →
      `MissingSlotAnchor` (12070); wrong sysvar account →
      `WrongSlotHashesSysvar` (12071). `cargo test --lib` for
      certificate-issuer must show 5 passing `slot_anchor::tests::*`
      entries. This is the write-time defence-in-depth check; the SDK
      `verifyAgainstSolanaLedger` is the read-time analogue.
- [ ] **AW-01-EXT SDK-side ledger re-verification** — at least one
      integration partner has wired `verifyAgainstSolanaLedger(cert,
      provider)` from `@helixor/sdk` and confirmed it returns `ok:
      true` for a fresh production cert. The partner's `provider` is
      either `Connection.getSlotHashes()` or an equivalent — and is
      pointed at an RPC INDEPENDENT from the cluster's RPC fleet
      (any of: a friendly validator's RPC, an exchange ops RPC, the
      partner's own validator). Wiring a provider that reads from
      one of the cluster's own RPCs defeats the third-source-of-truth
      guarantee. Document the chosen provider RPC in the partner's
      integration policy.
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
- [ ] **AW-01 input-provenance bound on the first live cert.** Decode
      the first mainnet cert via the SDK and verify
      `cert.layoutVersion === 4` AND
      `cert.inputCommitment` is non-zero (32 bytes of `0x00` would
      mean the cert was issued before the AW-01 plumbing landed —
      that must NEVER happen on mainnet). One integration partner
      MUST run `verifyInputProvenance(cert, observedInputs)` against
      the first cert and report `ok: true`; a `Mismatch` here blocks
      promotion. The cert-issuer program rejects a zero
      `input_commitment` at write time
      (`CertificateError::MissingInputCommitment`), so a zero
      commitment on chain would only mean the program itself was
      somehow deployed pre-AW-01 — investigate before issuing more
      certs. Runbook: `launch/runbooks/input_provenance.md`.
- [ ] **AW-01-EXT slot anchor bound on the first live cert.** From the
      SAME decoded cert above, verify
      `cert.slotAnchorSlot !== 0n` AND
      `cert.slotAnchorHash` is not 32 bytes of `0x00`. The cert-issuer
      program rejects a zero anchor at write time
      (`CertificateError::MissingSlotAnchor` 12070) AND verifies the
      pair against the SlotHashes sysvar
      (`SlotAnchorHashMismatch` 12073 / `SlotAnchorTooOld` 12072),
      so a non-zero anchor on a live cert is by-construction a
      Solana-verified `(slot, block_hash)`. One integration partner
      MUST also run
      `verifyAgainstSolanaLedger(cert, provider)` (provider pointed
      at an INDEPENDENT RPC, see audit gate above) and report
      `ok: true` while the cert's slot is still inside the
      ~512-slot SlotHashes window (~3.4 min). After that window,
      the cert is "best-effort verified at write time"; the
      `challenge_certificate` on-chain ix (AW-01-EXT.6) is the
      post-window dispute path — a third-party M-of-N attester
      cluster can file a challenge with their independently
      observed `true_block_hash`, the handler compares to the
      cert's pinned `slot_anchor_hash`, and on divergence flips
      `cert.challenge_state` to `Upheld` (REPUDIATED) and emits
      `CertificateRepudiated`. See design at
      `launch/design/aw01_ext_discrepancy_challenge.md`. Runbook
      addendum: `launch/runbooks/input_provenance.md`
      "AW-01-EXT — slot-anchor divergence".
- [ ] **AW-02 M-of-N epoch-advance is the only Tier-1 path.** The
      deployed `advance_epoch` instruction REQUIRES
      `consensus_threshold(OracleConfig.oracle_keys)` Ed25519
      precompile attestations over the canonical advance digest
      (`sha256("helixor-epoch-advance" || current_epoch ||
      target_epoch || last_advanced_at)`) for every Tier-1 tick.
      The legacy single-key `advance_authority` Tier-1 path is
      GONE — the field is a non-authoritative hint, retained for
      layout compatibility. The Tier-2 liveness fallback (any
      single cluster member after 2× duration) remains for
      catastrophic-failure recovery. Confirm by inspecting any
      production `EpochAdvanced` event: it MUST be accompanied
      by an `EpochAdvancedByThreshold` event whose
      `attester_count >= consensus_threshold(cluster)`. An
      `EpochAdvancedByFallback` event in steady state is a P0
      (the cluster failed to assemble quorum for >= 2× duration —
      see `launch/runbooks/epoch_advance_stalled.md`).
- [ ] **AW-02 cluster signer rotation runbook in place.** Each
      cluster operator has tested signing the advance digest
      with their HSM / KMS / Squads setup at least once on
      devnet. The off-chain signer pipeline produces an Ed25519
      program instruction the on-chain verifier accepts (use the
      SDK helper `advancePayloadDigest` from `@helixor/sdk` to
      compute the digest — it is byte-for-byte identical to the
      on-chain `advance_payload_digest`). The cluster's daily
      "advance coordinator" rotation is documented in
      `launch/runbooks/epoch_advance_stalled.md`.
- [ ] **AW-01-EXT.6 challenge cluster wired or DELIBERATELY left
      disabled.** `initialize_config` was called with EITHER:
      (a) `challenge_attester_keys` containing >= 1 DISJOINT
      third-party validator pubkeys + `challenge_threshold >= 1`
      (the active configuration — challenge ix is live), OR
      (b) `[]` + `0` (the safe deferred configuration — challenge
      ix rejects every call with `NoAttesterCluster` 12080; the
      write-time slot-anchor check remains the only defence).
      Document the choice in `audit/reports/challenge_cluster.md`
      with the attester operator names and the rotation policy.
      A wired attester cluster MUST NOT overlap `cluster_keys`
      — the program's `initialize_config` validator rejects
      overlap with `AttesterOverlapsCluster` (12088).
- [ ] **The first epoch on mainnet completes** end-to-end, on-chain
      cert visible via explorer

## 5 — Post-launch (first 30 days)

- [ ] Daily review of `helixor_byzantine_flags_total` — flag count should
      be 0 or near 0 in steady state
- [ ] Daily review of `helixor_cert_submit_failures_total`
- [ ] **Daily review of `helixor_input_divergence_flags_total`** — any
      epoch where this is non-zero means at least one node disagreed
      with the cluster on what its upstream pipeline delivered (AW-01).
      Steady state is 0. A persistent non-zero on the same node
      indicates a poisoned or misconfigured upstream — follow
      `launch/runbooks/input_provenance.md`. ANY epoch where the
      aggregator reports `input_commitment is None` (no AW-01 quorum
      → no cert issued for that agent) is a P0.
- [ ] **Daily review of `helixor_slot_anchor_writetime_rejections_total`
      (AW-01-EXT).** Any non-zero count for either
      `SlotAnchorHashMismatch` (12073) or `SlotAnchorTooOld` (12072)
      means a write-time slot-anchor rejection landed on chain.
      `SlotAnchorTooOld` in steady state is a latency regression
      (page if sustained — see `launch/runbooks/latency_regression.md`).
      `SlotAnchorHashMismatch` is a P0 — at least one cluster RPC
      returned a fake block hash for the slot the cluster pinned;
      follow the SOURCE_DISAGREEMENT triage in
      `launch/runbooks/input_provenance.md`.
- [ ] **Daily review of AW-02 epoch-advance events.** EVERY
      `EpochAdvanced` event in steady state MUST be paired with
      an `EpochAdvancedByThreshold` event whose `attester_count
      >= consensus_threshold(cluster)`. A SINGLE
      `EpochAdvancedByFallback` event is a P0 — the cluster could
      not assemble M-of-N attestations for the prior 2× duration
      window, meaning > N - threshold cluster nodes were silent
      AND the previous tick's primary signer also missed. Follow
      `launch/runbooks/epoch_advance_stalled.md`. A trend of
      declining `attester_count` toward the threshold (e.g. 5/5
      → 4/5 → 3/5 over a week) is an early-warning P1 even
      without a fallback event — it indicates a node is silently
      dropping out of the daily ceremony.
- [ ] **Daily review of AW-01-EXT.6 challenge events.** Any
      `CertificateRepudiated` event emitted on chain is a P0 —
      a cert was provably wrong at the slot-anchor layer and
      the third-party attester cluster signed off on the
      divergence. Downstream consumers MUST treat the cert as
      invalid; the slash-authority off-chain plumbing should
      have already triggered the cluster-side slashing flow.
      `ChallengeRejected` events are not P0 (the challenge was
      frivolous — the cluster was right; the challenger's rent
      was consumed as the anti-spam cost) but a SUSTAINED rate
      of `ChallengeRejected` from the same challenger pubkey
      indicates either a misconfigured attester operator or a
      DOS attempt — investigate and consider rotating the
      attester cluster.
- [ ] **Weekly external-RPC ledger re-verification.** A scheduled job
      decodes the previous day's certs and runs
      `verifyAgainstSolanaLedger` against an RPC NOT in the cluster's
      RPC fleet. For each cert still inside the SlotHashes window,
      the job must report `ok: true`. Any `AnchorHashMismatch`
      finding from this job is a P0 (the cluster's RPCs and the
      external RPC disagree — at least one is lying). Output:
      `audit/reports/slot_anchor_weekly_<YYYY-MM-DD>.json`.
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
