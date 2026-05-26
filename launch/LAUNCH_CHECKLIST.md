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
- [ ] **AW-03 baseline-provenance sweep clean** —
      `python3 audit/baseline_provenance_check.py --json audit/reports/aw03_baseline_provenance.json`
      reports **0 HARD findings**. The sweep enforces that every
      production cluster-signing callsite binds the AW-03
      `baseline_commit_nonce` so the cert-payload digest names a
      SPECIFIC fetchable `BaselineDataAccount` PDA on chain. A
      regression that drops the binding would let a malicious cluster
      rotate the baseline mid-attack and still emit a cert whose
      stale `baseline_hash` cannot be tied back to any on-chain
      payload the consumer can re-verify. Specifically:
        1. `oracle.cluster.cert_signing.cert_payload_digest` — every
           production call passes the `baseline_commit_nonce=` kwarg
           (default-0 is reserved for legacy/test paths and is gated
           out of the production scan roots).
        2. TS `certPayloadDigest(...)` — every callsite includes the
           `baselineCommitNonce` token in its argument region (either
           as a named binding or as an explicit annotation comment)
           so a refactor that drops the 8-byte BE tail cannot pass
           review silently.
        3. TS `baselineDataPda(healthOracle, agent, <nonce>)` — every
           callsite passes a nonce-bearing variable (substring
           `nonce`); a constant or literal there would mean the
           caller is deriving the PDA against a hard-coded rotation
           rather than the agent's current `baseline_commit_nonce`.
      The on-chain `BaselineDataAccount` is at `layout_version = 1`
      with seeds `["baseline_data", agent_wallet, commit_nonce_le]`;
      the program enforces `sha256(payload) == baseline_hash` at
      write time, and `BaselineStats` + `HealthCertificate` carry
      the `baseline_commit_nonce` that names the latest account.
      `verifyBaselineProvenance` in `@helixor/sdk` reproduces the
      hash byte-for-byte from the fetched payload. A DeFi consumer
      can detect a substituted baseline without trusting either the
      cluster OR a separate DA service.
- [ ] **AW-04 scoring-provenance sweep clean** —
      `python3 audit/scoring_provenance_check.py --json audit/reports/aw04_scoring_provenance.json`
      reports **0 HARD findings**. The sweep enforces that every
      production cluster-signing / certificate-issuing callsite
      binds BOTH the AW-04 `scoring_code_hash` and the AW-04
      `score_components_hash` so the cert-payload digest names a
      SPECIFIC scoring kernel version AND a SPECIFIC fetchable
      `ScoreComponentsAccount` PDA on chain. A regression that
      drops either binding would silently emit certs that bind to
      "no code" / "no components" — defeating AW-04 without any
      type error, since both kwargs default to 32 zero bytes for
      legacy compatibility. Specifically:
        1. `oracle.cluster.cert_signing.cert_payload_digest` —
           every production call passes BOTH the
           `scoring_code_hash=` and `score_components_hash=`
           kwargs (default-zero is reserved for legacy/test paths
           and is gated out of the production scan roots).
        2. TS `certPayloadDigest(...)` — every callsite includes
           BOTH the `scoringCodeHash` and `scoreComponentsHash`
           tokens in its argument region (either as named bindings
           or as explicit annotation comments) so a refactor that
           drops the 64-byte tail cannot pass review silently.
        3. TS `scoreComponentsPda(certIssuer, agent, <epoch>)` —
           every callsite passes an epoch-bearing variable
           (substring `epoch`); a constant or literal there would
           mean the caller is deriving the components PDA against
           a hard-coded epoch rather than the cert's own
           `cert.epoch`.
      The on-chain `ScoreComponentsAccount` is at `layout_version
      = 1` with seeds `["score_components", agent_wallet,
      epoch_le]`; the program computes `sha256(payload)` at init
      time (the chain NEVER trusts a caller-supplied hash), and
      `HealthCertificate` (v7) carries `scoring_code_hash` whose
      32 bytes are folded into `cert_payload_digest` after the
      AW-03 nonce, with `score_components_hash` folded immediately
      after as another 32 bytes. `verifyScoreComputation` in
      `@helixor/sdk` re-derives BOTH the hash AND the headline
      score from the fetched payload. A DeFi consumer can detect a
      silent kernel swap OR an arithmetically inconsistent score
      without trusting either the cluster OR a separate DA service.
- [ ] **SPOF audit gate clean** —
      `python3 audit/spof_check.py --json audit/reports/spof.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the 9-entry SPOF inventory in
      `launch/design/spof_resolution.md`: SPOF-#2 (slash-authority
      rotation ceremony), SPOF-#3 (Squads upgrade authority),
      SPOF-#5 (Kafka RF=3 min.insync=2), SPOF-#6 (TimescaleDB
      primary+standby+WAL archive), SPOF-#7+#9 (3 API replicas
      behind nginx LB), SPOF-#8 (Geyser N>=3 with
      `SinglePointGeyserError` boot refusal). A regression that
      removes any mitigation lights the gate red BEFORE the change
      reaches mainnet; SPOF-#1 and SPOF-#4 are covered by the AW-02
      and cluster-threshold gates respectively.
- [ ] **Trust-assumption audit gate clean** —
      `python3 audit/trust_assumption_check.py --json audit/reports/trust_assumption.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the 8-entry TRUST ASSUMPTIONS inventory in
      `launch/design/trust_resolution.md`: TA-1 (oracle-node honesty —
      `DivergenceDetector` + `DEFAULT_SCORE_TOLERANCE=50`), TA-2
      (Geyser data integrity — runner pre-flight +
      `is_verified_consensus_source` marker), TA-3 (scoring
      properties — monotonicity + IMMEDIATE_RED invariants pinned),
      TA-4 (library verification — `EXPECTED_LIBRARY_VERSIONS` in
      lockstep with `requirements.in`), TA-5 (tx-window digest —
      `compute_tx_window_digest` present), TA-6 (cert freshness —
      `MAX_AGE_SECONDS=48h` + `is_fresh_at`), TA-7 (Squads transition
      deadline 2026-09-01T00:00:00Z pinned), TA-8 (multi-RPC consensus
      — `MAINNET_MIN_RPC_ENDPOINTS=3`, `MIN_RPC_CONSENSUS_THRESHOLD=2`).
      A regression that removes any of these mitigations lights the
      gate red BEFORE the change reaches mainnet.
- [ ] **Centralization audit gate clean** —
      `python3 audit/centralization_check.py --json audit/reports/centralization.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the 4-entry HIDDEN CENTRALIZATION RISKS
      inventory in `launch/design/centralization_resolution.md`:
      HCR-1 (RPC provider monoculture — `verify_provider_diversity`,
      `MIN_DISTINCT_RPC_PROVIDERS=2`, `KNOWN_PROVIDERS` covering
      helius/quicknode/triton), HCR-2 (single-region cluster —
      `verify_region_diversity`, `MIN_DISTINCT_REGIONS=2`, 3-of-5
      default pinned so per-region cap N-K is well-defined), HCR-3
      (shared Kafka/Redis reaching signing path —
      `verify_signing_path_isolation` over `SIGNING_PATH_MODULES`
      with `SHARED_STATE_FORBIDDEN_IMPORTS` covering aiokafka/redis/
      confluent_kafka; the gate ALSO re-runs the live verifier against
      the on-disk tree), HCR-4 (operator-key monoculture —
      `verify_operator_diversity` with `MIN_DISTINCT_OPERATORS=2` and
      `MIN_DISTINCT_JURISDICTIONS=2`, refusing any manifest where one
      org owns >= threshold pubkeys). A regression that removes any of
      these mitigations lights the gate red BEFORE the change reaches
      mainnet.
- [ ] **Protocol Death Spiral audit gate clean** —
      `python3 audit/death_spiral_check.py --json audit/reports/death_spiral.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the catastrophic Scenario A
      "Protocol Death Spiral" attack chain in
      `launch/design/death_spiral_resolution.md` — attacker
      compromises two oracle nodes, runs VULN-03 slow-drift inflation
      for ~30 epochs until the agent universe lives in the 900+
      band, DeFi protocols issue maximum loans against the saturated
      scores, attacker triggers mass agent failures, every loan
      defaults at once. Closed by three orthogonal mitigations: PDS-1
      cluster score-band saturation gate
      (`verify_saturation` + `HIGH_BAND_FLOOR=700`,
      `MAX_HIGH_BAND_MIGRATION_FRACTION=0.40`,
      `ABSOLUTE_HIGH_BAND_CEILING=0.80`,
      `VARIANCE_COLLAPSE_THRESHOLD=0.50` — refuses cert batch when
      the agent distribution saturates HIGH band in one epoch),
      PDS-2 SDK-consumer score-velocity contract
      (`verify_score_velocity` + `MAX_SCORE_DELTA_PER_EPOCH=200` in
      lockstep with `scoring/_gaming.MAX_SCORE_DELTA=200`,
      `MAX_SCORE_VELOCITY_PER_HOUR=100`,
      `ABSURD_VELOCITY_PER_HOUR=500` — caps adjacent-epoch cert pairs
      so the DeFi consumer refuses inflated scores even if the
      cluster is captured), PDS-3 multi-epoch correlated-movement +
      mass-failure detector
      (`verify_correlated_movement` + `verify_mass_failure` +
      `CORRELATION_WINDOW=5`, `MAX_DIRECTIONAL_SHARE=0.85`,
      `MASS_FAILURE_DROP=200`, `MASS_FAILURE_AGENT_FRACTION=0.50` —
      rolling-window directional + crash tally with deterministic
      SHA-256 evidence hash that any honest cluster member can
      reproduce). The gate ALSO cross-checks
      `scoring/_gaming.MAX_SCORE_DELTA = 200` against
      `score_velocity.MAX_SCORE_DELTA_PER_EPOCH = 200` so the
      internal clamp and the SDK cap cannot drift out of lockstep
      silently. A regression that removes any of these mitigations
      lights the gate red BEFORE the change reaches mainnet.
- [ ] **Nation-State Silent Subversion audit gate clean** —
      `python3 audit/nation_state_check.py --json audit/reports/nation_state.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the catastrophic Scenario B
      "Nation-State Silent Subversion" attack chain in
      `launch/design/nation_state_subversion_resolution.md` —
      nation-state compromises a cloud provider hosting oracle
      nodes, a hypervisor kernel module exfiltrates Ed25519 private
      keys, attacker accumulates K-of-N cluster keys, issues GREEN
      certs for fresh state-controlled wallets, agents accumulate
      large DeFi positions over weeks, coordinated market action.
      Closed by three orthogonal mitigations: NSS-1 cluster cloud-
      provider diversity gate
      (`verify_cloud_diversity` + `MIN_DISTINCT_CLOUD_PROVIDERS=2`,
      `DEFAULT_CLUSTER_SIZE=5`, `DEFAULT_CLUSTER_THRESHOLD=3` —
      max nodes per cloud = N−K = 2, `KNOWN_CLOUD_PROVIDERS`
      includes aws/gcp/azure/hetzner/self-hosted/etc. — refuses to
      boot a cluster whose nodes concentrate on one cloud regardless
      of region), NSS-2 mainnet HSM-only signing enforcement
      (`classify_signer` + `verify_production_signer` +
      `enforce_production_signer`, three pinned bucket constants
      `SIGNER_BUCKET_IN_PROCESS="in-process"`,
      `SIGNER_BUCKET_HSM="hsm"`, `SIGNER_BUCKET_UNKNOWN="unknown"`,
      `HSMSigner`-suffix rule, opt-in env var
      `HELIXOR_INPROCESS_SIGNER_OK` — refuses to start a mainnet
      oracle node with an in-process Ed25519 signer so the
      hypervisor-kernel exfil substrate is not present), NSS-3
      cluster-side agent-registration-age floor
      (`verify_agent_age_for_tier` + `enforce_agent_age_for_tier` +
      `MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14 * 24 * 3600` (14 days),
      `MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168` (168 epochs at 2h
      cadence), `GATED_TIER_GREEN = "GREEN"`,
      `REASON_TIME_TRAVEL = "AGENT_REGISTERED_IN_FUTURE"` — refuses
      to stamp a GREEN cert on a wallet whose `AgentRegistration` PDA
      is younger than the dual seconds + epochs floors, so a state-
      controlled fresh wallet either ages publicly visible or never
      receives a collateral-grade endorsement). The gate ALSO
      cross-checks the VULN-25 signer surface
      (`InProcessSigner` + `HSMSigner` in
      `oracle/cluster/signer.py`) and lights a SOFT finding if the
      consumer-side VULN-23 `MIN_HISTORY_REQUIRED` marker in
      `helixor-sdk/src/lib/cert_reader.ts` disappears. A regression
      that removes any of these mitigations lights the gate red
      BEFORE the change reaches mainnet.
- [ ] **Stale Oracle Lock audit gate clean** —
      `python3 audit/stale_oracle_check.py --json audit/reports/stale_oracle.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the catastrophic Scenario C
      "Stale Oracle Lock" attack chain in
      `launch/design/stale_oracle_resolution.md` — all 5 oracle nodes
      disrupted simultaneously (coordinated DDoS or infra failure),
      no new certs issued, DeFi protocols continue to use last-issued
      certs, agents whose behaviour degrades never get updated certs,
      mass defaults with no warning. Closed by three orthogonal
      mitigations: SOL-1 cluster-liveness signal
      (`verify_cluster_liveness` + `enforce_cluster_alive` +
      `WARN_QUIET_SECONDS = 2 * 3600` (2h),
      `SILENT_QUIET_SECONDS = 4 * 3600` (4h),
      `MIN_RECENT_NODES_FOR_ALIVE = 3`,
      `LIVENESS_FUTURE_TOLERANCE_SECONDS = 60`, band labels
      `LIVENESS_ALIVE = "ALIVE"`, `LIVENESS_DEGRADED = "DEGRADED"`,
      `LIVENESS_SILENT = "SILENT"` — refuses consumer-side activity
      hours BEFORE TA-6's 48h ceiling on a cluster that has gone
      quiet or lost K-of-N capability), SOL-2 per-agent age-based
      tier degradation (`escalate_for_age` +
      `GREEN_TO_YELLOW_AFTER_SECONDS = 6 * 3600` (6h),
      `YELLOW_TO_RED_AFTER_SECONDS = 12 * 3600` (12h),
      `REFUSE_AFTER_SECONDS = 24 * 3600` (24h — half-life of TA-6),
      tier labels `TIER_GREEN = "GREEN"`, `TIER_YELLOW = "YELLOW"`,
      `TIER_RED = "RED"`, `TIER_REFUSE = "REFUSE"` — transitive
      one-directional downgrade so a stale cert progressively loses
      weight rather than staying GREEN until the cliff edge), SOL-3
      per-operation freshness floors
      (`verify_operation_freshness` + `enforce_operation_freshness` +
      `LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600` (4h),
      `LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 3600` (8h),
      `LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 3600` (12h),
      `STATUS_READ_MAX_AGE_SECONDS = 48 * 3600` (48h — mirrors TA-6's
      `MAX_AGE_SECONDS`), `OPERATION_FUTURE_TOLERANCE_SECONDS = 60`,
      `Operation` enum with `LOAN_ISSUE` / `LOAN_INCREASE` /
      `LIQUIDATION_CHECK` / `STATUS_READ` wire labels — risk-asymmetric
      consumer circuit breaker, so high-stakes operations refuse
      against aged certs even within TA-6's window). The gate ALSO
      cross-checks TA-6's on-chain `MAX_AGE_SECONDS = 48 * 60 * 60`
      in `programs/certificate-issuer/src/state/health_certificate.rs`
      so SOL-3's `STATUS_READ` floor and TA-6's ceiling cannot drift
      out of lockstep silently. A regression that removes any of
      these mitigations lights the gate red BEFORE the change reaches
      mainnet.
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
- [ ] **AW-03 baseline data-availability bound on the first live cert.**
      Decode the first mainnet cert via the SDK and verify
      `cert.baselineCommitNonce > 0n` AND that
      `baselineDataPda(healthOracle, agent, cert.baselineCommitNonce)`
      resolves to an on-chain account whose
      `sha256(payload) === cert.baselineHash`. One integration partner
      MUST run
      `verifyBaselineProvenance(connection, healthOracleProgram, cert)`
      against the first cert and report `ok: true`; a `HashMismatch`
      rejection here blocks promotion. A zero `baseline_commit_nonce` on a v6 cert
      would mean the cert was issued before the AW-03 plumbing landed
      — that must NEVER happen on mainnet. The cluster's
      `cert_payload_digest` folds the 8-byte BE nonce into the signed
      digest, so a zero nonce on a non-legacy cert is by construction
      either (a) a pre-AW-03 deploy (investigate before issuing more
      certs) or (b) a regression that the audit sweep above should
      have caught (re-run the sweep). Runbook:
      `launch/runbooks/baseline_provenance.md`.
- [ ] **AW-04 scoring data-availability bound on the first live cert.**
      Decode the first mainnet cert via the SDK and verify
      `cert.layoutVersion === 7` AND `cert.scoringCodeHash !==
      zeroes` AND that
      `scoreComponentsPda(certificateIssuer, agent, cert.epoch)`
      resolves to an on-chain account whose
      `sha256(payload) === cert.scoreComponentsHash`. One
      integration partner MUST run
      `verifyScoreComputation(connection, certificateIssuer, cert)`
      against the first cert and report `ok: true`; a
      `HashMismatch` or `ScoreReplayMismatch` rejection here blocks
      promotion. The SAME partner MUST also run
      `verifyScoringCodeHash(cert, EXPECTED_SCORING_CODE_HASH)` —
      where `EXPECTED_SCORING_CODE_HASH` is the audited bundle
      hash from `audit/reports/aw04_scoring_provenance.json` — and
      report `result: Ok`. A `PreV7Cert` or zero
      `scoring_code_hash` on the first mainnet cert would mean the
      cert was issued before the AW-04 plumbing landed — that
      must NEVER happen on mainnet. The cluster's
      `cert_payload_digest` folds the 32-byte BE
      `scoring_code_hash` AND the 32-byte BE
      `score_components_hash` into the signed digest, so a zero
      either field on a v7 cert is by construction either (a) a
      pre-AW-04 deploy (investigate before issuing more certs) or
      (b) a regression that the audit sweep above should have
      caught (re-run the sweep). Runbook:
      `launch/runbooks/score_provenance.md`.
- [ ] **SPOF mitigations active on first mainnet day.** Verify all
      six platform-substrate mitigations are running BEFORE the
      first agent registers:
        1. **Kafka HA** — `docker compose ps` shows three healthy
           `kafka-1/-2/-3` brokers; topic `agent.transactions` was
           created by `kafka-init` with `--replication-factor 3
           --config min.insync.replicas=2`.
        2. **TimescaleDB HA** — `timescale-primary` accepting writes,
           `timescale-standby` in hot-standby with
           `pg_is_in_recovery() = t` and replication lag < 5s,
           `wal-archive` shipping WAL into the `wal_archive` volume.
        3. **API multi-replica** — all three of `api-1/-2/-3` return
           200 on `/health`; nginx `api-lb` returns 200 on
           `/lb-health`. External traffic hits port 8080 of `api-lb`,
           not a replica directly.
        4. **Geyser consensus** — the indexer boot log shows
           `ProductionGeyserConfig(total_sources=N>=3,
           consensus_threshold>=2, is_mainnet=True)`. A
           `SinglePointGeyserError` at boot is the gate REFUSING the
           launch — fix the endpoint config, do NOT relax the floor.
        5. **slash-authority rotation ceremony** — the deployed
           `update_authorities` instruction returns
           `SingleAdminUpdateRemoved (6088)` on call; the propose/
           attest/enact instructions are present in the IDL.
        6. **Squads upgrade authority** — `solana program show <id>`
           reports the multisig PDA as the upgrade authority for
           each deployed program. A single-key upgrade authority on
           mainnet is a P0 — invoke `launch/runbooks/spof_failover.md`
           to revoke and re-point at the multisig before launching.
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
- [ ] **Daily review of AW-03 baseline-provenance events.** Every
      `BaselineCommitted` event in steady state MUST carry a
      strictly-monotonic `commit_nonce` for its agent (the on-chain
      handler rejects regressions with `BaselineNonceRegression`).
      A `HashMismatch` finding from any partner running
      `verifyBaselineProvenance(connection, healthOracleProgram, cert)`
      is a P0 — the cert's
      on-chain `baseline_hash` does not match
      `sha256(BaselineDataAccount.payload)`, which by construction
      should be impossible (the program enforces equality at write
      time). The two ways it CAN happen in practice: (a) the partner
      is fetching the wrong PDA — confirm
      `baselineDataPda(healthOracle, agent, cert.baselineCommitNonce)`
      derivation; (b) a chain reorg landed a stale baseline-data
      account version — re-fetch at finalized commitment. If neither
      applies, follow `launch/runbooks/baseline_provenance.md`.
- [ ] **Daily review of AW-04 scoring-provenance events.** Every
      `CertificateIssued` event in steady state MUST be paired with
      a `ScoreComponentsAccount` PDA at
      `scoreComponentsPda(certificateIssuer, agent, epoch)` whose
      `components_hash` field equals `cert.scoreComponentsHash`
      (the chain enforces this at init time via `sha256(payload)`
      computed on chain). The daily job re-runs
      `verifyScoreComputation(connection, certificateIssuer, cert)`
      across the prior day's certs and reports any non-`ok`
      result. A `HashMismatch` or `ScoreReplayMismatch` finding is
      a P0 — the former is by-construction impossible (the chain
      computes the hash), and the latter means the cluster signed
      a cert whose headline score disagrees with the sum of its
      own dim contribs (kernel swap or fabricated components).
      The job also pulls `cert.scoringCodeHash` for every cert and
      cross-references against the deployed kernel's published
      bundle hash; any drift NOT preceded by a release announcement
      is a P0 deploy-discipline regression. The two ways a
      `HashMismatch` CAN happen in practice: (a) the partner is
      fetching the wrong PDA — confirm
      `scoreComponentsPda(certIssuer, agent, cert.epoch)`
      derivation; (b) a chain reorg landed a stale components
      account version — re-fetch at finalized commitment. If
      neither applies, follow `launch/runbooks/score_provenance.md`.
- [ ] **Weekly external-RPC ledger re-verification.** A scheduled job
      decodes the previous day's certs and runs
      `verifyAgainstSolanaLedger` against an RPC NOT in the cluster's
      RPC fleet. For each cert still inside the SlotHashes window,
      the job must report `ok: true`. Any `AnchorHashMismatch`
      finding from this job is a P0 (the cluster's RPCs and the
      external RPC disagree — at least one is lying). Output:
      `audit/reports/slot_anchor_weekly_<YYYY-MM-DD>.json`.
- [ ] **Daily SPOF substrate health review.** Run, against
      Prometheus, the queries that watch each SPOF mitigation
      under load:
        1. **Kafka** — `kafka_under_replicated_partitions{} == 0`
           AND `kafka_isr_shrinks_total[1d] == 0`. A non-zero ISR
           shrink rate means a broker is repeatedly falling out of
           sync; investigate before the next broker incident
           pushes the cluster below min.insync.
        2. **TimescaleDB** — replication lag from
           `pg_last_xact_replay_timestamp()` on the standby is
           < 60s sustained, and `pg_stat_archiver.failed_count`
           is 0. WAL-archive failures silently break PITR.
        3. **API** — each of `api-1/-2/-3` returns 200 on
           `/health` over the last 24h with > 99.5% success;
           `nginx_upstream_responses_seconds_total{upstream="api-N",
           status="5xx"}` is < 0.1% of total. An asymmetric error
           rate on one replica means the LB has not been ejecting
           it cleanly.
        4. **Geyser consensus** —
           `geyser_consensus_conflicts_total[1d] == 0`. ANY
           conflict in steady state is a P0 (one endpoint emitted
           different canonical bytes for the same signature than
           the other(s) — at least one is lying). The runbook is
           `launch/runbooks/spof_failover.md`
           "Geyser consensus alerts".
        5. **slash-authority** — no `AuthorityRotationProposed`
           event without a matching `AuthorityRotationEnacted`
           OR `AuthorityRotationCancelled` within 14 days
           (a proposal that never resolved is operator drift,
           not a security finding, but it indicates the rotation
           runbook is not being exercised).
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
