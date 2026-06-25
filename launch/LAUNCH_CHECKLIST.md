# Phylanx V2 — Launch Checklist

The pre-mainnet gate. Every box must be ticked, with the linked artefact,
**before** an `PHYLANX_MAINNET_OK=1` flag is added to any production env
file.

## 1 — Audit gates (Day 29-31)

- [ ] `audit/run_all.sh` passes locally — 7 PASSED, externals skipped
- [ ] `audit/hardening_check.py` reports **0 HARD findings**
      → `audit/reports/hardening.json`
- [ ] **VULN-20 SQLi sweep clean** —
      `python3 audit/sql_injection_check.py --json audit/reports/sql_injection.json`
      reports **0 HARD findings**. Every `.execute(...)` in
      `phylanx-oracle/db/`, `phylanx-oracle/baseline/`, `phylanx-api/api/`,
      and `phylanx-indexer/` uses parameterised binding (`%s` + params
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
           `phylanx-{oracle,api,indexer}/requirements.txt` with full
           SHA256 hash closures via `pip-compile --generate-hashes`.
           Commit BOTH `.in` and `.txt` files.
        2. Verify `phylanx-programs/Cargo.lock` is committed (it
           already is — Rust transitives are pinned).
        3. Confirm `oracle/cluster/signer.py` exports the `Signer`
           Protocol with `InProcessSigner` (default) and `HSMSigner`
           (production swap-in). `HSMSigner.sign` MUST raise
           `NotImplementedError` on the base class so a misconfigured
           production deploy that forgot the HSM subclass fails
           LOUDLY rather than silently falling back.
        4. Confirm `launch/deploy/systemd/oracle-node@.service`
           still carries the supply-chain hardening directives:
           `ReadOnlyPaths=/opt/phylanx`, `SystemCallFilter=@system-service`,
           `CapabilityBoundingSet=` (empty), `MemoryDenyWriteExecute=true`,
           `ProtectSystem=strict`.
      Production install command (in the deploy script):
      `/opt/phylanx/venv/bin/pip install --require-hashes --no-deps -r phylanx-oracle/requirements.txt`.
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
        4. `phylanx-api/api/flag_obfuscation.py` exposes
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
      `@phylanx/sdk` reproduce them byte-for-byte from observable
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
      provider)` from `@phylanx/sdk` and confirmed it returns `ok:
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
      `verifyBaselineProvenance` in `@phylanx/sdk` reproduces the
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
      `@phylanx/sdk` re-derives BOTH the hash AND the headline
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
      `PHYLANX_INPROCESS_SIGNER_OK` — refuses to start a mainnet
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
      `phylanx-sdk/src/lib/cert_reader.ts` disappears. A regression
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
- [ ] **Forge High-Score Cert audit gate clean** —
      `python3 audit/forge_high_score_check.py --json audit/reports/forge_high_score.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the red-team Path 1 "Forge High-Score
      Cert" attack chain in
      `launch/design/forge_high_score_resolution.md` — three
      sub-leaves: (1a) compromise 3 oracle keys [HIGH EFFORT], (1b)
      exploit VULN-01 signature-verification bypass [MEDIUM EFFORT],
      (1c) exploit VULN-13 wholesale key-replacement [HIGH EFFORT].
      Closed by three orthogonal mitigations: FHS-1 cluster-key
      rotation cadence floor (`verify_key_rotation_cadence` +
      `enforce_key_rotation_cadence` +
      `MAX_KEY_AGE_SECONDS = 90 * 24 * 3600` (90d hard floor),
      `WARN_KEY_AGE_SECONDS = 60 * 24 * 3600` (60d soft floor — 30d
      operator warning window),
      `CADENCE_FUTURE_TOLERANCE_SECONDS = 60`, status labels
      `CADENCE_OK = "OK"`, `CADENCE_WARN = "WARN"`,
      `CADENCE_OVERDUE = "OVERDUE"` — refuses cluster boot against
      keys past the 90-day NIST SP 800-57 cryptoperiod ceiling so a
      compromised key cannot dwell indefinitely), FHS-2 per-signer
      provenance attestation gate (`verify_signer_provenance` +
      `enforce_signer_provenance` + `MAX_SIGNERS_PER_HOST = 1`,
      `MAX_SIGNERS_PER_REGION = 2` (mirror of NSS-1's per-cloud
      `N - K = 2`), `MIN_DISTINCT_HOSTS = 3`, status labels
      `PROVENANCE_OK = "OK"`, `PROVENANCE_REFUSED = "REFUSED"` —
      refuses a threshold-signature set whose K signatures share a
      physical host_id, exceed the per-region cap, or are missing
      attestations, catching the "one physical machine running two
      cluster HSMs" residual that on-chain pubkey deduplication
      cannot see), FHS-3 cluster-key rotation overlap guard
      (`verify_rotation_overlap` + `enforce_rotation_overlap` +
      `MAX_KEYS_REPLACED_PER_ROTATION = 1`, derived
      `required_overlap = max(threshold - 1, 0)`, status labels
      `OVERLAP_OK = "OK"`, `OVERLAP_REFUSED = "REFUSED"`, reason
      codes `WHOLESALE_REPLACEMENT`, `INSUFFICIENT_OVERLAP` —
      refuses any rotation proposal that would replace more than one
      cluster key per ceremony, forcing a full cluster rotation to
      take a minimum of 5 × 48h = 10 days of public on-chain
      activity every step of which honest attesters can refuse).
      The gate ALSO cross-checks the on-chain VULN-01 anchor
      (`pub fn verify_threshold_signatures` + `expected_digest` +
      `record.message` in
      `programs/certificate-issuer/src/signing.rs`) and the on-chain
      VULN-13 anchor (`MIN_TIMELOCK_SECONDS = 48 * 60 * 60` in
      `programs/health-oracle/src/state/pending_oracle_rotation.rs`)
      so the off-chain FHS-2 / FHS-3 mitigations cannot drift out of
      lockstep with the on-chain defences they pair with. A
      regression that removes any of these mitigations lights the
      gate red BEFORE the change reaches mainnet.
- [ ] **Inflate Legitimate Score audit gate clean** —
      `python3 audit/inflate_score_check.py --json audit/reports/inflate_score.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the red-team Path 2 "Inflate Legitimate
      Score" attack chain in
      `launch/design/inflate_score_resolution.md` — three sub-leaves:
      (2a) exploit VULN-06 baseline overwrite [LOW EFFORT], (2b)
      exploit VULN-07 feature poisoning [MEDIUM EFFORT], (2c) exploit
      VULN-03 Byzantine slow drift [HIGH EFFORT, LONG TERM]. Closed
      by three orthogonal mitigations: ILS-1 baseline-rotation
      cadence + co-attestation guard (`verify_baseline_rotation` +
      `enforce_baseline_rotation` +
      `MIN_EPOCHS_BETWEEN_BASELINE_ROTATIONS = 30` (30-epoch /
      ~2.5-day cadence floor between per-agent baseline rotations),
      `MIN_BASELINE_COSIGNERS = 2`,
      `BASELINE_FUTURE_TOLERANCE_EPOCHS = 1`, status labels
      `BASELINE_OK = "OK"`, `BASELINE_REFUSED = "REFUSED"` — refuses
      any baseline rotation faster than 30 epochs OR solo-signed by
      a single cluster key OR missing the agent's own cosignature,
      so a compromised cluster key cannot grind an agent's baseline
      upward), ILS-2 producer-corroboration + record-freshness
      floor (`verify_feature_corroboration` +
      `enforce_feature_corroboration` +
      `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2`,
      `MAX_PRODUCER_DOMINANCE_RATIO = 0.7` (cap against busiest
      producer load distribution), `MAX_RECORD_AGE_SECONDS = 24 *
      3600` (24h freshness window), `RECORD_FUTURE_TOLERANCE_SECONDS
      = 60`, status labels `CORROBORATION_OK = "OK"`,
      `CORROBORATION_REFUSED = "REFUSED"` — refuses an aggregation
      whose producer set is smaller than 2, dominated above 70% by
      one producer, or contains records older than 24h, catching the
      "single compromised producer key stamps 100% of records"
      residual that on-chain signature checks cannot see in isolation
      AND the backfill attack with a since-decommissioned producer
      key), ILS-3 cumulative score-drift ceiling
      (`verify_score_drift_ceiling` + `enforce_score_drift_ceiling` +
      `MAX_DRIFT_FROM_BASELINE_RATIO = 0.30` (30% cumulative
      ceiling), `MAX_DRIFT_PER_EPOCH_RATIO = 0.05` (5% per-epoch
      sub-pin — a quarter of the cluster's `VELOCITY_THRESHOLD =
      0.20`), `MAX_MONOTONIC_DRIFT_EPOCHS = 10` (10-epoch monotonic-
      run cap), `DRIFT_FUTURE_TOLERANCE_EPOCHS = 1`, status labels
      `DRIFT_OK = "OK"`, `DRIFT_REFUSED = "REFUSED"`, reason codes
      `DRIFT_OVER_CUMULATIVE_CEILING`,
      `DRIFT_OVER_PER_EPOCH_CEILING`, `DRIFT_MONOTONIC_TOO_LONG` —
      refuses sub-velocity drips that compound into 30%+ inflation
      across many epochs; the three sub-pins are calibrated jointly
      so per-epoch × monotonic (1.05^10 - 1 ≈ 0.629) ≫ cumulative
      (0.30), forcing the cumulative ceiling to fire FIRST if an
      attacker threads the per-epoch limit). The gate ALSO
      cross-checks the on-chain VULN-06 anchor
      (`is_authorised_baseline_writer` + `BaselineRotationTooSoon` +
      `BaselineEpochNotMonotonic` in
      `programs/certificate-issuer/src/instructions/record_baseline.rs`),
      the indexer-side VULN-07 anchor (`TrustedProducerSet` +
      `verify_record_headers` in
      `phylanx-indexer/eventbus/consumer.py`), and the cluster-side
      VULN-03 anchor (`VELOCITY_THRESHOLD = 0.20` +
      `DRIFT_REASON_VELOCITY` in
      `phylanx-oracle/oracle/cluster/drift_detector.py`) so the
      off-chain ILS-1 / ILS-2 / ILS-3 mitigations cannot drift out
      of lockstep with the upstream defences they pair with. A
      regression that removes any of these mitigations lights the
      gate red BEFORE the change reaches mainnet.
- [ ] **Freeze-Cert-at-High-Score audit gate clean** —
      `python3 audit/freeze_cert_check.py --json audit/reports/freeze_cert.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the red-team Path 3 "Freeze Cert at High
      Score" attack chain in
      `launch/design/freeze_cert_resolution.md` — three sub-leaves:
      (3a) exploit VULN-05 to gate the cluster's commit-reveal round
      so the next cert never closes [LOW EFFORT], (3b) exploit
      VULN-02 to halt epoch advance so the cert keeps reading fresh
      while the underlying state drifts [MEDIUM EFFORT], (3c) attack
      cert re-issuance cadence so the consumer hits the TA-6 48h
      ceiling without a refresh [HIGH EFFORT, LONG TERM]. Closed by
      three orthogonal mitigations: FRP-1 cluster participation
      floor (`verify_cluster_participation_floor` +
      `enforce_cluster_participation_floor` +
      `MIN_HEALTHY_PARTICIPATION_RATIO = 0.8` (80% healthy floor),
      `MAX_BARELY_QUORATE_ROUNDS = 3` (trailing-run cap for rounds
      whose participation hugs `quorum + BARELY_QUORATE_MARGIN`),
      `BARELY_QUORATE_MARGIN = 1`,
      `PARTICIPATION_FUTURE_TOLERANCE_EPOCHS = 1`, status labels
      `PARTICIPATION_OK = "OK"`, `PARTICIPATION_REFUSED = "REFUSED"`,
      reason codes `PARTICIPATION_BARELY_QUORATE_TOO_LONG`,
      `PARTICIPATION_BELOW_HEALTHY_FLOOR` — refuses a cluster whose
      4-plus trailing rounds all skate the quorum line, catching the
      VULN-05 "withhold reveals up to but not over the threshold"
      residual that a single-round quorum check cannot see), FRP-2
      epoch-advance liveness floor (`verify_epoch_advance_liveness`
      + `enforce_epoch_advance_liveness` +
      `MAX_EPOCH_ADVANCE_STALL_SECONDS = 36 * 3600` (36h hard
      floor — 1.5× `EXPECTED_EPOCH_DURATION_SECONDS = 24 * 3600` so
      the floor fires BEFORE AW-02's Tier-2 fallback would kick in
      at 2× duration),
      `EPOCH_ADVANCE_FUTURE_TOLERANCE_SECONDS = 60`, status labels
      `EPOCH_ADVANCE_OK = "OK"`, `EPOCH_ADVANCE_REFUSED = "REFUSED"`
      — refuses a cluster whose `EpochState.last_advanced_at` has
      not budged in 36h+1s, catching the VULN-02 "halt epoch
      advance and let TA-6 do the work" residual that the on-chain
      advance-attestation count cannot see by itself), FRP-3 cert-
      reissue cadence floor (`verify_cert_reissue_cadence` +
      `enforce_cert_reissue_cadence` +
      `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600` (4h reissue
      floor),
      `CERT_REISSUE_FUTURE_TOLERANCE_SECONDS = 60`,
      `TA6_ONCHAIN_MAX_AGE_SECONDS = 48 * 3600` (the on-chain
      ceiling we calibrate against), report carries
      `safety_margin_factor = TA6_ONCHAIN_MAX_AGE_SECONDS //
      MAX_CERT_REISSUE_INTERVAL_SECONDS = 12` (12× safety margin so
      the cluster-side floor fires ELEVEN reissue cycles before
      TA-6's 48h ceiling), status labels `REISSUE_OK = "OK"`,
      `REISSUE_REFUSED = "REFUSED"` — refuses a per-agent reissue
      lag above 4h, catching the "cluster is up, certs not being
      stamped" residual that targets freshness-blind consumers who
      have not adopted SOL-3's per-operation freshness floors). The
      gate ALSO cross-checks the on-chain VULN-05 anchor
      (`submit_reveal` + `non_revealers` + `reveal_deadline` +
      `min_reveals` in
      `programs/health-oracle/src/instructions/commit_reveal_round.py`
      — Python prototype lives at the same name), the on-chain
      VULN-02 anchor (`verify_cluster_threshold` +
      `consensus_threshold` + `InsufficientAdvanceAttestations` in
      `programs/health-oracle/src/instructions/advance_epoch.rs` +
      `DEFAULT_DURATION_SECONDS: i64 = 86_400` in
      `programs/health-oracle/src/state/epoch_state.rs`), and the
      on-chain TA-6 anchor (`MAX_AGE_SECONDS: i64 = 48 * 60 * 60`
      + `is_fresh_default` in
      `programs/certificate-issuer/src/state/health_certificate.rs`)
      so the off-chain FRP-1 / FRP-2 / FRP-3 mitigations cannot
      drift out of lockstep with the on-chain substrate they pair
      with. The pytest suite ALSO pins the `12×` safety-margin
      invariant (`TA6_ONCHAIN_MAX_AGE_SECONDS //
      MAX_CERT_REISSUE_INTERVAL_SECONDS == 12`) and the `1.5×`
      duration invariant (`MAX_EPOCH_ADVANCE_STALL_SECONDS * 2 ==
      EXPECTED_EPOCH_DURATION_SECONDS * 3`) as explicit tests so
      any silent drift between the calibration constants lights red
      BEFORE the change reaches mainnet.
- [ ] **DeFi-Bypass audit gate clean** —
      `python3 audit/consumer_integration_check.py --json audit/reports/consumer_integration.json`
      reports **0 HARD findings**. The gate is the mechanical
      regression alarm for the red-team Path 4 "DeFi Bypass" attack
      chain in `launch/design/defi_bypass_resolution.md` — three
      sub-leaves all of which live in the CONSUMER's code, not
      Phylanx's: (4a) DeFi protocol uses cert without freshness
      check, (4b) DeFi protocol uses cert without score threshold
      validation, (4c) DeFi protocol's cert-reading code has bugs.
      Closed by a four-substrate "Verified Integrator" tier whose
      four deliverables (DBP-1 linter, DBP-2 on-chain
      `VerifiedConsumer` PDA, DBP-3 safe-default `@phylanx/sdk`
      export partition, DBP-4 per-partner telemetry + leaderboard
      + cert-degrading webhooks) have all shipped. The Insured
      tier's revenue surface is the bad-faith forfeit clause
      (DBP-2 admin revoke) + the SLA-backed freshness webhook
      (DBP-4d). DBP-1 specifically: a self-serve consumer integration
      linter (`audit/consumer_integration_check.py`) that verifies
      every `launch/integrations/*.json` partner manifest claims
      only allowed `operations_bound` (subset of
      `{LOAN_ISSUE, LOAN_INCREASE, LIQUIDATION_CHECK, STATUS_READ}`),
      attests `safe_reader_imported = true` /
      `input_provenance_verified = true` /
      `slot_anchor_verified = true`, names cert-reader source paths
      that exist on disk and contain the `SafeCertReader` +
      `verifyInputProvenance` + `verifyAgainstSolanaLedger` markers
      and the per-operation constant/enum-label for each entry in
      `operations_bound`, and carries an `integration_hash` that
      matches the canonical SHA256 recompute of
      `manifest minus {integration_hash, signature_ed25519}`. The
      reference manifest `launch/integrations/example_safe_partner.
      json` points at the reference safe-reader implementation at
      `launch/integrations/example_safe_partner/reader.ts` — both
      are checked into the repo as the canonical green target.
      The gate ALSO cross-checks the VULN-23 anchor
      (`export class SafeCertReader` + `CERT_MAX_AGE_SECONDS = 48 *
      60 * 60` + `MAX_SCORE_VELOCITY = 200` +
      `VELOCITY_WINDOW_EPOCHS = 3` + `MIN_HISTORY_REQUIRED = 2` in
      `phylanx-sdk/src/safe_reader.ts` and the re-export from
      `phylanx-sdk/src/index.ts`), the SOL-3 anchor
      (`class Operation(str, Enum)` +
      `LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600` +
      `LOAN_INCREASE_MAX_AGE_SECONDS = 8 * 3600` +
      `LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12 * 3600` +
      `STATUS_READ_MAX_AGE_SECONDS = 48 * 3600` +
      `verify_operation_freshness` in
      `phylanx-oracle/oracle/operation_freshness.py`), and the
      AW-01-EXT anchor (`verifyAgainstSolanaLedger` +
      `verifyInputProvenance` in
      `phylanx-sdk/src/input_provenance.ts` and the re-export from
      `phylanx-sdk/src/index.ts`), and the DBP-3 safe-default
      partition (`phylanx-sdk/src/unsafe.ts` re-exports
      `PhylanxClient` + `PhylanxChainClient`; the default
      `phylanx-sdk/src/index.ts` MUST NOT name either symbol; any
      partner cert-reader source that imports `@phylanx/sdk/
      unsafe` MUST also reference `SafeCertReader` — the
      `[DBP-1e][DBP-3 safe-default]` family fires HARD on any of
      the three regressions) — so any rename or removal of a
      surface partner manifests bind against lights red BEFORE the
      change reaches mainnet, giving every active integrator a
      coordinated migration window rather than a silent void. The
      pytest self-test at `audit/test_consumer_integration_check.
      py` ALSO pins the canonical-hash invariant
      (`example_safe_partner.json::integration_hash ==
      sha256(canonical_json(manifest_minus_signature))`) and the
      five-family check count
      (`summary.checks == 5` — DBP-1a..DBP-1e) so a schema drift
      between the manifest and its pinned hash, or a silent removal
      of an entire DBP-1 family, lights red on commit. A regression
      that removes any of these mitigations lights the gate red
      BEFORE the change reaches mainnet.
- [ ] **DBP-2 Verified-Integrator badge live on chain** — the
      `certificate-issuer` program exposes
      `register_verified_consumer(integration_hash)` and
      `revoke_verified_consumer(reason)` (anchors:
      `programs/certificate-issuer/src/instructions/
      register_verified_consumer.rs` +
      `programs/certificate-issuer/src/instructions/
      revoke_verified_consumer.rs` +
      `programs/certificate-issuer/src/state/
      verified_consumer.rs`). The PDA seed is
      `[b"verified_consumer", partner_wallet]`; partner_wallet IS
      the tx Signer so the binding is cryptographic without an
      Ed25519 precompile dance. The 148-byte layout (8
      discriminator + 140 data: partner_wallet, integration_hash,
      registered_at_{slot,unix}, state, revoked_at_unix, revoked_by,
      revoke_reason, layout_version, 16-byte _reserved) is pinned
      by the SDK decoder at `phylanx-sdk/src/verified_consumer.ts`
      and the 9-test SDK suite at
      `phylanx-sdk/test/verified_consumer.test.ts`. The revoke
      flow is dual-path: `PartnerSelfRevoke` requires the partner
      to sign; `AdminBadFaith` / `AdminTerminated` require
      `issuer_config.authority` to sign. The account is NEVER
      closed on revoke so the audit trail persists; downstream
      lending contracts MUST gate on
      `isVerifiedConsumerActive(decoded)` (the
      `is_active()` discriminator check on the `state` byte) and
      treat "had a badge, lost it" as a refusal — presence alone
      is insufficient. The
      `REGISTRATION_DOMAIN_TAG = "phylanx-dbp2-verified-consumer"`
      digest helper is exported on both Rust and TS sides so any
      future delegated-submission v2 path AND off-chain auditors
      arrive at the same SHA256.
- [ ] **DBP-4 Verified-Integrator revenue surface live** —
      `cd phylanx-api && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest
      tests/test_dbp4_partner_telemetry.py tests/test_dbp4_webhooks.py`
      reports **24 + 21 = 45 green tests**. The three substrates:

      (4a) **Per-partner safe-reader share telemetry** — `ApiKey`
      carries a `partner_wallet` (optional 5th colon field of
      `PHYLANX_API_KEYS`) and the
      `phylanx_api_safe_reader_share_total{partner_wallet,
      surface=safe|raw}` Prometheus counter increments on every
      successful score-read by a partner-bound key. `safe` =
      `/agents/{wallet}/safe_score`; `raw` =
      `/agents/{wallet}/health` + `/health/{epoch}` + `/history`.
      Calls from unauthenticated traffic or basic-tier keys never
      increment the counter so cardinality stays bounded to the
      Verified-Integrator population.

      (4b) **Public `/integrations/leaderboard`** —
      `IntegrationLeaderboardResponse` returns the Verified-
      Integrator ranking sorted by `safe_share` desc (tiebreak on
      `total_calls`); idle partners with zero observed traffic
      appear last with `safe_share=null`. Endpoint is intentionally
      public (no API key) so any consumer can read the ranking
      BEFORE deciding to trust a partner's certs.

      (4c) **Cert-degrading webhook (Insured tier)** —
      `api/webhooks.py` provides a `WebhookRegistry`
      (`partner_wallet → (url, secret)`, loaded from
      `PHYLANX_WEBHOOKS=partner_wallet:url:secret` lines), a
      `compute_signature` HMAC-SHA256 helper, a
      `CertDegradingPayload` with byte-stable
      canonical JSON (sorted keys, no whitespace) so the partner-
      side verifier reproduces the signature exactly, and a
      `CertDegradingTracker` that dedupes (partner, agent, epoch)
      so a partner polling every 60s gets ONE warning per cert
      lifecycle. The reactive trigger fires from the `/safe_score`
      handler when `cert_age_seconds ∈ [75% × CERT_MAX_AGE_SECONDS,
      100% × CERT_MAX_AGE_SECONDS)`. A partner-less key, an
      anonymous call, a fresh cert, an expired cert, or a partner
      without a webhook all short-circuit silently — no spurious
      pages. Anchors: `degrading_threshold_seconds(48*3600) ==
      36*3600`, `SIGNATURE_HEADER = "X-Phylanx-Webhook-Signature"`,
      `EVENT_CERT_DEGRADING = "cert.degrading"`,
      `WEBHOOK_SCHEMA_VERSION = 1`.

      A regression that breaks any of these substrates lights the
      45 DBP-4 tests red BEFORE the change reaches mainnet.
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
- [ ] **Read API tests green** — `cd phylanx-api && pytest` passes
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
- [ ] **Oracle-key-compromise runbook reviewed by lead.** The 4-step
      incident response in `launch/runbooks/oracle_key_compromise_response.md`
      composes the existing primitives — Step 1 (Squads
      propose/enact rotation, 48h `MIN_TIMELOCK_SECONDS` from
      `programs/health-oracle/.../state/pending_oracle_rotation.rs`),
      Step 2 (`revoke_verified_consumer` with `AdminBadFaith`),
      Step 3 (FRP-3 `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4*3600`
      cadence floor reissues certs under the rotated cluster within
      4h with no new instruction), Step 4 (SOL-3 per-operation
      freshness floors in `launch/integrations/example_safe_partner/reader.ts`
      compose with the DBP-4 `cert.degrading` webhook at the 36h
      `0.75 * 48h` threshold to fail-closed all Verified Integrators
      automatically). On-call confirms they can recite the four
      steps and find the linked instruction handlers in <5 minutes.
- [ ] **API-DDoS runbook reviewed by lead.** The 3-step incident
      response in `launch/runbooks/api_ddos_response.md` composes the
      existing primitives — Step 1 (tighten the VULN-09 sliding-window
      limiter in `phylanx-api/api/rate_limit.py` via the
      `PHYLANX_PUBLIC_RATE_LIMIT_PER_MIN` env var; NGINX upstream pool
      at `launch/deploy/nginx/api_upstream.conf` already enforces
      `max_fails=3 fail_timeout=15s` ejection + 64KiB body cap + GET-only
      `proxy_next_upstream` failover; per-key tier overrides via
      `PHYLANX_API_KEYS`), Step 2 (Verified Integrators switch to the
      DBP-3 `SafePartnerReader` in
      `launch/integrations/example_safe_partner/reader.ts`, which reads
      `HealthCertificate` PDAs directly via Solana RPC with NO
      dependency on `phylanx-api`; the 2h epoch cadence stays well
      under the SOL-3 LOAN_ISSUE 4h freshness floor so direct readers
      remain valid throughout the flood), Step 3 (tighten Prometheus
      `scrape_interval` from 15s to 5s in
      `launch/monitoring/prometheus.yml` via hot-reload — `curl -X POST
      /-/reload` — so on-call gets 3x faster signal on cluster health
      while the API is degraded; the on-chain 2h cadence is unchanged
      because changing it requires the VULN-13 48h timelock ceremony
      and the existing cadence already meets SOL-3 floors). A
      Redis-backed distributed limiter + managed CDN + kill-switch are
      noted in the runbook as additive future work, not blockers.
      On-call confirms they can recite the three steps and find the
      linked files in <5 minutes.
- [ ] **Score-manipulation runbook reviewed by lead.** The 4-step
      incident response in `launch/runbooks/score_manipulation_response.md`
      composes the existing primitives — Step 1 (`challenge_certificate`
      + `ChallengeRecord` PDA in
      `programs/certificate-issuer/src/state/challenge_record.rs`
      flips `challenge_state` to `Upheld=1` per affected
      `(agent, epoch)` after attester quorum), Step 2
      (`issue_certificate` accepts `alert_tier` as input and signs
      it into the cluster digest; the `PHYLANX_FORCE_YELLOW_AGENTS`
      cluster-side config forces YELLOW for the affected agent set,
      and FRP-3 `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4*3600` reissues
      them under the rotated tier within 4h with no new instruction),
      Step 3 (DeFi consumers read upheld `challenge_state` on-chain
      via the DBP-3 pattern, then SOL-3 per-operation freshness
      floors and the DBP-4 `cert.degrading` webhook compose to
      fail-closed Verified Integrators automatically; a courtesy
      notice goes out via the existing partner-notify channel),
      Step 4 (forensic queries Q1–Q4 against TimescaleDB
      `agent_score_history` + `byzantine_flags` and Kafka topics
      `scores.raw` / `commits` / `reveals` / `input_commitments`
      under the documented retention floors — Kafka 30d,
      TimescaleDB indefinite, Prometheus 30d, PITR 7d — plus
      re-runs of `audit/forge_high_score_check.py` and
      `audit/inflate_score_check.py` to file the postmortem).
      On-call confirms they can recite the four steps and find
      the linked instruction handlers in <5 minutes.
- [ ] **OFAC-compliance / nation-state-delist runbook reviewed by lead.**
      The 4-step incident response in
      `launch/runbooks/ofac_compliance_response.md` composes the
      existing primitives — Step 1 (`verify_operator_diversity` + the
      new OFAC-1 `verify_attestation_signatures` in
      `phylanx-oracle/oracle/operator_manifest.py` together pin
      `MIN_DISTINCT_JURISDICTIONS = 2` AND bind every declared
      jurisdiction with an Ed25519 sig under the domain tag
      `phylanx.operator_attestation.v1`, so a captured cluster cannot
      silently re-declare jurisdiction without holding the original
      keys), Step 2 (`cert_refusal_log.operator_override(...)` with a
      required non-empty justification publishes a `CertRefusal` with
      `RefusalGate.OPERATOR_OVERRIDE` onto the dedicated
      `Topic.CERT_REFUSED = "agent.cert_events.refused"` Kafka topic
      via `serialize_cert_refused` — silent delist becomes
      mechanically impossible because the audit gate
      `audit/cert_refusal_check.py` pins the canonical topic name and
      reason codes), Step 3 (the existing 3-of-5 threshold in
      `programs/certificate-issuer/src/signing.rs` makes joint
      compulsion fail closed for everyone — SOL-3 freshness floors
      and the DBP-4 `cert.degrading` webhook compose to make the
      cost of a single-agent delist protocol-wide and visible),
      Step 4 (`propose_oracle_key_rotation` /
      `enact_oracle_key_rotation` with the 48h
      `MIN_TIMELOCK_SECONDS` from VULN-13 is the only path for an
      operator to legitimately withdraw and have the manifest
      re-signed under the OFAC-1 binding). The runbook explicitly
      REFUSES adding an on-chain `SanctionedAgentList` PDA — that
      would break the permissionless invariant, create a
      high-value authority key, and make silent delist the default.
      On-call confirms they can recite the four steps and find the
      linked instruction handlers in <5 minutes.
- [ ] **DP-1 data-protection compliance + DSAR runbook reviewed by lead.**
      The 6-step incident response in
      `launch/runbooks/data_subject_request_response.md` composes the
      existing primitives — proof-of-control verification at intake,
      then `python -m oracle.data_subject_request query <wallet>` for
      Art. 15 / s.11 / §1798.110 access requests, `... erase <wallet>
      --justification <ticket>` for Art. 17 / s.12 / §1798.105 erasure
      (purges `agent_transactions` and `agent_scores` rows via the
      VULN-20-guarded parameterised SQL through the existing
      `DBConnection` Protocol), an operator-local objection list for
      Art. 21 / s.13 (NOT on-chain — same anti-pattern OFAC-1
      declined), and a canonical-JSON DSAR audit log at
      `/var/log/phylanx/dsar/<ticket>.<op>.json`. The substrate
      `phylanx-oracle/oracle/data_protection_policy.py` declares
      DataCategory × StorageLocation × LawfulBasis × RetentionPolicy
      with the on-chain / off-chain erasability biconditional and a
      single carve-out (REFUSAL_LOG, justified by the OFAC-1
      transparency invariant). The public privacy notice
      `launch/legal/privacy_notice.md` discloses the on-chain
      carve-out BEFORE registration (the GDPR Recital 26 / DPDP s.3(c)
      technical-infeasibility path). The audit gate
      `audit/data_protection_check.py` verifies the TimescaleDB 180d
      pin in `phylanx-oracle/db/migrations/0009_timescaledb.sql` and
      the Prometheus 30d pin in
      `launch/deploy/docker-compose.indexer.yml` still match the
      substrate's declared seconds — a drift trips the gate HARD.
      On-call confirms they can recite the six steps, find the linked
      handlers in <5 minutes, AND name the four on-chain carve-out
      categories verbatim.
- [ ] **SEC-1 securities-posture compliance + regulator-inquiry runbook
      reviewed by lead.** The 7-step incident response in
      `launch/runbooks/securities_inquiry_response.md` composes the
      existing primitives — classify-and-engage-counsel at intake, then
      records production for subpoenas / CIDs (operator-local books +
      `collect_disclosed_conflicts(manifest)` + the existing DSAR /
      OFAC-1 audit logs), substrate-grounded posture statements for
      no-action / interpretive requests, operator-only response for
      examinations (the protocol does NOT attend), forward-only handling
      for cross-border inquiries (mirrors the OFAC-1 §3 anti-silent-
      delist posture), a canonical-JSON SEC-1 audit log at
      `/var/log/phylanx/securities/<ticket>.<op>.json`, and a SEC-1 gate
      re-run as the post-inquiry drift check. The substrate
      `phylanx-oracle/oracle/securities_compliance.py` declares the
      closed-enum `CompensationModel` (today only
      `FLAT_FEE_PER_CERT_FROM_TREASURY`), the `ConflictDisclosure`
      shape, and the canonical `ADVISORY_DISCLAIMER` — every field
      folded into `attestation_canonical_bytes` so the OFAC-1 Ed25519
      sig binding extends to cover them (lying about compensation or
      hiding a conflict costs the same key compromise the rest of the
      protocol already assumes the adversary cannot perform). The
      public notice `launch/legal/securities_notice.md` declares the
      not-investment-advice / not-rating / not-IA posture across US /
      EU/EEA / India / UK / SG regimes, references the substrate by
      file:line, and discloses every operator's compensation model +
      conflicts up front. The audit gate
      `audit/securities_compliance_check.py` verifies the substrate
      stays present, the enum / allowlist agree, the allowlist matches
      the governance pin (today: `{FLAT_FEE_PER_CERT_FROM_TREASURY}`),
      `OperatorAttestation` carries both SEC-1 fields,
      `attestation_canonical_bytes` still binds them, the SDK's
      `ADVISORY_DISCLAIMER` matches the Python source-of-truth byte-
      for-byte, and every `launch/integrations/*/reader.ts` references
      the marker — a drift in any of those trips the gate HARD. SEC-1
      DECLINES on-chain accredited-investor gating (would create a
      high-value authority key, break the permissionless invariant) and
      DECLINES registering Phylanx as an investment adviser (registration
      is a per-operator legal posture, not a protocol feature). On-call
      confirms they can recite the seven steps, find the linked handlers
      in <5 minutes, AND name the four sub-runbooks (subpoena, no-action,
      examination, cross-border) verbatim.
- [ ] **AML-1 KYC/AML posture + complaint-response runbook reviewed by
      lead.** The 8-step incident response in
      `launch/runbooks/aml_complaint_response.md` composes the existing
      primitives — classify-and-engage-counsel at intake, then records
      production for regulator / FIU inquiries (operator-local books +
      `collect_aml_attestations(manifest)` + the existing DSAR / OFAC-1
      audit logs), substrate-grounded posture statements for
      interpretive requests, operator-only response for FATF mutual-
      evaluation interviews (the protocol does NOT attend), forward-
      only handling for cross-border inquiries (mirrors the OFAC-1 §3 /
      SEC-1 §5 anti-silent-delist posture), an explicit adversarial /
      boilerplate-complaint path (the process-tax DoS vector the
      AML-1 risk model calls out — substrate-citation reply, no
      protocol action, complaint dies at intake), a canonical-JSON
      AML-1 audit log at `/var/log/phylanx/aml/<ticket>.<op>.json`,
      and an AML-1 gate re-run as the post-inquiry drift check. The
      substrate `phylanx-oracle/oracle/aml_compliance.py` declares
      the closed-enum `AmlProgramAttestation` (today
      `{NO_AML_PROGRAM_REQUIRED_FOR_PHYLANX_ACTIVITY,
      EXTERNAL_AML_PROGRAM_DECLARED}`), the `_KYC_FORBIDDEN_FIELDS` +
      `assert_no_kyc_fields(name)` defensive guard against KYC-shaped
      DP-1 `DataCategory` drift (`KycFieldRefusedError` at substrate
      construction time), and the canonical `AML_KYC_DISCLAIMER` —
      the AML-1 field is folded into `attestation_canonical_bytes` so
      the OFAC-1 Ed25519 sig binding extends to cover it (lying about
      AML posture costs the same key compromise the rest of the
      protocol already assumes the adversary cannot perform). The
      public notice `launch/legal/aml_kyc_notice.md` declares the
      not-a-VASP / not-a-CASP / not-an-MSB / no-Travel-Rule posture
      across US BSA/FinCEN / EU 5AMLD/6AMLD/MiCA / India PMLA / UK
      MLR 2017 / SG PSA 2019 / FATF R.15/R.16 regimes, references the
      substrate by file:line, and discloses every operator's AML
      attestation up front. The audit gate
      `audit/aml_compliance_check.py` verifies the substrate stays
      present, the enum / allowlist agree, the allowlist matches the
      governance pin (today:
      `{NO_AML_PROGRAM_REQUIRED_FOR_PHYLANX_ACTIVITY,
      EXTERNAL_AML_PROGRAM_DECLARED}`), `OperatorAttestation` carries
      the AML-1 field, `attestation_canonical_bytes` still binds it,
      the DP-1 `DataCategory` allowlist stays KYC-clean against the
      forbidden-field set, the SDK's `AML_KYC_DISCLAIMER` matches the
      Python source-of-truth byte-for-byte, and every
      `launch/integrations/*/reader.ts` references the marker — a
      drift in any of those trips the gate HARD. AML-1 DECLINES
      cluster-side KYC ingestion (would invert the cluster's
      not-covered-activity posture and create a high-value PII
      honeypot) and DECLINES registering Phylanx as a VASP / MSB /
      CASP (registration is a per-operator legal posture, not a
      protocol feature). On-call confirms they can recite the eight
      steps, find the linked handlers in <5 minutes, AND name the five
      sub-runbooks (inquiry/production, posture, evaluation,
      cross-border, adversarial-complaint) verbatim.
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
- [ ] First mainnet node brought up with `PHYLANX_MAINNET_OK=1` in
      `/etc/phylanx/oracle-node-0.env`, journalctl shows the
      `network_guard: ... PRODUCTION network ... explicit
      PHYLANX_MAINNET_OK=1 opt-in` line
- [ ] **VULN-17 Kafka auth.** Each oracle node's env file sets
      `KAFKA_SECURITY_PROTOCOL=SASL_SSL` (or `SSL` for mTLS-only
      brokers); journalctl shows the
      `kafka_security: service ... starting with 'SASL_SSL'` info
      line. NO node shows `PHYLANX_KAFKA_PLAINTEXT_OK=1` unless the
      cluster sits behind a private-link service mesh that
      authenticates the connection independently (record the
      justification in `audit/reports/kafka_plaintext_optin.md`).
- [ ] **VULN-18 scoring determinism.** Every oracle node runs on a
      Python interpreter in `SUPPORTED_PYTHON_VERSIONS` (currently
      `{(3, 12), (3, 13)}` — see `phylanx-oracle/scoring/determinism.py`);
      journalctl shows the
      `scoring_determinism: service ... starting on PRODUCTION with
      pinned runtime python=...` warning line at startup. NO node
      shows `PHYLANX_SCORING_DETERMINISM_OK=1` unless the audited
      runtime has a CVE and the bypass is justified in
      `audit/reports/scoring_determinism_optin.md`. No node has
      `numpy`/`scipy`/`pandas`/`sklearn` in `sys.modules` at startup
      (the guard scans on every entrypoint).
- [ ] **VULN-20 wallet validation on the live API.** From an external
      host, `curl -i $PHYLANX_API_URL/agents/'%27%3B%20DROP%20TABLE%20agent_transactions%3B%20--'/health`
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
      `curl -i $PHYLANX_API_URL/agents/<wallet>/safe_score` returns
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
      `phylanx` UID except the documented RPC + indexer + peer-RPC
      destinations.
- [ ] **VULN-24 flag obfuscation live.** From an external host,
      `curl -s $PHYLANX_API_URL/agents/<wallet>/health | jq .` returns
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
      (`sha256("phylanx-epoch-advance" || current_epoch ||
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
      SDK helper `advancePayloadDigest` from `@phylanx/sdk` to
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

- [ ] Daily review of `phylanx_byzantine_flags_total` — flag count should
      be 0 or near 0 in steady state
- [ ] Daily review of `phylanx_cert_submit_failures_total`
- [ ] **Daily review of `phylanx_input_divergence_flags_total`** — any
      epoch where this is non-zero means at least one node disagreed
      with the cluster on what its upstream pipeline delivered (AW-01).
      Steady state is 0. A persistent non-zero on the same node
      indicates a poisoned or misconfigured upstream — follow
      `launch/runbooks/input_provenance.md`. ANY epoch where the
      aggregator reports `input_commitment is None` (no AW-01 quorum
      → no cert issued for that agent) is a P0.
- [ ] **Daily review of `phylanx_slot_anchor_writetime_rejections_total`
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
