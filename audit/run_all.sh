#!/usr/bin/env bash
# =============================================================================
# audit/run_all.sh — Day-29 one-shot audit driver.
#
# Runs every gate this environment supports and produces a single PASS/FAIL
# at the bottom. Gates that need an external service (devnet, deployed
# API, TimescaleDB) are skipped with an explicit notice.
#
# Exits 0 iff every runnable gate passes. The audit operator runs this
# locally; CI runs the same gates via .github/workflows/audit.yml.
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."

PYTHON_BIN="${PYTHON_BIN:-python3}"

PASS=()
FAIL=()
SKIP=()

run() {
    local name="$1"; shift
    echo
    echo "── ${name} ──────────────────────────────────────────────────"
    if "$@"; then
        PASS+=("$name")
    else
        FAIL+=("$name")
    fi
}

skip() {
    local name="$1" reason="$2"
    SKIP+=("$name: $reason")
}


# ── 1. Programmatic hardening sweep ─────────────────────────────────────────
run "hardening sweep"  python3 audit/hardening_check.py


# ── 1a. Entrypoint mainnet-refusal audit (Day 30) ───────────────────────────
run "entrypoint guard audit"  python3 audit/entrypoint_guard_audit.py


# ── 1b. VULN-20 SQLi sweep ──────────────────────────────────────────────────
run "sql injection sweep"  python3 audit/sql_injection_check.py \
    --json audit/reports/sql_injection.json


# ── 1c. VULN-21 Ed25519 strictness sweep ────────────────────────────────────
run "ed25519 strictness sweep"  python3 audit/ed25519_strictness_check.py \
    --json audit/reports/ed25519_strictness.json


# ── 1d. VULN-22 version-pinning sweep ───────────────────────────────────────
run "version pinning sweep"  python3 audit/version_pinning_check.py \
    --json audit/reports/version_pinning.json


# ── 1e. VULN-23 cert-consumption sweep ──────────────────────────────────────
run "cert consumption sweep"  python3 audit/cert_consumption_check.py \
    --json audit/reports/cert_consumption.json


# ── 1f. VULN-24 adversarial-ML sweep ────────────────────────────────────────
run "adversarial ml sweep"  python3 audit/adversarial_ml_check.py \
    --json audit/reports/adversarial_ml.json


# ── 1g. VULN-25 supply-chain sweep ──────────────────────────────────────────
run "supply chain sweep"  python3 audit/supply_chain_check.py \
    --json audit/reports/supply_chain.json


# ── 1h. AW-01 input-provenance pin sweep ────────────────────────────────────
# Architectural fix for trust-transitivity: every cluster-signing /
# certificate-issuing / score-submission callsite must bind the AW-01
# input commitment. A regression that drops the arg would let an attacker
# poison upstream inputs without the on-chain signature catching it.
run "aw01 input provenance sweep"  python3 audit/input_provenance_check.py \
    --json audit/reports/aw01_input_provenance.json


# ── 1i. AW-03 baseline-provenance pin sweep ─────────────────────────────────
# Architectural fix for baseline data availability: every production
# cluster-signing callsite must bind `baseline_commit_nonce` so the cert
# digest names a SPECIFIC fetchable `BaselineDataAccount` PDA on chain.
# A regression that drops the arg would let a malicious cluster rotate
# the baseline mid-attack and still emit a cert with a stale hash that
# no consumer can re-verify against an on-chain payload.
run "aw03 baseline provenance sweep"  python3 audit/baseline_provenance_check.py \
    --json audit/reports/aw03_baseline_provenance.json


# ── 1j. AW-04 scoring-provenance pin sweep ──────────────────────────────────
# Architectural fix for scoring black-box opacity: every production
# cluster-signing callsite must bind BOTH `scoring_code_hash` and
# `score_components_hash` so the cert digest names a SPECIFIC scoring
# kernel + SPECIFIC fetchable `ScoreComponentsAccount` PDA on chain.
# A regression that drops either argument would silently emit certs
# that bind to "no code"/"no components" — defeating AW-04 without any
# type error, since both kwargs default to 32 zero bytes for legacy
# compat. Also pins `scoreComponentsPda(.., epoch)` — the components
# account is per-epoch and must be addressed accordingly.
run "aw04 scoring provenance sweep"  python3 audit/scoring_provenance_check.py \
    --json audit/reports/aw04_scoring_provenance.json


# ── 1k. SPOF audit gate ─────────────────────────────────────────────────────
# Architectural fix for the 9 SPOFs enumerated in
# launch/design/spof_resolution.md. Verifies, mechanically, that each
# mitigation is still in place: slash-authority rotation ceremony,
# upgrade-authority multisig, Kafka 3-broker HA overlay, TimescaleDB
# primary/standby/WAL-archive overlay, API multi-replica + nginx LB,
# Geyser multi-endpoint mainnet floor. A refactor that quietly undoes
# any mitigation lights this gate red before the change reaches
# mainnet.
run "spof gate"  python3 audit/spof_check.py \
    --json audit/reports/spof.json


# ── 1l. Trust-assumption audit gate ─────────────────────────────────────────
# Architectural fix for the 8 TRUST ASSUMPTIONS enumerated in the audit
# (TA-1..TA-8). Each was closed by a real mechanism — Byzantine-node
# divergence detector, Geyser pre-flight gate, scoring property tests,
# runtime library-version verification, tx-window digest commitment,
# cert freshness ceiling, Squads transition deadline, multi-RPC
# consensus. This gate greps each marker so a refactor that quietly
# removes a mitigation lights red BEFORE mainnet.
run "trust assumption gate"  python3 audit/trust_assumption_check.py \
    --json audit/reports/trust_assumption.json


# ── 1m. Centralization audit gate ───────────────────────────────────────────
# Architectural fix for the 4 HIDDEN CENTRALIZATION RISKS enumerated in
# the audit (HCR-1..HCR-4). Each was closed by a real mechanism —
# RPC-provider diversity floor, region-diversity / N-K cap, signing-path
# state isolation, operator manifest with org + jurisdiction floors. This
# gate greps each marker so a refactor that quietly removes a mitigation
# lights red BEFORE mainnet, and additionally re-runs the live HCR-3
# signing-path isolation check against the on-disk tree.
run "centralization gate"  python3 audit/centralization_check.py \
    --json audit/reports/centralization.json


# ── 1m+. OFAC-1 silent-delist transparency gate ─────────────────────────────
# A nation-state could pressure oracle node operators to delist certain
# agent wallets. The cluster's existing defenses (HCR-4, 3-of-5
# threshold, write-once cert PDAs) make a single coerced node
# insufficient and make retrospective censorship visible — but offer no
# real-time signal that the cluster considered an agent and DECLINED to
# issue. OFAC-1 adds that signal: a structured `CertRefusal` record
# (oracle/cert_refusal_log.py) is emitted onto the new
# `Topic.CERT_REFUSED = "agent.cert_events.refused"` topic by every per-
# agent gate (NSS-3, FRP-3, PDS-2, AW-01, AW-01-EXT, quorum,
# threshold-sig, OPERATOR_OVERRIDE). This gate enforces that the
# substrate, the canonical topic name, and the wire serialiser pair all
# remain in place — a refactor that removes any of them makes silent
# operator-side delisting invisible.
run "OFAC-1 cert-refusal gate"  python3 audit/cert_refusal_check.py \
    --json audit/reports/cert_refusal.json


# ── 1m++. DP-1 data-protection compliance gate ─────────────────────────────
# The scoring system builds per-agent behavioral profiles. In
# jurisdictions with data protection law (GDPR Art. 6/15/17, DPDP s.7/11/
# 12, CCPA §1798.105/110/140), storing behavioral data without a declared
# lawful basis, retention ceiling, or access/erasure mechanism is a
# regulatory liability. DP-1 (phylanx-oracle/oracle/data_protection_policy
# .py) pins DataCategory × StorageLocation → RetentionPolicy with the
# erasability biconditional (off-chain ⇒ erasable; on-chain ⇒ not,
# explicitly disclosed) and a single carve-out (REFUSAL_LOG, kept for
# the OFAC-1 transparency invariant). This gate enforces the substrate
# stays present, every category has a policy, the biconditional holds,
# and the TimescaleDB 180-day + Prometheus 30-day ceilings in the
# canonical config files still match the policy declaration.
run "DP-1 data-protection gate" python3 audit/data_protection_check.py \
    --json audit/reports/data_protection.json


# ── 1m+++. SEC-1 securities-posture gate ────────────────────────────────────
# DeFi protocols use cert scores to gate capital allocation. If an oracle
# operator's compensation couples to consumer-side outcomes (performance
# fee, token grant tracking TVL, revenue share), Howey prong 4 ("derived
# solely from efforts of others") starts to align with the cluster's
# output. SEC-1 (oracle/securities_compliance.py +
# OperatorAttestation.compensation_model + .conflicts_disclosed) makes
# the operator's posture mechanically verifiable: a closed-enum allowlist
# (today: FLAT_FEE_PER_CERT_FROM_TREASURY only) plus sig-bound
# self-dealing disclosures. Both new fields fold into
# attestation_canonical_bytes so the existing OFAC-1 Ed25519 sig binding
# extends to cover them — lying about compensation or hiding a conflict
# costs the same key compromise the rest of the protocol assumes the
# adversary cannot perform. This gate enforces the substrate stays
# present, the enum / allowlist agree, the allowlist matches the
# governance pin, OperatorAttestation carries both fields, and
# attestation_canonical_bytes still binds them.
run "SEC-1 securities-posture gate" python3 audit/securities_compliance_check.py \
    --json audit/reports/securities_compliance.json


# ── 1m++++. AML-1 KYC/AML posture gate ──────────────────────────────────────
# Large-scale AI agent lending enabled by Phylanx certs may trigger AML
# compliance requirements for downstream DeFi protocols, creating a
# regulatory attack surface that adversaries can exploit via complaint
# (FinCEN / FCA / SEBI / FATF). The risk is NOT that the cluster is an
# MSB / VASP — it has no custody, no transmission, no exchange — but
# that without a clean, sig-bound posture statement the complaint
# becomes a process tax. AML-1 (oracle/aml_compliance.py +
# OperatorAttestation.aml_program_attestation) makes the operator's
# AML posture mechanically verifiable: a closed-enum allowlist
# ({NO_AML_PROGRAM_REQUIRED_FOR_PHYLANX_ACTIVITY,
# EXTERNAL_AML_PROGRAM_DECLARED}) sig-bound via
# attestation_canonical_bytes so the existing OFAC-1 Ed25519 binding
# extends to cover it — lying about AML posture costs the same key
# compromise the rest of the protocol assumes the adversary cannot
# perform. The module also exports a _KYC_FORBIDDEN_FIELDS guard so
# DP-1 cannot accidentally introduce a KYC-shaped DataCategory and
# silently invert the carve-out. This gate enforces the substrate
# stays present, the enum / allowlist agree, the allowlist matches the
# governance pin, OperatorAttestation carries the new field,
# attestation_canonical_bytes still binds it, and every existing
# DataCategory passes assert_no_kyc_fields.
run "AML-1 KYC/AML posture gate" python3 audit/aml_compliance_check.py \
    --json audit/reports/aml_compliance.json


# ── 1n. Protocol Death Spiral audit gate ────────────────────────────────────
# Architectural fix for catastrophic Scenario A from the audit: attacker
# compromises 2 oracle nodes, runs VULN-03 slow drift for 30 epochs, all
# agent scores reach 900+, DeFi protocols issue max loans against the
# inflated scores, attacker triggers mass agent failures, every loan
# defaults at once. Closed by three real mechanisms — cluster
# saturation gate (PDS-1), SDK score-velocity contract (PDS-2),
# multi-epoch correlated-movement + mass-failure detector (PDS-3). This
# gate greps each marker so a refactor that quietly removes a
# mitigation lights red BEFORE mainnet.
run "death spiral gate"  python3 audit/death_spiral_check.py \
    --json audit/reports/death_spiral.json


# ── 1o. Nation-State Silent Subversion audit gate ───────────────────────────
# Architectural fix for catastrophic Scenario B from the audit: nation-state
# compromises a cloud provider hosting oracle nodes, a kernel module on the
# hypervisor exfiltrates Ed25519 private keys, attacker accumulates K-of-N
# cluster keys, issues GREEN certs for fresh state-controlled wallets, the
# agents accumulate large DeFi positions over weeks, coordinated market
# action follows. Closed by three real mechanisms — cluster cloud-provider
# diversity gate (NSS-1), mainnet HSM-only signing enforcement (NSS-2),
# cluster-side agent-registration-age floor for GREEN certs (NSS-3). This
# gate greps each marker so a refactor that quietly removes a mitigation
# lights red BEFORE mainnet.
run "nation state gate"  python3 audit/nation_state_check.py \
    --json audit/reports/nation_state.json


# ── 1p. Stale Oracle Lock audit gate ────────────────────────────────────────
# Architectural fix for catastrophic Scenario C from the audit: all 5
# oracle nodes are disrupted simultaneously (DDoS or infra failure) -> no
# new certs are issued -> DeFi protocols continue to use last-issued certs
# (stale data) -> agents whose behaviour degrades never get updated certs
# -> mass defaults with no warning. Closed by three orthogonal mechanisms
# — cluster-liveness signal (SOL-1), per-agent age-based tier degradation
# escalator (SOL-2), per-operation freshness floors (SOL-3). This gate
# greps each marker so a refactor that quietly removes a mitigation lights
# red BEFORE mainnet, and additionally cross-checks the TA-6 mirror
# constant (`MAX_AGE_SECONDS = 48*60*60` in the on-chain
# certificate-issuer health-certificate state).
run "stale oracle gate"  python3 audit/stale_oracle_check.py \
    --json audit/reports/stale_oracle.json


# ── 1q. Forge-High-Score-Cert audit gate ────────────────────────────────────
# Red-team Path 1 closure: an attacker who has compromised K=3 of the 5
# cluster keys (or who controls a single physical machine running two
# cluster HSMs) can still mint forged GREEN certs unless the cluster
# enforces (a) a hard rotation cadence so compromised keys don't dwell
# indefinitely, (b) a per-signer host/region attestation so two cluster
# signatures can't come from the same machine, and (c) a rotation-overlap
# guard so one ceremony cannot wholesale-replace the cluster. Closed by
# three orthogonal mechanisms — cluster-key rotation cadence floor
# (FHS-1), per-signer provenance attestation (FHS-2), cluster-key
# rotation overlap guard (FHS-3). This gate greps each marker so a
# refactor that quietly removes a mitigation lights red BEFORE mainnet,
# and additionally cross-checks the on-chain anchors for VULN-01
# (`verify_threshold_signatures` + `expected_digest` filtering in
# `certificate-issuer/src/signing.rs`) and VULN-13
# (`MIN_TIMELOCK_SECONDS = 48 * 60 * 60` in `pending_oracle_rotation.rs`).
run "forge high-score gate"  python3 audit/forge_high_score_check.py \
    --json audit/reports/forge_high_score.json


# ── 1r. Inflate-Legitimate-Score audit gate ─────────────────────────────────
# Red-team Path 2 closure: an attacker who has (a) compromised one cluster
# key and tries to rotate the baseline every epoch (VULN-06), (b) exfiltrated
# one trusted producer key and stamps 100% of feature records for a target
# agent (VULN-07), or (c) drips small per-epoch score deltas to inflate the
# score over many epochs (VULN-03) can still inflate a legitimate score
# unless the oracle enforces (1) a hard baseline-rotation cadence + co-signer
# floor so a single compromised cluster key cannot wholesale-rewrite the
# baseline, (2) a producer-corroboration + record-freshness gate so a single
# compromised producer key cannot dominate an aggregation, and (3) a
# multi-substrate score-drift ceiling (cumulative + per-epoch + monotonic-run)
# so slow drift cannot evade single-epoch velocity. Closed by three orthogonal
# mechanisms — baseline-rotation cadence + co-attestation guard (ILS-1),
# producer-corroboration + freshness floor (ILS-2), score-drift ceiling
# (ILS-3). This gate greps each marker so a refactor that quietly removes a
# mitigation lights red BEFORE mainnet, and additionally cross-checks the
# anchors for VULN-06 (`is_authorised_baseline_writer` +
# `BaselineRotationTooSoon` + `BaselineEpochNotMonotonic` in
# `certificate-issuer/src/instructions/record_baseline.rs`), VULN-07
# (`TrustedProducerSet` + `verify_record_headers` in `indexer/eventbus/
# consumer.py`), and VULN-03 (`VELOCITY_THRESHOLD = 0.20` +
# `DRIFT_REASON_VELOCITY` in `oracle/cluster/drift_detector.py`).
run "inflate score gate"  python3 audit/inflate_score_check.py \
    --json audit/reports/inflate_score.json


# ── 1s. Freeze-Cert-at-High-Score audit gate ────────────────────────────────
# Red-team Path 3 closure: an attacker who has (a) compromised a fraction of
# the cluster nodes and withholds commit-reveal shares so rounds keep closing
# at minimum quorum (VULN-05), (b) withholds advance attestations so the
# cluster's epoch clock freezes (VULN-02), or (c) targets a DeFi consumer
# that doesn't call `is_fresh_default` on the on-chain cert (so the
# attacker only needs the cluster to KEEP MINTING certs against a stalled
# substrate) can still freeze a cert at a high score unless the cluster
# refuses to issue NEW certs while it is itself in a degraded state.
# Closed by three orthogonal mechanisms — cluster participation floor
# (FRP-1), epoch-advance liveness floor (FRP-2), cert-reissue cadence floor
# (FRP-3). This gate greps each marker so a refactor that quietly removes a
# mitigation lights red BEFORE mainnet, and additionally cross-checks the
# anchors for VULN-05 (`submit_reveal` + `non_revealers` + `reveal_deadline`
# + `min_reveals` in `oracle/cluster/commit_reveal_round.py`), VULN-02
# (`verify_cluster_threshold` + `consensus_threshold` +
# `InsufficientAdvanceAttestations` in `health-oracle/src/instructions/
# advance_epoch.rs` and `DEFAULT_DURATION_SECONDS = 86_400` in
# `health-oracle/src/state/epoch_state.rs`), and TA-6 (`MAX_AGE_SECONDS:
# i64 = 48 * 60 * 60` + `is_fresh_default` in `certificate-issuer/src/
# state/health_certificate.rs`).
run "freeze cert gate"  python3 audit/freeze_cert_check.py \
    --json audit/reports/freeze_cert.json


# ── 1t. DeFi-Bypass audit gate ──────────────────────────────────────────────
# Red-team Path 4 closure: an attacker who can't break Phylanx's own substrate
# (Paths 1/2/3 closed by FHS/ILS/FRP) targets a DeFi consumer's INTEGRATION
# instead — a lending protocol that reads `getScore()` raw, never bounds
# operations against SOL-3 freshness floors, and never re-verifies the
# AW-01-EXT slot anchor against an independent RPC. Phylanx cannot close this
# from its own substrate — the only durable mitigation is making the safe
# path the easy path. This gate is the mechanical regression alarm for the
# "Verified Integrator" pre-flight: every partner manifest at
# `launch/integrations/*.json` is verified to (a) claim only allowed
# `operations_bound` (LOAN_ISSUE / LOAN_INCREASE / LIQUIDATION_CHECK /
# STATUS_READ), (b) attest the three safety surfaces (SafeCertReader,
# verifyInputProvenance, verifyAgainstSolanaLedger), (c) name a cert-reader
# source on disk that contains every claimed marker, and (d) carry a
# canonical-hash that matches the recompute. The gate ALSO cross-checks the
# VULN-23 anchor (`SafeCertReader` + `CERT_MAX_AGE_SECONDS = 48 * 60 * 60` in
# `phylanx-sdk/src/safe_reader.ts`), the SOL-3 anchor (`Operation` enum + all
# four per-op constants in `phylanx-oracle/oracle/operation_freshness.py`),
# and the AW-01-EXT anchor (`verifyAgainstSolanaLedger` in
# `phylanx-sdk/src/input_provenance.ts`) so a rename in any of those
# surfaces voids every existing manifest and lights red here BEFORE the
# refactor reaches mainnet.
run "consumer integration gate"  python3 audit/consumer_integration_check.py \
    --json audit/reports/consumer_integration.json


# ── 2. cargo clippy + cargo audit ───────────────────────────────────────────
if command -v cargo >/dev/null; then
    run "cargo clippy" bash -c "cd phylanx-programs && cargo clippy --workspace --all-targets -- -D warnings -A unexpected-cfgs -A ambiguous-glob-reexports -A clippy::diverging-sub-expression"
    if command -v cargo-audit >/dev/null; then
        run "cargo audit" bash -c "cd phylanx-programs && cargo audit"
    else
        skip "cargo audit" "cargo-audit not installed (cargo install cargo-audit)"
    fi
    run "cargo test" bash -c "cd phylanx-programs && cargo test --workspace -q"
else
    skip "cargo clippy" "rust toolchain not installed"
    skip "cargo audit"  "rust toolchain not installed"
    skip "cargo test"   "rust toolchain not installed"
fi


# ── 3. Python test suite ────────────────────────────────────────────────────
run "oracle pytest"  bash -c "cd phylanx-oracle && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ../phylanx-api/.venv/bin/python -m pytest tests/ --ignore=tests/oracle/test_integration.py -q"
run "indexer pytest" bash -c "cd phylanx-indexer && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ${PYTHON_BIN} -m pytest tests/ -q"
run "api pytest"     bash -c "cd phylanx-api && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=.:../phylanx-oracle .venv/bin/python -m pytest tests/ -q"


# ── 4. Cluster load + chaos ─────────────────────────────────────────────────
run "cluster load test" bash -c "cd phylanx-oracle && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ../phylanx-api/.venv/bin/python -m pytest ../audit/load_tests/test_cluster_under_load.py -v -s"


# ── 5. SDK ──────────────────────────────────────────────────────────────────
if command -v npm >/dev/null; then
    run "sdk tests" bash -c "cd phylanx-sdk && npm install --silent && npm test"
else
    skip "sdk tests" "npm not installed"
fi


# ── 6. Trident fuzz (external) ──────────────────────────────────────────────
if command -v trident >/dev/null; then
    run "trident fuzz" bash audit/trident/run_fuzz.sh
else
    skip "trident fuzz" "trident-cli not installed — see audit/trident/README.md"
fi


# ── 7. Load tests against deployed services (external) ──────────────────────
# Optional helpers:
#   PHYLANX_WALLETS_FILE  — JSON list of registered agent wallets so the
#                           harness gets real 2xx responses (otherwise the
#                           DEFAULT_AGENTS placeholder list 4xx's).
#   PHYLANX_DB_PYTHON     — python with psycopg2 installed (defaults to
#                           the API venv if present, else system python3).
if [[ -n "${PHYLANX_API_URL:-}" ]]; then
    API_LOAD_ARGS=(--base-url "$PHYLANX_API_URL" --rate 4 --duration 30)
    if [[ -n "${PHYLANX_WALLETS_FILE:-}" ]]; then
        API_LOAD_ARGS+=(--wallets-file "$PHYLANX_WALLETS_FILE" --rate 1.5)
    fi
    run "API load (smoke)" python3 audit/load_tests/api_load.py "${API_LOAD_ARGS[@]}"
else
    skip "API load test" "PHYLANX_API_URL not set"
fi

if [[ -n "${DATABASE_URL:-}" ]]; then
    DB_PYTHON="${PHYLANX_DB_PYTHON:-}"
    if [[ -z "$DB_PYTHON" ]] && [[ -x phylanx-api/.venv/bin/python ]]; then
        DB_PYTHON="phylanx-api/.venv/bin/python"
    fi
    DB_PYTHON="${DB_PYTHON:-python3}"
    run "DB stress (smoke)" "$DB_PYTHON" audit/load_tests/db_stress.py --rows 100000
else
    skip "DB stress" "DATABASE_URL not set"
fi


# ── 8. Deployed .so verification (external) ─────────────────────────────────
# Optional: PHYLANX_PROGRAMS_FILE overrides the placeholder PROGRAMS map
# with the real deployed program IDs for non-mainnet clusters.
if [[ -n "${PHYLANX_SOLANA_CLUSTER:-}" ]]; then
    if command -v npx >/dev/null; then
        REPO_ROOT="$PWD"
        VERIFY_CMD="cd audit/artifact_verification && npx ts-node verify_so_match.ts"
        VERIFY_CMD+=" --cluster $PHYLANX_SOLANA_CLUSTER"
        VERIFY_CMD+=" --report $REPO_ROOT/audit/reports/so_match.json"
        VERIFY_CMD+=" --build-dir ${PHYLANX_BUILD_DIR:-$REPO_ROOT/phylanx-programs/target/deploy}"
        if [[ -n "${PHYLANX_PROGRAMS_FILE:-}" ]]; then
            VERIFY_CMD+=" --programs-file $PHYLANX_PROGRAMS_FILE"
        fi
        run ".so verification" bash -c "$VERIFY_CMD"
    else
        skip ".so verification" "npx not installed"
    fi
else
    skip ".so verification" "PHYLANX_SOLANA_CLUSTER not set"
fi


# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "──────────────────────────────────────────────────────────────────"
echo "PASSED (${#PASS[@]}):"
for n in ${PASS[@]+"${PASS[@]}"}; do echo "  ✅ $n"; done
echo "SKIPPED (${#SKIP[@]}):"
for n in ${SKIP[@]+"${SKIP[@]}"}; do echo "  ⊘  $n"; done
if [[ "${#FAIL[@]}" -ne 0 ]]; then
    echo "FAILED (${#FAIL[@]}):"
    for n in ${FAIL[@]+"${FAIL[@]}"}; do echo "  ❌ $n"; done
    echo
    echo "❌ AUDIT GATE FAILED"
    exit 1
fi
echo
echo "✅ AUDIT GATES — ${#PASS[@]} passed, ${#SKIP[@]} skipped (external)"
