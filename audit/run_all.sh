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


# ── 2. cargo clippy + cargo audit ───────────────────────────────────────────
if command -v cargo >/dev/null; then
    run "cargo clippy" bash -c "cd helixor-programs && cargo clippy --workspace --all-targets -- -D warnings -A unexpected-cfgs -A ambiguous-glob-reexports -A clippy::diverging-sub-expression"
    if command -v cargo-audit >/dev/null; then
        run "cargo audit" bash -c "cd helixor-programs && cargo audit"
    else
        skip "cargo audit" "cargo-audit not installed (cargo install cargo-audit)"
    fi
    run "cargo test" bash -c "cd helixor-programs && cargo test --workspace -q"
else
    skip "cargo clippy" "rust toolchain not installed"
    skip "cargo audit"  "rust toolchain not installed"
    skip "cargo test"   "rust toolchain not installed"
fi


# ── 3. Python test suite ────────────────────────────────────────────────────
run "oracle pytest"  bash -c "cd helixor-oracle && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ../helixor-api/.venv/bin/python -m pytest tests/ --ignore=tests/oracle/test_integration.py -q"
run "indexer pytest" bash -c "cd helixor-indexer && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ${PYTHON_BIN} -m pytest tests/ -q"
run "api pytest"     bash -c "cd helixor-api && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=.:../helixor-oracle .venv/bin/python -m pytest tests/ -q"


# ── 4. Cluster load + chaos ─────────────────────────────────────────────────
run "cluster load test" bash -c "cd helixor-oracle && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ../helixor-api/.venv/bin/python -m pytest ../audit/load_tests/test_cluster_under_load.py -v -s"


# ── 5. SDK ──────────────────────────────────────────────────────────────────
if command -v npm >/dev/null; then
    run "sdk tests" bash -c "cd helixor-sdk && npm install --silent && npm test"
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
#   HELIXOR_WALLETS_FILE  — JSON list of registered agent wallets so the
#                           harness gets real 2xx responses (otherwise the
#                           DEFAULT_AGENTS placeholder list 4xx's).
#   HELIXOR_DB_PYTHON     — python with psycopg2 installed (defaults to
#                           the API venv if present, else system python3).
if [[ -n "${HELIXOR_API_URL:-}" ]]; then
    API_LOAD_ARGS=(--base-url "$HELIXOR_API_URL" --rate 4 --duration 30)
    if [[ -n "${HELIXOR_WALLETS_FILE:-}" ]]; then
        API_LOAD_ARGS+=(--wallets-file "$HELIXOR_WALLETS_FILE" --rate 1.5)
    fi
    run "API load (smoke)" python3 audit/load_tests/api_load.py "${API_LOAD_ARGS[@]}"
else
    skip "API load test" "HELIXOR_API_URL not set"
fi

if [[ -n "${DATABASE_URL:-}" ]]; then
    DB_PYTHON="${HELIXOR_DB_PYTHON:-}"
    if [[ -z "$DB_PYTHON" ]] && [[ -x helixor-api/.venv/bin/python ]]; then
        DB_PYTHON="helixor-api/.venv/bin/python"
    fi
    DB_PYTHON="${DB_PYTHON:-python3}"
    run "DB stress (smoke)" "$DB_PYTHON" audit/load_tests/db_stress.py --rows 100000
else
    skip "DB stress" "DATABASE_URL not set"
fi


# ── 8. Deployed .so verification (external) ─────────────────────────────────
# Optional: HELIXOR_PROGRAMS_FILE overrides the placeholder PROGRAMS map
# with the real deployed program IDs for non-mainnet clusters.
if [[ -n "${HELIXOR_SOLANA_CLUSTER:-}" ]]; then
    if command -v npx >/dev/null; then
        REPO_ROOT="$PWD"
        VERIFY_CMD="cd audit/artifact_verification && npx ts-node verify_so_match.ts"
        VERIFY_CMD+=" --cluster $HELIXOR_SOLANA_CLUSTER"
        VERIFY_CMD+=" --report $REPO_ROOT/audit/reports/so_match.json"
        VERIFY_CMD+=" --build-dir ${HELIXOR_BUILD_DIR:-$REPO_ROOT/helixor-programs/target/deploy}"
        if [[ -n "${HELIXOR_PROGRAMS_FILE:-}" ]]; then
            VERIFY_CMD+=" --programs-file $HELIXOR_PROGRAMS_FILE"
        fi
        run ".so verification" bash -c "$VERIFY_CMD"
    else
        skip ".so verification" "npx not installed"
    fi
else
    skip ".so verification" "HELIXOR_SOLANA_CLUSTER not set"
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
