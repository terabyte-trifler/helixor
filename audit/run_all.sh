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
if [[ -n "${HELIXOR_API_URL:-}" ]]; then
    run "API load (smoke)" python3 audit/load_tests/api_load.py \
        --base-url "$HELIXOR_API_URL" --rate 4 --duration 30
else
    skip "API load test" "HELIXOR_API_URL not set"
fi

if [[ -n "${DATABASE_URL:-}" ]]; then
    run "DB stress (smoke)" python3 audit/load_tests/db_stress.py --rows 100000
else
    skip "DB stress" "DATABASE_URL not set"
fi


# ── 8. Deployed .so verification (external) ─────────────────────────────────
if [[ -n "${HELIXOR_SOLANA_CLUSTER:-}" ]]; then
    if command -v npx >/dev/null; then
        run ".so verification" bash -c \
            "cd audit/artifact_verification && npx ts-node verify_so_match.ts --cluster $HELIXOR_SOLANA_CLUSTER"
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
for n in "${PASS[@]}"; do echo "  ✅ $n"; done
echo "SKIPPED (${#SKIP[@]}):"
for n in "${SKIP[@]}"; do echo "  ⊘  $n"; done
if [[ "${#FAIL[@]}" -ne 0 ]]; then
    echo "FAILED (${#FAIL[@]}):"
    for n in "${FAIL[@]}"; do echo "  ❌ $n"; done
    echo
    echo "❌ AUDIT GATE FAILED"
    exit 1
fi
echo
echo "✅ AUDIT GATES — ${#PASS[@]} passed, ${#SKIP[@]} skipped (external)"
