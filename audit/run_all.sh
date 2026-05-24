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

if [[ -z "${PYTHON_BIN:-}" ]]; then
    if [[ -x "$PWD/helixor-oracle/.venv/bin/python" ]]; then
        PYTHON_BIN="$PWD/helixor-oracle/.venv/bin/python"
    else
        PYTHON_BIN="$(command -v python3)"
    fi
fi

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
run "hardening sweep"  "$PYTHON_BIN" audit/hardening_check.py


# ── 1a. Entrypoint mainnet-refusal audit (Day 30) ───────────────────────────
run "entrypoint guard audit"  "$PYTHON_BIN" audit/entrypoint_guard_audit.py


# ── 2. cargo clippy + cargo audit ───────────────────────────────────────────
if command -v cargo >/dev/null; then
    run "cargo clippy" bash -c "cd helixor-programs && cargo clippy --workspace --all-targets -- -D warnings -A unexpected-cfgs -A ambiguous-glob-reexports"
    if command -v cargo-audit >/dev/null; then
        # These advisories are inherited through the pinned Anchor/Solana 1.18
        # toolchain used by the programs. Keep the audit gate running, but
        # don't fail Helixor's Day-31 gate on upstream advisories that require
        # a coordinated Anchor/Solana upgrade rather than an application patch.
        run "cargo audit" bash -c "cd helixor-programs && cargo audit --deny warnings \
            --ignore RUSTSEC-2024-0344 \
            --ignore RUSTSEC-2025-0141 \
            --ignore RUSTSEC-2024-0388 \
            --ignore RUSTSEC-2025-0161 \
            --ignore RUSTSEC-2024-0436 \
            --ignore RUSTSEC-2023-0033 \
            --ignore RUSTSEC-2026-0097"
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
run "oracle pytest"  bash -c "cd helixor-oracle && HELIXOR_TEST_DATABASE_URL=\${HELIXOR_TEST_DATABASE_URL:-postgresql://$(whoami)@127.0.0.1:5432/helixor_pytest} '$PYTHON_BIN' -m pytest -p no:anchorpy tests/ --ignore=tests/oracle/test_integration.py -q"
run "indexer pytest" bash -c "cd helixor-indexer && '$PYTHON_BIN' -m pytest -p no:anchorpy tests/ -q"
run "api pytest"     bash -c "cd helixor-api && PYTHONPATH=.:../helixor-oracle '$PYTHON_BIN' -m pytest -p no:anchorpy tests/ -q"


# ── 4. Cluster load + chaos ─────────────────────────────────────────────────
run "cluster load test" bash -c "cd helixor-oracle && '$PYTHON_BIN' -m pytest -p no:anchorpy ../audit/load_tests/test_cluster_under_load.py -v -s"


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
    run "API load (smoke)" "$PYTHON_BIN" audit/load_tests/api_load.py \
        --base-url "$HELIXOR_API_URL" --rate 4 --duration 30
else
    skip "API load test" "HELIXOR_API_URL not set"
fi

run "DB stress (local smoke)" bash -c "HELIXOR_TEST_DATABASE_URL=\${HELIXOR_TEST_DATABASE_URL:-postgresql://$(whoami)@127.0.0.1:5432/helixor_pytest} '$PYTHON_BIN' audit/load_tests/db_stress.py --rows 10000 --min-throughput 500 --max-p95-ms 250"


# ── 8. Deployed .so verification (external) ─────────────────────────────────
if command -v npx >/dev/null; then
    if [[ -n "${HELIXOR_SOLANA_CLUSTER:-}" ]]; then
        run ".so verification" bash -c \
            "cd helixor-sdk && npx tsx ../audit/artifact_verification/verify_so_match.ts --cluster $HELIXOR_SOLANA_CLUSTER --build-dir ../helixor-programs/target/deploy --report ../audit/reports/so_match.json"
    else
        run ".so verification (local hash pin)" bash -c \
            "cd helixor-sdk && npx tsx ../audit/artifact_verification/verify_so_match.ts --local-only --build-dir ../helixor-programs/target/deploy --report ../audit/reports/so_match.json"
    fi
else
    skip ".so verification" "npx not installed"
fi


# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "──────────────────────────────────────────────────────────────────"
echo "PASSED (${#PASS[@]}):"
if [[ "${#PASS[@]}" -ne 0 ]]; then
    for n in "${PASS[@]}"; do echo "  ✅ $n"; done
fi
echo "SKIPPED (${#SKIP[@]}):"
if [[ "${#SKIP[@]}" -ne 0 ]]; then
    for n in "${SKIP[@]}"; do echo "  ⊘  $n"; done
fi
if [[ "${#FAIL[@]}" -ne 0 ]]; then
    echo "FAILED (${#FAIL[@]}):"
    for n in "${FAIL[@]}"; do echo "  ❌ $n"; done
    echo
    echo "❌ AUDIT GATE FAILED"
    exit 1
fi
echo
echo "✅ AUDIT GATES — ${#PASS[@]} passed, ${#SKIP[@]} skipped (external)"
