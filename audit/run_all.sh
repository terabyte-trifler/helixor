#!/usr/bin/env bash
# =============================================================================
# audit/run_all.sh — Day-29 one-shot audit driver.
#
# Runs every audit gate and produces a single PASS/FAIL at the bottom.
# External-production gates have local smoke defaults so this script executes
# every category instead of silently skipping them.
#
# Exits 0 iff every runnable gate passes. The audit operator runs this
# locally; CI runs the same gates via .github/workflows/audit.yml.
# =============================================================================
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

PASS=()
FAIL=()
SKIP=()
CLEANUP_PIDS=()
cleanup() {
    for pid in "${CLEANUP_PIDS[@]:-}"; do
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

PY_ORACLE="${PY_ORACLE:-$ROOT/helixor-oracle/.venv/bin/python}"
PY_INDEXER="${PY_INDEXER:-$ROOT/helixor-oracle/.venv/bin/python}"
AUDIT_IGNORES=(
    RUSTSEC-2024-0344  # Solana 1.18.x transitive curve25519-dalek timing advisory
    RUSTSEC-2025-0141  # Solana/Anchor transitive bincode unmaintained warning
    RUSTSEC-2024-0388  # Solana transitive derivative unmaintained warning
    RUSTSEC-2025-0161  # Solana transitive libsecp256k1 unmaintained warning
    RUSTSEC-2024-0436  # Solana transitive paste unmaintained warning
    RUSTSEC-2023-0033  # Solana transitive borsh 0.9 warning
    RUSTSEC-2026-0097  # Solana transitive rand 0.7 warning
)

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

# ── 1. Programmatic hardening sweep ─────────────────────────────────────────
run "hardening sweep"  python3 audit/hardening_check.py


# ── 2. cargo clippy + cargo audit ───────────────────────────────────────────
run "cargo clippy" bash -c "cd helixor-programs && cargo clippy --workspace --all-targets -- -D warnings"
audit_ignore_args=()
for advisory in "${AUDIT_IGNORES[@]}"; do
    audit_ignore_args+=(--ignore "$advisory")
done
run "cargo audit" bash -c "cd helixor-programs && cargo audit --deny warnings ${audit_ignore_args[*]}"
run "cargo test" bash -c "cd helixor-programs && cargo test --workspace -q"


# ── 3. Python test suite ────────────────────────────────────────────────────
run "oracle pytest"  bash -c "cd helixor-oracle && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $PY_ORACLE -m pytest -p pytest_asyncio.plugin tests/ --ignore=tests/oracle/test_integration.py -q"
run "indexer pytest" bash -c "cd helixor-indexer && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=.. $PY_INDEXER -m pytest tests/ -q"


# ── 4. Cluster load + chaos ─────────────────────────────────────────────────
run "cluster load test" bash -c "cd helixor-oracle && PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $PY_ORACLE -m pytest -p pytest_asyncio.plugin ../audit/load_tests/test_cluster_under_load.py -v -s"


# ── 5. SDK ──────────────────────────────────────────────────────────────────
run "sdk tests" bash -c "cd helixor-sdk && npm install --silent && npm test"


# ── 6. Trident fuzz (external) ──────────────────────────────────────────────
run "trident fuzz" bash audit/trident/run_fuzz.sh


# ── 7. Load tests against deployed services (external) ──────────────────────
if [[ -z "${HELIXOR_API_URL:-}" ]]; then
    HELIXOR_API_URL="http://127.0.0.1:18081"
    createdb -h 127.0.0.1 -p 5432 helixor_audit 2>/dev/null || true
    psql -h 127.0.0.1 -p 5432 -d helixor_audit >/dev/null <<'SQL'
DROP TABLE IF EXISTS agent_scores;
DROP TABLE IF EXISTS registered_agents;
CREATE TABLE registered_agents (
  agent_wallet TEXT PRIMARY KEY,
  owner_wallet TEXT NOT NULL,
  name TEXT,
  registration_pda TEXT NOT NULL,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  onchain_signature TEXT NOT NULL UNIQUE
);
CREATE TABLE agent_scores (
  agent_wallet TEXT PRIMARY KEY REFERENCES registered_agents(agent_wallet),
  score SMALLINT NOT NULL,
  alert TEXT NOT NULL,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  window_success_rate DOUBLE PRECISION NOT NULL DEFAULT 0.97,
  success_rate_score INTEGER NOT NULL DEFAULT 485,
  consistency_score INTEGER NOT NULL DEFAULT 280,
  stability_score INTEGER NOT NULL DEFAULT 180,
  raw_score INTEGER NOT NULL DEFAULT 945,
  guard_rail_applied BOOLEAN NOT NULL DEFAULT FALSE,
  anomaly_flag BOOLEAN NOT NULL DEFAULT FALSE,
  scoring_algo_version INTEGER NOT NULL DEFAULT 2,
  weights_version INTEGER NOT NULL DEFAULT 1,
  baseline_hash TEXT NOT NULL DEFAULT '0123456789abcdef0123456789abcdef'
);
INSERT INTO registered_agents(agent_wallet, owner_wallet, name, registration_pda, onchain_signature)
VALUES ('11111111111111111111111111111111', 'owner', 'system-agent', 'pda-system', 'sig-system');
INSERT INTO agent_scores(agent_wallet, score, alert)
VALUES ('11111111111111111111111111111111', 927, 'GREEN');
SQL
    (
        cd helixor-oracle
        DATABASE_URL=postgresql://$(whoami)@127.0.0.1:5432/helixor_audit \
        HELIUS_API_KEY=dummy \
        HELIUS_WEBHOOK_URL=http://localhost:9999/webhook \
        HELIUS_WEBHOOK_AUTH_TOKEN=dummy \
        HEALTH_ORACLE_PROGRAM_ID=Hex1xor111111111111111111111111111111111111 \
        ORACLE_KEYPAIR_PATH=/tmp/helixor-oracle-keypair.json \
        RATE_LIMIT_FREE_CAPACITY=100000 \
        RATE_LIMIT_CAPACITY=100000 \
        RATE_LIMIT_REFILL_PER_SECOND=10000 \
        "$PY_ORACLE" -m uvicorn api.main:app --host 127.0.0.1 --port 18081 >/tmp/helixor-audit-api.log 2>&1
    ) &
    CLEANUP_PIDS+=("$!")
    for _ in {1..30}; do
        if curl -fsS "$HELIXOR_API_URL/" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
fi
run "API load (smoke)" "$PY_ORACLE" audit/load_tests/api_load.py \
    --base-url "$HELIXOR_API_URL" --rate 4 --duration 30

DATABASE_URL="${DATABASE_URL:-postgresql://$(whoami)@127.0.0.1:5432/helixor_audit}"
createdb -h 127.0.0.1 -p 5432 helixor_audit 2>/dev/null || true
run "DB stress (smoke)" env DATABASE_URL="$DATABASE_URL" "$PY_ORACLE" audit/load_tests/db_stress.py --rows 100000


# ── 8. Deployed .so verification (external) ─────────────────────────────────
if [[ -n "${HELIXOR_SOLANA_CLUSTER:-}" ]]; then
    run ".so verification" bash -c \
        "npx ts-node audit/artifact_verification/verify_so_match.ts --cluster $HELIXOR_SOLANA_CLUSTER"
else
    run ".so verification (local deploy)" bash audit/artifact_verification/deploy_and_verify_local.sh
fi


# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "──────────────────────────────────────────────────────────────────"
echo "PASSED (${#PASS[@]}):"
for n in "${PASS[@]}"; do echo "  ✅ $n"; done
if [[ "${#FAIL[@]}" -ne 0 ]]; then
    echo "FAILED (${#FAIL[@]}):"
    for n in "${FAIL[@]}"; do echo "  ❌ $n"; done
    echo
    echo "❌ AUDIT GATE FAILED"
    exit 1
fi
echo
echo "✅ AUDIT GATES — ${#PASS[@]} passed, 0 skipped"
