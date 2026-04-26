#!/usr/bin/env bash
# =============================================================================
# Helixor Oracle — Day 6 Setup
# Applies migration 0003 + runs scoring engine tests.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor-oracle]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}            $*"; }
fail() { echo -e "${RED}[fail]${NC}            $*"; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║  Helixor Oracle — Day 6 Setup                 ║"
echo "║  Scoring engine: 3 signals → 0-1000           ║"
echo "╚═══════════════════════════════════════════════╝"

step "Bringing up postgres"
docker compose up -d --build postgres >/dev/null
for i in 1 2 3 4 5; do
  if docker compose exec -T postgres pg_isready -U helixor -d helixor >/dev/null 2>&1; then
    log "Postgres ready ✓"; break
  fi
  sleep 2
done

step "Applying migration 0003 (score tables)"
docker compose exec -T postgres psql -U helixor -d helixor < db/migrations/0003_scores.sql
docker compose exec -T postgres psql -U helixor -d helixor -c \
  "SELECT version, description FROM schema_version ORDER BY version;"

step "Python deps"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

step "Unit tests (engine + window — pure math)"
DATABASE_URL="postgresql://helixor:helixor@localhost:55433/helixor" \
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  pytest tests/scoring/test_engine.py tests/scoring/test_window.py -v -p pytest_asyncio.plugin 2>&1 | tail -40

step "Integration tests (full pipeline)"
DATABASE_URL="postgresql://helixor:helixor@localhost:55433/helixor" \
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  pytest tests/scoring/test_score_engine.py -v -p pytest_asyncio.plugin 2>&1 | tail -30

step "End-to-end manual test"
TEST_WALLET=$(printf "DAY6TESTwallet%032s" "$(date +%s)" | tr ' ' '0')
log "Test wallet: $TEST_WALLET"

DATABASE_URL="postgresql://helixor:helixor@localhost:55433/helixor" \
  HELIUS_API_KEY="test-api-key" \
  HELIUS_WEBHOOK_URL="https://test.helixor.local/webhook" \
  HELIUS_WEBHOOK_AUTH_TOKEN="test-auth-token-1234567890123456" \
  HEALTH_ORACLE_PROGRAM_ID="Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P" \
  python -m scripts.seed_baseline_test_data \
    --wallet "$TEST_WALLET" --tx-count 150 --active-days 25 --success-rate 0.95

DATABASE_URL="postgresql://helixor:helixor@localhost:55433/helixor" \
  HELIUS_API_KEY="test-api-key" \
  HELIUS_WEBHOOK_URL="https://test.helixor.local/webhook" \
  HELIUS_WEBHOOK_AUTH_TOKEN="test-auth-token-1234567890123456" \
  HEALTH_ORACLE_PROGRAM_ID="Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P" \
  python -m scripts.compute_baseline "$TEST_WALLET" --store > /dev/null

DATABASE_URL="postgresql://helixor:helixor@localhost:55433/helixor" \
  HELIUS_API_KEY="test-api-key" \
  HELIUS_WEBHOOK_URL="https://test.helixor.local/webhook" \
  HELIUS_WEBHOOK_AUTH_TOKEN="test-auth-token-1234567890123456" \
  HEALTH_ORACLE_PROGRAM_ID="Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P" \
  python -m scripts.compute_score "$TEST_WALLET"

step "Inspecting stored score"
docker compose exec -T postgres psql -U helixor -d helixor -c \
  "SELECT agent_wallet, score, alert,
          success_rate_score, consistency_score, stability_score,
          anomaly_flag, computed_at, written_onchain_at IS NOT NULL AS synced
   FROM agent_scores WHERE agent_wallet = '$TEST_WALLET';"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Day 6 Complete ✓                                        ║"
echo "║                                                          ║"
echo "║  ✓ Migration 0003 applied (agent_scores + history)       ║"
echo "║  ✓ 40+ unit tests passing (pure scoring math)            ║"
echo "║  ✓ 12 integration tests passing                          ║"
echo "║  ✓ End-to-end: seeded → baseline → window → score        ║"
echo "║                                                          ║"
echo "║  Next: Day 7 → write score on-chain via update_score CPI ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
