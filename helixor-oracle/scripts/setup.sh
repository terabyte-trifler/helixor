#!/usr/bin/env bash
# =============================================================================
# Helixor Oracle — Day 8 Setup
#
# Brings up the FastAPI service and runs API tests.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor-api]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}        $*"; }
fail() { echo -e "${RED}[fail]${NC}        $*"; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║  Helixor Oracle — Day 8 Setup                  ║"
echo "║  REST API: GET /score/{agent}                  ║"
echo "╚════════════════════════════════════════════════╝"

step "Python deps"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

step "Running API tests"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
DATABASE_URL="postgresql://helixor:helixor@localhost:55433/helixor" \
HELIUS_API_KEY="test-api-key" \
HELIUS_WEBHOOK_URL="https://test.helixor.local/webhook" \
HELIUS_WEBHOOK_AUTH_TOKEN="test-auth-token-1234567890123456" \
HEALTH_ORACLE_PROGRAM_ID="Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P" \
SOLANA_RPC_URL="https://api.devnet.solana.com" \
pytest tests/api/test_score_routes.py -v -p pytest_asyncio.plugin 2>&1 | tail -40

step "Starting API server"
docker compose up -d --build api

sleep 3

step "Smoke test"
log "Health: $(curl -sf http://localhost:8001/health)"
log "Status: $(curl -sf http://localhost:8001/status | python3 -m json.tool)"
log ""
log "OpenAPI docs: http://localhost:8001/docs"
log "Try a query:  curl http://localhost:8001/score/AGENT_WALLET_PUBKEY"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Day 8 Complete ✓                                ║"
echo "║  ✓ FastAPI on http://localhost:8001              ║"
echo "║  ✓ OpenAPI docs at /docs                         ║"
echo "║  ✓ Cache + rate limit + auth ready               ║"
echo "║                                                  ║"
echo "║  Next: cd helixor-sdk && npm install && npm test ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
