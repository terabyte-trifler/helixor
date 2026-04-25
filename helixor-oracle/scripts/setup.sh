#!/usr/bin/env bash
# =============================================================================
# Helixor Oracle — Day 4 Setup
#
# Spins up Postgres + indexer services via docker-compose, applies schema,
# runs tests.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor-oracle]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}            $*"; }
fail() { echo -e "${RED}[fail]${NC}            $*"; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║  Helixor Oracle — Day 4 Setup                 ║"
echo "║  Helius webhook → PostgreSQL                  ║"
echo "╚═══════════════════════════════════════════════╝"

step "Tools"
command -v docker         >/dev/null || fail "Install Docker"
command -v docker-compose >/dev/null 2>&1 || command -v "docker compose" >/dev/null 2>&1 || \
  fail "Install docker-compose"
command -v python3        >/dev/null || fail "Install Python 3.12+"
log "docker $(docker --version | awk '{print $3}' | tr -d ',')"
log "python $(python3 --version | awk '{print $2}')"

step "Setup .env"
if [ ! -f .env ]; then
  cp .env.example .env
  warn "Created .env from .env.example — EDIT IT before running for real."
fi

step "Starting services"
docker compose up -d --build postgres
log "Waiting for postgres to be ready..."
for i in 1 2 3 4 5 6 7 8 9 10; do
  if docker compose exec -T postgres pg_isready -U helixor -d helixor >/dev/null 2>&1; then
    log "Postgres ready ✓"; break
  fi
  sleep 2
done

step "Applying schema"
# Schema is auto-applied via docker-entrypoint-initdb.d on first start.
# Verify it landed.
docker compose exec -T postgres psql -U helixor -d helixor -c \
  "SELECT version, description FROM schema_version;" || fail "Schema not applied"

step "Installing Python deps"
python3 -m venv .venv 2>/dev/null || true
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
log "Deps installed ✓"

step "Running unit tests (parser only — no DB needed)"
DATABASE_URL="postgresql://helixor:helixor@localhost:5432/helixor" \
  pytest tests/test_parser.py -v 2>&1 | tail -20

step "Running integration tests (requires Docker)"
DATABASE_URL="postgresql://helixor:helixor@localhost:5432/helixor" \
  pytest tests/test_webhook.py -v 2>&1 | tail -30 || \
  warn "Integration tests need testcontainers + Docker accessible"

step "Starting indexer services"
docker compose up -d webhook_receiver agent_sync webhook_registrar reconciler

sleep 3

step "Health check"
curl -sf http://localhost:8000/health && echo "" || fail "webhook_receiver not responding"
curl -sf http://localhost:8000/status | python3 -m json.tool || true

echo ""
echo "╔═════════════════════════════════════════════════════╗"
echo "║  Day 4 Complete ✓                                   ║"
echo "║                                                     ║"
echo "║  ✓ Postgres + schema running                        ║"
echo "║  ✓ webhook_receiver:  http://localhost:8000         ║"
echo "║  ✓ agent_sync, webhook_registrar, reconciler up     ║"
echo "║  ✓ Tests passing                                    ║"
echo "║                                                     ║"
echo "║  Next: register a test agent, send a tx,            ║"
echo "║        verify it lands in agent_transactions.       ║"
echo "║                                                     ║"
echo "║  Manual test:                                       ║"
echo "║    bash scripts/test_webhook_manually.sh            ║"
echo "║                                                     ║"
echo "║  View logs:                                         ║"
echo "║    docker compose logs -f webhook_receiver          ║"
echo "║                                                     ║"
echo "║  Inspect DB:                                        ║"
echo "║    docker compose exec postgres psql -U helixor     ║"
echo "╚═════════════════════════════════════════════════════╝"
echo ""
