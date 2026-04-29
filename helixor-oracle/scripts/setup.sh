#!/usr/bin/env bash
# =============================================================================
# Helixor — Day 11 Setup
# Applies migration 0005, runs monitoring tests, prints systemd install steps.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor-day11]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}            $*"; }
fail() { echo -e "${RED}[fail]${NC}            $*"; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║  Helixor — Day 11 Setup                        ║"
echo "║  Continuous monitoring + alerts + SLOs         ║"
echo "╚════════════════════════════════════════════════╝"

step "Apply migration 0005"
psql postgresql://helixor:helixor@localhost:55433/helixor \
  -f db/migrations/0005_monitoring.sql
psql postgresql://helixor:helixor@localhost:55433/helixor \
  -c "SELECT version, description FROM schema_version ORDER BY version;"

step "Python deps"
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

step "Unit tests"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
DATABASE_URL="postgresql://helixor:helixor@localhost:55433/helixor" \
HELIUS_API_KEY="test-api-key" \
HELIUS_WEBHOOK_URL="https://test.helixor.local/webhook" \
HELIUS_WEBHOOK_AUTH_TOKEN="test-auth-token-1234567890123456" \
HEALTH_ORACLE_PROGRAM_ID="Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P" \
SOLANA_RPC_URL="https://api.devnet.solana.com" \
ORACLE_KEYPAIR_PATH="/Users/terabyte_trifler/Documents/helixor/helixor-programs/keys/oracle-node.json" \
pytest tests/monitoring/ -v -p pytest_asyncio.plugin 2>&1 | tail -30

step "One-shot dry run"
python -m monitoring.runner --once || true
log "(any unhealthy checks above are real signal — investigate before enabling alerts)"

step "Systemd install (production-only)"
cat <<'EOF'

To install systemd services on a production host:

  sudo useradd -r -s /usr/sbin/nologin helixor
  sudo mkdir -p /opt/helixor-oracle /etc/helixor /var/log/helixor
  sudo cp -r . /opt/helixor-oracle/
  sudo chown -R helixor:helixor /opt/helixor-oracle /var/log/helixor

  # Create env file (chmod 600)
  sudo tee /etc/helixor/oracle.env >/dev/null <<ENV
  DATABASE_URL=postgresql://helixor:helixor@localhost:5432/helixor
  HELIXOR_API_URL=http://localhost:8001
  HEALTH_ORACLE_PROGRAM_ID=...
  SOLANA_RPC_URL=https://api.devnet.solana.com
  ORACLE_KEYPAIR_PATH=/opt/helixor-oracle/keys/oracle-node.json
  HELIXOR_TELEGRAM_BOT_TOKEN=...
  HELIXOR_TELEGRAM_CHAT_ID=...
  ENV
  sudo chmod 600 /etc/helixor/oracle.env

  # Install units
  sudo cp deploy/systemd/*.service /etc/systemd/system/
  sudo cp deploy/systemd/*.timer   /etc/systemd/system/
  sudo cp deploy/logrotate.conf    /etc/logrotate.d/helixor

  # Enable + start
  sudo systemctl daemon-reload
  sudo systemctl enable --now helixor-monitoring.service
  sudo systemctl enable --now helixor-epoch.timer

  # Verify
  systemctl list-timers helixor-epoch.timer
  systemctl status helixor-monitoring
  journalctl -u helixor-monitoring -f

EOF

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Day 11 ready ✓                                      ║"
echo "║                                                      ║"
echo "║  Next: designate the real agent                      ║"
echo "║    python -m scripts.operator.add_monitored_agent \\ ║"
echo "║        --wallet REAL_AGENT_PUBKEY \\                  ║"
echo "║        --label 'First production agent' \\           ║"
echo "║        --min-score 600                               ║"
echo "║                                                      ║"
echo "║  Then watch: python -m scripts.operator.show_status  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
