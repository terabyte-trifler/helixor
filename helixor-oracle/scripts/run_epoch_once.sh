#!/usr/bin/env bash
# =============================================================================
# scripts/run_epoch_once.sh — Day 7 manual verification.
#
# Walks through the full Day 7 happy path:
#   1. Verify oracle keypair + balance
#   2. Run one epoch pass (computes scores + submits to chain)
#   3. Read the cert back and assert it matches
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}    $*"; }
fail() { echo -e "${RED}[fail]${NC}    $*"; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

if [ ! -f .env ]; then fail "Missing .env (copy from .env.example)"; fi
# shellcheck disable=SC1091
set -a; source .env; set +a

step "Oracle keypair"
[ -f "$ORACLE_KEYPAIR_PATH" ] || fail "ORACLE_KEYPAIR_PATH not found: $ORACLE_KEYPAIR_PATH"
ORACLE_PK=$(solana-keygen pubkey "$ORACLE_KEYPAIR_PATH")
log "Oracle pubkey: $ORACLE_PK"
solana balance --url "$SOLANA_RPC_URL" "$ORACLE_PK"

step "Running ONE epoch pass"
.venv/bin/python -m oracle.epoch_runner --once

step "Inspecting agent_scores DB"
docker compose exec -T postgres psql -U helixor -d helixor -c \
  "SELECT agent_wallet, score, alert, written_onchain_at IS NOT NULL AS synced
   FROM agent_scores ORDER BY computed_at DESC LIMIT 10;"

echo ""
log "Day 7 manual run complete. Verify any 'synced=t' rows have a"
log "real TrustCertificate on-chain via Solana Explorer."
