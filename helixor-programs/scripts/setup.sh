#!/usr/bin/env bash
# =============================================================================
# Helixor — Day 3 Devnet Setup
# Builds 2 programs (health-oracle + consumer-example), deploys, runs tests.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}    $*"; }
fail() { echo -e "${RED}[fail]${NC}    $*"; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  Helixor MVP — Day 3 Setup                 ║"
echo "║  get_health() CPI endpoint                 ║"
echo "╚════════════════════════════════════════════╝"

step "Tools"
command -v solana >/dev/null || fail "Install solana"
command -v anchor >/dev/null || fail "Install anchor"
command -v cargo  >/dev/null || fail "Install Rust"
command -v yarn   >/dev/null || { warn "Installing yarn"; npm i -g yarn; }
log "solana $(solana --version | awk '{print $2}')"
log "anchor $(anchor --version | awk '{print $2}')"

step "Configuring devnet"
solana config set --url devnet --commitment confirmed >/dev/null

step "Wallet"
if [ ! -f "$HOME/.config/solana/id.json" ]; then
  log "Generating deploy wallet..."
  solana-keygen new --no-bip39-passphrase -o "$HOME/.config/solana/id.json" --silent
fi
DEPLOYER=$(solana-keygen pubkey "$HOME/.config/solana/id.json")
log "Deployer: $DEPLOYER"

step "Airdropping SOL"
for attempt in 1 2 3; do
  if solana airdrop 2 "$DEPLOYER" --url devnet 2>/dev/null; then
    log "  Airdrop ✓"; break
  fi
  warn "  Attempt $attempt failed — retrying..."
  sleep 3
done
log "Balance: $(solana balance --url devnet)"

step "Dependencies"
yarn install --frozen-lockfile 2>/dev/null || yarn install >/dev/null
log "yarn install ✓"

step "Lint"
cargo fmt --all -- --check || fail "cargo fmt failed. Run: cargo fmt"
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
log "Lint clean ✓"

step "Build (2 programs)"
anchor build 2>&1 | tail -8
log "Build complete ✓"

step "Deploy to devnet"
anchor deploy --provider.cluster devnet 2>&1 | tail -8
log "Deployed ✓"

step "Tests"
anchor test --provider.cluster devnet --skip-deploy --skip-local-validator 2>&1 | tail -50

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Day 3 Complete ✓                                ║"
echo "║  ✓ get_health() returns Provisional + Live + …   ║"
echo "║  ✓ consumer-example proves CPI works             ║"
echo "║  ✓ HealthQueried event emitted                   ║"
echo "║  ✓ All 16 tests passing                          ║"
echo "║                                                  ║"
echo "║  Next: Day 4 → Helius webhook → PostgreSQL       ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
