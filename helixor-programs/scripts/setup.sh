#!/usr/bin/env bash
# =============================================================================
# Helixor — Day 2 Devnet Setup
#
# One command to go from fresh clone to all 14 Day 2 tests passing on devnet.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}    $*"; }
fail() { echo -e "${RED}[fail]${NC}    $*"; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${NC}"; }

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  Helixor MVP — Day 2 Setup                 ║"
echo "║  register_agent + AgentRegistration PDA    ║"
echo "╚════════════════════════════════════════════╝"

# ── 1. Prerequisites ──────────────────────────────────────────────────────────
step "Checking tools"
command -v solana >/dev/null || fail "Install solana: sh -c \"\$(curl -sSfL https://release.solana.com/v1.18.0/install)\""
command -v anchor >/dev/null || fail "Install anchor: cargo install --git https://github.com/coral-xyz/anchor anchor-cli --tag v0.30.1 --locked"
command -v cargo  >/dev/null || fail "Install Rust: https://rustup.rs"
command -v yarn   >/dev/null || { warn "Installing yarn..."; npm i -g yarn; }
log "solana  $(solana --version | awk '{print $2}')"
log "anchor  $(anchor --version | awk '{print $2}')"

# ── 2. Configure devnet ───────────────────────────────────────────────────────
step "Configuring devnet"
solana config set --url devnet --commitment confirmed

# ── 3. Wallets ────────────────────────────────────────────────────────────────
step "Setting up wallets"
mkdir -p keys

if [ ! -f "$HOME/.config/solana/id.json" ]; then
  log "Generating deploy wallet..."
  solana-keygen new --no-bip39-passphrase -o "$HOME/.config/solana/id.json" --silent
fi
DEPLOYER=$(solana-keygen pubkey "$HOME/.config/solana/id.json")
log "Deployer: $DEPLOYER"

for i in 1 2 3; do
  if [ ! -f "keys/test-agent-$i.json" ]; then
    solana-keygen new --no-bip39-passphrase -o "keys/test-agent-$i.json" --silent
    log "  Created test-agent-$i: $(solana-keygen pubkey keys/test-agent-$i.json)"
  fi
done

# ── 4. Airdrop SOL ────────────────────────────────────────────────────────────
step "Airdropping devnet SOL"
for attempt in 1 2 3; do
  if solana airdrop 2 "$DEPLOYER" --url devnet 2>/dev/null; then
    log "  Airdrop: 2 SOL ✓"; break
  fi
  warn "  Airdrop attempt $attempt failed — retrying..."
  sleep 3
done
log "Deployer balance: $(solana balance --url devnet)"

# ── 5. Dependencies ───────────────────────────────────────────────────────────
step "Installing dependencies"
yarn install --frozen-lockfile 2>/dev/null || yarn install

# ── 6. Lint ───────────────────────────────────────────────────────────────────
step "Linting"
cargo fmt --all -- --check || fail "cargo fmt check failed. Run: cargo fmt"
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
log "Lint clean ✓"

# ── 7. Build ──────────────────────────────────────────────────────────────────
step "Building"
anchor build 2>&1 | tail -5
log "Build complete ✓"

# ── 8. Deploy ─────────────────────────────────────────────────────────────────
step "Deploying to devnet"
anchor deploy --provider.cluster devnet 2>&1 | tail -5
log "Deployed ✓"

# ── 9. Test ───────────────────────────────────────────────────────────────────
step "Running Day 2 test suite"
anchor test --provider.cluster devnet --skip-deploy --skip-local-validator 2>&1 | tail -40

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Day 2 Complete ✓                                ║"
echo "║                                                  ║"
echo "║  ✓ register_agent fully implemented              ║"
echo "║  ✓ AgentRegistration PDA written correctly       ║"
echo "║  ✓ EscrowVault funded + program-controlled       ║"
echo "║  ✓ 14 integration tests passing                  ║"
echo "║                                                  ║"
echo "║  Next: Day 3 → get_health() CPI endpoint         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
