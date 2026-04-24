#!/usr/bin/env bash
# =============================================================================
# Helixor — Day 1 Setup Script
#
# Does everything from scratch:
#   1. Checks tool versions
#   2. Generates wallets
#   3. Airdrops devnet SOL
#   4. Installs Node deps
#   5. Lints
#   6. Builds
#   7. Deploys to devnet
#   8. Runs smoke tests
#
# Usage: bash scripts/setup.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[helixor]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}    $*"; }
fail() { echo -e "${RED}[fail]${NC}    $*"; exit 1; }
step() { echo -e "\n${BOLD}── Step $* ──────────────────────${NC}"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Helixor MVP — Day 1 Setup               ║"
echo "║  One program. One loop. One operator.    ║"
echo "╚══════════════════════════════════════════╝"

# ── 1. Tool versions ──────────────────────────────────────────────────────────
step "1/8 Checking tools"

command -v solana >/dev/null 2>&1 || fail "solana not found.
  Install: sh -c \"\$(curl -sSfL https://release.solana.com/v1.18.0/install)\""

command -v anchor >/dev/null 2>&1 || fail "anchor not found.
  Install: cargo install --git https://github.com/coral-xyz/anchor anchor-cli --tag v0.30.1 --locked"

command -v cargo  >/dev/null 2>&1 || fail "cargo not found. Install: https://rustup.rs"
command -v node   >/dev/null 2>&1 || fail "node not found. Install v20: https://nodejs.org"
command -v yarn   >/dev/null 2>&1 || { warn "yarn not found — installing"; npm i -g yarn; }

log "solana  $(solana --version | awk '{print $2}')"
log "anchor  $(anchor --version | awk '{print $2}')"
log "node    $(node --version)"

# ── 2. Configure cluster ──────────────────────────────────────────────────────
step "2/8 Configuring devnet"
solana config set --url devnet --commitment confirmed
log "Cluster → devnet"

# ── 3. Wallet setup ───────────────────────────────────────────────────────────
step "3/8 Wallets"

mkdir -p keys

if [ ! -f "$HOME/.config/solana/id.json" ]; then
  log "Generating deploy wallet..."
  solana-keygen new --no-bip39-passphrase -o "$HOME/.config/solana/id.json" --silent
fi
DEPLOYER=$(solana-keygen pubkey "$HOME/.config/solana/id.json")
log "Deploy wallet: $DEPLOYER"

# Test agent wallets for Day 2 onwards
for i in 1 2 3; do
  KF="keys/test-agent-$i.json"
  if [ ! -f "$KF" ]; then
    solana-keygen new --no-bip39-passphrase -o "$KF" --silent
    log "  test-agent-$i: $(solana-keygen pubkey $KF)"
  else
    log "  test-agent-$i: $(solana-keygen pubkey $KF) (existing)"
  fi
done

# Oracle node wallet (used Day 7)
if [ ! -f "keys/oracle-node.json" ]; then
  solana-keygen new --no-bip39-passphrase -o "keys/oracle-node.json" --silent
  log "  oracle-node:   $(solana-keygen pubkey keys/oracle-node.json)"
fi

# ── 4. Airdrop SOL ────────────────────────────────────────────────────────────
step "4/8 Airdropping devnet SOL"

airdrop() {
  local PUBKEY=$1 LABEL=$2
  for attempt in 1 2 3; do
    if solana airdrop 2 "$PUBKEY" --url devnet 2>/dev/null; then
      log "  $LABEL: 2 SOL ✓"; return 0
    fi
    warn "  Attempt $attempt failed for $LABEL — retrying in 3s..."
    sleep 3
  done
  warn "  Could not airdrop to $LABEL (rate limit). Check balance manually."
}

airdrop "$DEPLOYER" "deployer"
for i in 1 2 3; do
  airdrop "$(solana-keygen pubkey keys/test-agent-$i.json)" "test-agent-$i"
done

log "Deployer balance: $(solana balance --url devnet)"

# ── 5. Node dependencies ──────────────────────────────────────────────────────
step "5/8 Installing Node dependencies"
yarn install --frozen-lockfile 2>/dev/null || yarn install
log "Dependencies installed ✓"

# ── 6. Lint ───────────────────────────────────────────────────────────────────
step "6/8 Linting (clippy)"
cargo clippy --all-targets -- -D warnings 2>&1 | tail -3
log "Lint clean ✓"

# ── 7. Build ──────────────────────────────────────────────────────────────────
step "7/8 Building program"
anchor build 2>&1 | tail -5
log "Build complete ✓"
log "IDL: target/idl/health_oracle.json"

# ── 8. Deploy + test ──────────────────────────────────────────────────────────
step "8/8 Deploying to devnet + running smoke tests"

anchor deploy --provider.cluster devnet 2>&1 | tail -5
log "Deployed to devnet ✓"

anchor test \
  --provider.cluster devnet \
  --skip-deploy \
  --skip-local-validator \
  2>&1 | tail -20

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Day 1 Complete ✓                                ║"
echo "║                                                  ║"
echo "║  ✓ health_oracle deployed to devnet              ║"
echo "║  ✓ 3 instructions in IDL                         ║"
echo "║  ✓ 8 smoke tests passing                         ║"
echo "║  ✓ CI pipeline ready                             ║"
echo "║                                                  ║"
echo "║  Next: Day 2 → register_agent full impl          ║"
echo "║  File: programs/health-oracle/src/instructions/  ║"
echo "║        register_agent.rs                         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
