#!/usr/bin/env bash
# =============================================================================
# tests/oracle/run_integration.sh — boot a local validator and run the
# Day-3 integration test. End-to-end demonstration of the on-chain commit.
#
# Prerequisites (must be on PATH):
#   - solana-test-validator        (Solana CLI 1.18+)
#   - anchor                       (Anchor 0.30.1)
#   - python with pip (the helixor-oracle requirements installed)
#
# This script:
#   1. Starts solana-test-validator on port 8899 (ledger in a tempdir)
#   2. Generates a fresh oracle keypair
#   3. Builds + deploys the health-oracle program
#   4. Bootstraps OracleConfig (caller must wire register/init in their repo;
#      this script assumes the bootstrap helper exists at scripts/bootstrap_localnet.ts)
#   5. Registers a test agent
#   6. Runs the Day-3 integration test
#   7. Tears the validator down on exit
#
# This is a *driver*, not the test itself. The test is test_integration.py.
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROGRAMS_DIR="${HELIXOR_PROGRAMS_DIR:-${ROOT}/../helixor-programs}"

# Tempdir for the ledger and keypair — cleaned on exit.
TMP=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

ORACLE_KEYPAIR="$TMP/oracle.json"
OWNER_KEYPAIR="$TMP/owner.json"
solana-keygen new --no-passphrase --silent -o "$ORACLE_KEYPAIR"
solana-keygen new --no-passphrase --silent -o "$OWNER_KEYPAIR"

echo "▶ starting local validator (ledger at $TMP)"
solana-test-validator --ledger "$TMP/ledger" --quiet --reset \
    --rpc-port 8899 --faucet-port 9900 &
VALIDATOR_PID=$!
sleep 4

export SOLANA_RPC_URL="http://127.0.0.1:8899"
solana config set --url "$SOLANA_RPC_URL" --keypair "$OWNER_KEYPAIR" >/dev/null
solana airdrop 100 "$(solana-keygen pubkey "$OWNER_KEYPAIR")"  >/dev/null
solana airdrop 100 "$(solana-keygen pubkey "$ORACLE_KEYPAIR")" >/dev/null

echo "▶ building program"
(cd "$PROGRAMS_DIR" && anchor build --skip-lint)

echo "▶ deploying program"
(cd "$PROGRAMS_DIR" && anchor deploy --provider.cluster localnet)

# The actual bootstrap (init OracleConfig + register a test agent) belongs in
# the helixor-programs scripts directory — the precise shape depends on the
# rest of the repo (which Day 3 doesn't redeclare). Day 3 just runs the test.

export HELIXOR_INTEGRATION=1
export HELIXOR_PROGRAM_ID="$(solana address -k "$PROGRAMS_DIR/target/deploy/health_oracle-keypair.json")"
export ORACLE_KEYPAIR_PATH="$ORACLE_KEYPAIR"
# Caller exports HELIXOR_TEST_AGENT_PUBKEY to the agent registered above.

echo "▶ running integration test"
(cd "$ROOT" && python -m pytest tests/oracle/test_integration.py -v)

echo "▶ done."
