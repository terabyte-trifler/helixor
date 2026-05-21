#!/usr/bin/env bash
# =============================================================================
# audit/artifact_verification/deploy_and_verify_local.sh
#
# Starts a disposable local validator, deploys the three Helixor programs, then
# runs verify_so_match.ts against the live local chain. This is the no-caveat
# artifact gate: deployed bytes must equal local build bytes.
# =============================================================================
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
LEDGER="${HELIXOR_LOCAL_LEDGER:-/tmp/helixor-local-ledger}"
RPC="${HELIXOR_LOCAL_RPC:-http://127.0.0.1:8899}"
RPC_PORT="${HELIXOR_LOCAL_RPC_PORT:-8899}"
GOSSIP_PORT="${HELIXOR_LOCAL_GOSSIP_PORT:-19000}"
FAUCET_PORT="${HELIXOR_LOCAL_FAUCET_PORT:-19099}"
DYNAMIC_RANGE="${HELIXOR_LOCAL_DYNAMIC_PORT_RANGE:-19001-19100}"

cd "$ROOT"
rm -rf "$LEDGER"
solana-test-validator \
  --reset \
  --quiet \
  --ledger "$LEDGER" \
  --rpc-port "$RPC_PORT" \
  --gossip-port "$GOSSIP_PORT" \
  --faucet-port "$FAUCET_PORT" \
  --dynamic-port-range "$DYNAMIC_RANGE" &
VALIDATOR_PID=$!
cleanup() {
  kill "$VALIDATOR_PID" >/dev/null 2>&1 || true
  wait "$VALIDATOR_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in {1..30}; do
  if solana cluster-version --url "$RPC" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
solana cluster-version --url "$RPC" >/dev/null

solana program deploy --url "$RPC" \
  --program-id helixor-programs/target/deploy/health_oracle-keypair.json \
  helixor-programs/target/deploy/health_oracle.so
solana program deploy --url "$RPC" \
  --program-id helixor-programs/target/deploy/certificate_issuer-keypair.json \
  helixor-programs/target/deploy/certificate_issuer.so
solana program deploy --url "$RPC" \
  --program-id helixor-programs/target/deploy/slash_authority-keypair.json \
  helixor-programs/target/deploy/slash_authority.so

npx ts-node audit/artifact_verification/verify_so_match.ts \
  --cluster "$RPC" \
  --build-dir helixor-programs/target/deploy
