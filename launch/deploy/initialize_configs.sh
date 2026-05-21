#!/usr/bin/env bash
# =============================================================================
# launch/deploy/initialize_configs.sh — initialize on-chain configs.
#
# Day 30 — after deploy_programs.sh, the singleton config PDAs need to be
# created. This script reads the manifest, builds the initialize tx for
# each program, signs with the admin keypair, sends, and verifies.
#
# Idempotent — if a config PDA already exists, it is skipped.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

CLUSTER=""
ADMIN_KEYPAIR=""
ORACLE_KEYS_FILE=""    # JSON list of 5 pubkeys for the BFT cluster
THRESHOLD=3
MAINNET_OK=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cluster)        CLUSTER="$2"; shift 2 ;;
        --admin)          ADMIN_KEYPAIR="$2"; shift 2 ;;
        --oracle-keys)    ORACLE_KEYS_FILE="$2"; shift 2 ;;
        --threshold)      THRESHOLD="$2"; shift 2 ;;
        --mainnet-ok)     MAINNET_OK=1; shift ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [[ -z "$CLUSTER" || -z "$ADMIN_KEYPAIR" || -z "$ORACLE_KEYS_FILE" ]]; then
    cat <<'USAGE'
usage:
  initialize_configs.sh --cluster <cluster> --admin <keypair.json> \
                        --oracle-keys <keys.json> [--threshold 3] [--mainnet-ok]

Required:
  --cluster       localnet | devnet | testnet | mainnet-beta
  --admin         path to admin keypair (the rent payer / update authority)
  --oracle-keys   JSON list of 5 cluster pubkeys (base58 strings)

Optional:
  --threshold     signing threshold (default 3)
  --mainnet-ok    explicit opt-in to mainnet (refused otherwise)
USAGE
    exit 2
fi

# Mainnet refusal gate.
if [[ "$CLUSTER" == "mainnet-beta" && "$MAINNET_OK" -ne 1 ]]; then
    echo "❌ REFUSING to initialize configs on mainnet without --mainnet-ok"
    exit 2
fi

if [[ ! -f launch/deploy/manifest.json ]]; then
    echo "❌ no deploy manifest — run deploy_programs.sh first"
    exit 2
fi

# Drive the TypeScript initializer (Anchor + web3.js) — same library the
# tests use.
NODE_BIN="${NODE_BIN:-node}"
export NODE_PATH="$REPO_ROOT/helixor-programs/node_modules${NODE_PATH:+:$NODE_PATH}"
export TS_NODE_TRANSPILE_ONLY="${TS_NODE_TRANSPILE_ONLY:-1}"
export TS_NODE_COMPILER_OPTIONS="${TS_NODE_COMPILER_OPTIONS:-{\"module\":\"CommonJS\",\"moduleResolution\":\"Node\"}}"
cmd=(
    helixor-programs/node_modules/.bin/ts-node launch/deploy/initialize_configs.ts
    --cluster "$CLUSTER"
    --admin "$ADMIN_KEYPAIR"
    --oracle-keys "$ORACLE_KEYS_FILE"
    --threshold "$THRESHOLD"
)
if [[ "$MAINNET_OK" -eq 1 ]]; then
    cmd+=(--mainnet-ok)
fi
exec "${cmd[@]}"
