#!/usr/bin/env bash
# =============================================================================
# launch/deploy/deploy_programs.sh — Day 30 — deploy all 3 Anchor programs.
#
# Deploys health-oracle, certificate-issuer, slash-authority to the named
# Solana cluster. The script refuses mainnet without an explicit
# `--mainnet-ok` flag (mirrors the Python-side network guard).
#
# Acceptance (each program):
#   1. `anchor build --verifiable`  — reproducible build
#   2. `anchor deploy` to the target cluster
#   3. Capture the deployed program ID + the .so sha256 into a manifest
#   4. Run audit/artifact_verification/verify_so_match.ts to confirm
#      deployed bytecode == local build byte-for-byte
#
# After every step the script writes to launch/deploy/manifest.json. A
# resumable deploy reads that manifest and skips programs already deployed.
#
# USAGE
# -----
#   bash launch/deploy/deploy_programs.sh --cluster devnet
#   bash launch/deploy/deploy_programs.sh --cluster mainnet-beta --mainnet-ok
# =============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

CLUSTER=""
MAINNET_OK=0
RESUME=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cluster)     CLUSTER="$2"; shift 2 ;;
        --mainnet-ok)  MAINNET_OK=1; shift ;;
        --no-resume)   RESUME=0; shift ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [[ -z "$CLUSTER" ]]; then
    echo "usage: $0 --cluster {localnet|devnet|testnet|mainnet-beta} [--mainnet-ok]"
    exit 2
fi

# ── Mainnet refusal gate ─────────────────────────────────────────────────────
case "$CLUSTER" in
    mainnet-beta)
        if [[ "$MAINNET_OK" -ne 1 ]]; then
            echo "❌ REFUSING to deploy to mainnet-beta without --mainnet-ok"
            echo "   Read launch/RUNBOOK.md before passing this flag."
            exit 2
        fi
        echo "⚠️  MAINNET DEPLOY — opt-in acknowledged. Last chance to bail."
        sleep 5
        ;;
    localnet|devnet|testnet)
        ;;
    *)
        echo "❌ unsupported cluster: $CLUSTER"
        exit 2
        ;;
esac

CLUSTER_URL=$(case "$CLUSTER" in
    localnet)      echo "http://localhost:8899" ;;
    devnet)        echo "https://api.devnet.solana.com" ;;
    testnet)       echo "https://api.testnet.solana.com" ;;
    mainnet-beta)  echo "https://api.mainnet-beta.solana.com" ;;
esac)

PROGRAMS=("health-oracle" "certificate-issuer" "slash-authority")
MANIFEST="launch/deploy/manifest.json"
mkdir -p "$(dirname "$MANIFEST")"

# Initialise the manifest if missing.
if [[ ! -f "$MANIFEST" || "$RESUME" -eq 0 ]]; then
    echo '{}' > "$MANIFEST"
fi

# ── 1. Reproducible build ────────────────────────────────────────────────────
echo "── building all 3 programs with anchor build --verifiable ──"
(cd helixor-programs && anchor build --verifiable)

# ── 2. Deploy each program ───────────────────────────────────────────────────
for prog in "${PROGRAMS[@]}"; do
    echo
    echo "── deploying $prog to $CLUSTER ──"

    # Resume support: if the manifest already records a deployed ID for
    # this program on this cluster, skip the deploy.
    deployed_id=$(jq -r ".[\"$CLUSTER\"].\"$prog\".program_id // empty" "$MANIFEST")
    if [[ -n "$deployed_id" && "$RESUME" -eq 1 ]]; then
        echo "  ⊘  already deployed: $deployed_id (use --no-resume to redeploy)"
        continue
    fi

    so_path="helixor-programs/target/deploy/${prog//-/_}.so"
    if [[ ! -f "$so_path" ]]; then
        echo "❌ build artifact missing: $so_path"
        exit 2
    fi
    so_sha256=$(sha256sum "$so_path" | awk '{print $1}')

    # The deploy itself. anchor deploy reads Anchor.toml and uses the
    # configured cluster + wallet.
    deploy_out=$(
        cd helixor-programs && \
        anchor deploy --provider.cluster "$CLUSTER_URL" --program-name "$prog"
    )
    echo "$deploy_out"
    program_id=$(echo "$deploy_out" | awk '/Program Id:/ {print $3}')
    if [[ -z "$program_id" ]]; then
        echo "❌ could not extract program id from deploy output"
        exit 2
    fi

    # Record in manifest.
    jq --arg cluster "$CLUSTER" --arg prog "$prog" \
        --arg id "$program_id" --arg sha "$so_sha256" \
        --arg ts "$(date -u +%FT%TZ)" \
        '.[$cluster][$prog] = {program_id: $id, so_sha256: $sha, deployed_at: $ts}' \
        "$MANIFEST" > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"

    echo "  ✅ deployed:  $program_id   (sha256 $so_sha256)"
done

# ── 3. Byte-match verification ───────────────────────────────────────────────
echo
echo "── verifying deployed .so == local build ──"
if command -v npx >/dev/null; then
    (
        cd audit/artifact_verification && \
        npx ts-node verify_so_match.ts --cluster "$CLUSTER" \
            --build-dir ../../helixor-programs/target/deploy
    )
else
    echo "⚠️  npx not installed — run audit/artifact_verification manually"
fi

echo
echo "✅ DEPLOY COMPLETE — manifest at $MANIFEST"
echo
echo "Next steps:"
echo "  1. Initialise on-chain config (run launch/deploy/initialize_configs.sh)"
echo "  2. Transfer upgrade authority to Squads (audit/multisig/transfer_upgrade_authority.ts)"
echo "  3. Re-run audit/artifact_verification on a fresh checkout to confirm"
