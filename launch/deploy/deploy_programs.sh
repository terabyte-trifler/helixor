#!/usr/bin/env bash
# =============================================================================
# launch/deploy/deploy_programs.sh — Day 30 — deploy + atomic Squads transfer.
#
# Deploys health-oracle, certificate-issuer, slash-authority to the named
# Solana cluster AND, immediately after each deploy, transfers that
# program's BPF upgrade authority to a Squads multisig vault — all in one
# script, with no manual gap between the two operations.
#
# THE WINDOW THIS CLOSES (VULN-19)
# --------------------------------
# In the legacy flow the deploy and the transfer were two separate
# commands the operator ran by hand:
#
#     $ bash launch/deploy/deploy_programs.sh ...   # hot key has authority
#     ... time passes ...
#     $ npx ts-node audit/multisig/transfer_upgrade_authority.ts --execute
#
# Between the two, the deployer hot key was the sole upgrade authority for
# all 3 programs. An attacker who exfiltrated that key during the window
# could replace any program with a backdoored build that looks identical
# but tampers with signature verification or threshold logic. The launch
# checklist said "transfer immediately"; in practice "immediately" could
# stretch to hours if there's a team meeting, timezone hand-off, or
# checklist confusion.
#
# THIS SCRIPT CLOSES THE WINDOW:
#
#   for each program in {health-oracle, certificate-issuer, slash-authority}:
#       1. anchor deploy ............................ hot key holds authority for SECONDS
#       2. SetAuthority -> Squads vault ............. transfer
#       3. read on-chain authority, compare to vault . verify
#       4. record in manifest with `upgrade_authority` field
#   only after all 3 verified do we emit the "deploy verified — safe to
#   publish program IDs" marker.
#
# MAINNET REQUIRES
# ----------------
#   --mainnet-ok                       (the existing opt-in)
#   --squads-vault    <pubkey>         (the Squads vault PDA)
#   --squads-owner    <pubkey,...>     (one+ accepted owner program IDs)
#   --deployer-keypair <path>          (signs deploy + transfer)
#
# `--no-transfer` is allowed ONLY on localnet/devnet/testnet — it's a
# developer affordance for iterating without provisioning a Squads vault.
# Mainnet hard-refuses it.
#
# USAGE — localnet/devnet (no transfer)
# -------------------------------------
#   bash launch/deploy/deploy_programs.sh --cluster devnet --no-transfer
#
# USAGE — mainnet (atomic deploy + transfer)
# ------------------------------------------
#   bash launch/deploy/deploy_programs.sh \
#       --cluster          mainnet-beta \
#       --mainnet-ok \
#       --squads-vault     <SquadsVaultPDA> \
#       --squads-owner     <SquadsProgramId> \
#       --deployer-keypair ~/.config/solana/deployer.json
# =============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

CLUSTER=""
MAINNET_OK=0
RESUME=1
SQUADS_VAULT=""
SQUADS_OWNER=""
DEPLOYER_KEYPAIR=""
NO_TRANSFER=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cluster)            CLUSTER="$2"; shift 2 ;;
        --mainnet-ok)         MAINNET_OK=1; shift ;;
        --no-resume)          RESUME=0; shift ;;
        --squads-vault)       SQUADS_VAULT="$2"; shift 2 ;;
        --squads-owner)       SQUADS_OWNER="$2"; shift 2 ;;
        --deployer-keypair)   DEPLOYER_KEYPAIR="$2"; shift 2 ;;
        --no-transfer)        NO_TRANSFER=1; shift ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [[ -z "$CLUSTER" ]]; then
    cat >&2 <<EOF
usage: $0 --cluster {localnet|devnet|testnet|mainnet-beta} [--mainnet-ok]
       [--squads-vault <pda> --squads-owner <pid,...> --deployer-keypair <path>]
       [--no-transfer]   # localnet/devnet/testnet only
EOF
    exit 2
fi

# ── Mainnet refusal gate ─────────────────────────────────────────────────────
case "$CLUSTER" in
    mainnet-beta)
        if [[ "$MAINNET_OK" -ne 1 ]]; then
            echo "❌ REFUSING to deploy to mainnet-beta without --mainnet-ok" >&2
            echo "   Read launch/RUNBOOK.md before passing this flag." >&2
            exit 2
        fi
        # VULN-19: mainnet requires the atomic deploy+transfer flow.
        if [[ "$NO_TRANSFER" -eq 1 ]]; then
            echo "❌ REFUSING --no-transfer on mainnet-beta (VULN-19)." >&2
            echo "   The deploy/transfer window is the maximum compromise" >&2
            echo "   surface and the mainnet path MUST close it atomically." >&2
            exit 2
        fi
        if [[ -z "$SQUADS_VAULT" ]]; then
            echo "❌ REFUSING mainnet deploy without --squads-vault (VULN-19)." >&2
            echo "   The script transfers upgrade authority to the Squads" >&2
            echo "   vault IMMEDIATELY after each anchor deploy. Provision" >&2
            echo "   the multisig first (see launch/RUNBOOK.md)." >&2
            exit 2
        fi
        if [[ -z "$SQUADS_OWNER" ]]; then
            echo "❌ REFUSING mainnet deploy without --squads-owner (VULN-19)." >&2
            echo "   The preflight verifies the vault is owned by an" >&2
            echo "   accepted program — pass the Squads program id(s)." >&2
            exit 2
        fi
        if [[ -z "$DEPLOYER_KEYPAIR" ]]; then
            echo "❌ REFUSING mainnet deploy without --deployer-keypair." >&2
            echo "   The keypair signs both the deploy and the atomic" >&2
            echo "   SetAuthority transfer; the script needs the path." >&2
            exit 2
        fi
        echo "⚠️  MAINNET DEPLOY — atomic deploy+transfer. Last chance to bail."
        sleep 5
        ;;
    localnet|devnet|testnet)
        ;;
    *)
        echo "❌ unsupported cluster: $CLUSTER" >&2
        exit 2
        ;;
esac

# Non-mainnet path may still opt into the atomic transfer (recommended on
# devnet to dry-run the production flow). If --squads-vault is supplied we
# require the rest of the args too.
if [[ -n "$SQUADS_VAULT" || -n "$SQUADS_OWNER" || -n "$DEPLOYER_KEYPAIR" ]]; then
    if [[ -z "$SQUADS_VAULT" || -z "$SQUADS_OWNER" || -z "$DEPLOYER_KEYPAIR" ]]; then
        echo "❌ --squads-vault, --squads-owner, --deployer-keypair must be passed together" >&2
        exit 2
    fi
fi

DO_TRANSFER=0
if [[ -n "$SQUADS_VAULT" && "$NO_TRANSFER" -ne 1 ]]; then
    DO_TRANSFER=1
fi

case "$CLUSTER" in
    localnet)      CLUSTER_URL="http://localhost:8899" ;;
    devnet)        CLUSTER_URL="https://api.devnet.solana.com" ;;
    testnet)       CLUSTER_URL="https://api.testnet.solana.com" ;;
    mainnet-beta)  CLUSTER_URL="https://api.mainnet-beta.solana.com" ;;
esac

PROGRAMS=("health-oracle" "certificate-issuer" "slash-authority")
MANIFEST="launch/deploy/manifest.json"
mkdir -p "$(dirname "$MANIFEST")"

# Initialise the manifest if missing.
if [[ ! -f "$MANIFEST" || "$RESUME" -eq 0 ]]; then
    echo '{}' > "$MANIFEST"
fi

# ── 0. Pre-flight: verify the Squads vault before any deploy ─────────────────
if [[ "$DO_TRANSFER" -eq 1 ]]; then
    echo "── pre-flight: verify Squads vault $SQUADS_VAULT on $CLUSTER ──"
    if ! command -v npx >/dev/null; then
        echo "❌ npx not installed — required for vault pre-flight" >&2
        exit 2
    fi
    npx ts-node launch/deploy/preflight_vault.ts \
        --vault "$SQUADS_VAULT" \
        --expected-owner "$SQUADS_OWNER" \
        --cluster "$CLUSTER" \
        --out "audit/reports/squads_vault_preflight.json"
    echo "  ✅ pre-flight OK — proceeding with deploy"
else
    echo "── pre-flight: --no-transfer / no --squads-vault — skipping vault check ──"
fi

# ── 1. Reproducible build ────────────────────────────────────────────────────
echo "── building all 3 programs with anchor build --verifiable ──"
(cd helixor-programs && anchor build --verifiable)

# ── 2. Per-program: deploy → transfer → verify ───────────────────────────────
ALL_TRANSFERRED=1
for prog in "${PROGRAMS[@]}"; do
    echo
    echo "── $prog ──"

    # Resume support: if the manifest already records a deployed ID for
    # this program on this cluster AND it was already transferred (or
    # transfer is disabled), skip. We do NOT skip if the deploy is
    # recorded but the transfer is missing — that's exactly the VULN-19
    # window and we must close it on every run.
    deployed_id=$(jq -r ".[\"$CLUSTER\"].\"$prog\".program_id // empty" "$MANIFEST")
    deployed_authority=$(jq -r ".[\"$CLUSTER\"].\"$prog\".upgrade_authority // empty" "$MANIFEST")

    needs_deploy=1
    if [[ -n "$deployed_id" && "$RESUME" -eq 1 ]]; then
        needs_deploy=0
        echo "  ⊘  deploy already recorded: $deployed_id"
    fi

    so_path="helixor-programs/target/deploy/${prog//-/_}.so"
    if [[ ! -f "$so_path" ]]; then
        echo "❌ build artifact missing: $so_path" >&2
        exit 2
    fi
    so_sha256=$(sha256sum "$so_path" | awk '{print $1}')

    if [[ "$needs_deploy" -eq 1 ]]; then
        # The deploy itself. anchor deploy reads Anchor.toml and uses the
        # configured cluster + wallet.
        deploy_out=$(
            cd helixor-programs && \
            anchor deploy --provider.cluster "$CLUSTER_URL" --program-name "$prog"
        )
        echo "$deploy_out"
        deployed_id=$(echo "$deploy_out" | awk '/Program Id:/ {print $3}')
        if [[ -z "$deployed_id" ]]; then
            echo "❌ could not extract program id from deploy output" >&2
            exit 2
        fi

        # Record the deploy in the manifest BEFORE the transfer so an
        # interrupted run still leaves a recoverable trail.
        jq --arg cluster "$CLUSTER" --arg prog "$prog" \
            --arg id "$deployed_id" --arg sha "$so_sha256" \
            --arg ts "$(date -u +%FT%TZ)" \
            '.[$cluster][$prog] = {program_id: $id, so_sha256: $sha, deployed_at: $ts}' \
            "$MANIFEST" > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"

        echo "  ✅ deployed:  $deployed_id   (sha256 $so_sha256)"
    fi

    # ── 2b. Atomic transfer ──────────────────────────────────────────────────
    if [[ "$DO_TRANSFER" -eq 1 ]]; then
        if [[ -n "$deployed_authority" && "$deployed_authority" == "$SQUADS_VAULT" && "$RESUME" -eq 1 ]]; then
            echo "  ⊘  authority already transferred to $deployed_authority"
            continue
        fi

        echo "  → transferring upgrade authority to Squads vault $SQUADS_VAULT"
        # `transfer_upgrade_authority.ts` does the transfer AND verifies
        # the on-chain authority post-transfer; it exits non-zero on
        # mismatch, which causes `set -e` to terminate the whole deploy.
        if ! npx ts-node audit/multisig/transfer_upgrade_authority.ts \
                --program     "$prog" \
                --program-id  "$deployed_id" \
                --vault       "$SQUADS_VAULT" \
                --keypair     "$DEPLOYER_KEYPAIR" \
                --cluster     "$CLUSTER" \
                --execute; then
            echo "❌ transfer FAILED for $prog — aborting deploy" >&2
            ALL_TRANSFERRED=0
            exit 2
        fi

        # Stamp the verified authority into the manifest.
        jq --arg cluster "$CLUSTER" --arg prog "$prog" \
            --arg auth "$SQUADS_VAULT" \
            --arg ts "$(date -u +%FT%TZ)" \
            '.[$cluster][$prog].upgrade_authority = $auth |
             .[$cluster][$prog].upgrade_authority_transferred_at = $ts' \
            "$MANIFEST" > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"
        echo "  ✅ authority verified on-chain == $SQUADS_VAULT"
    else
        # Non-mainnet: leave a clear marker that authority is still the deployer.
        jq --arg cluster "$CLUSTER" --arg prog "$prog" \
            '.[$cluster][$prog].upgrade_authority = "DEPLOYER-HOTKEY (no transfer requested)"' \
            "$MANIFEST" > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"
        ALL_TRANSFERRED=0
    fi
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

# ── 4. Publish gate — only print "safe to publish" when all 3 are locked ─────
echo
if [[ "$DO_TRANSFER" -eq 1 && "$ALL_TRANSFERRED" -eq 1 ]]; then
    DEPLOY_OK_MARKER="audit/reports/deploy_verified.json"
    mkdir -p "$(dirname "$DEPLOY_OK_MARKER")"
    jq -n \
        --arg cluster "$CLUSTER" \
        --arg vault "$SQUADS_VAULT" \
        --arg ts "$(date -u +%FT%TZ)" \
        --slurpfile m "$MANIFEST" \
        '{verified_at: $ts, cluster: $cluster, vault: $vault, manifest: $m[0]}' \
        > "$DEPLOY_OK_MARKER"
    echo "✅ DEPLOY VERIFIED — manifest at $MANIFEST"
    echo "✅ Upgrade authority for all 3 programs is the Squads vault $SQUADS_VAULT"
    echo "✅ Safe-to-publish marker: $DEPLOY_OK_MARKER"
    echo
    echo "Next steps:"
    echo "  1. Initialise on-chain config (run launch/deploy/initialize_configs.sh)"
    echo "  2. Re-run audit/artifact_verification on a fresh checkout to confirm"
    echo "  3. Announce program IDs publicly"
else
    echo "⚠️  DEPLOY COMPLETE WITHOUT TRANSFER — manifest at $MANIFEST"
    echo "⚠️  Upgrade authority is still the deployer hot key for at least"
    echo "    one program. DO NOT announce program IDs until the authority"
    echo "    is transferred to a Squads vault. Re-run with --squads-vault."
fi
