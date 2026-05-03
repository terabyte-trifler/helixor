#!/usr/bin/env bash
# =============================================================================
# Manual end-to-end test for Day 4
#
# Simulates a Helius webhook POST against a running indexer.
# Useful before exposing the URL to real Helius webhooks.
#
# Usage: bash scripts/test_webhook_manually.sh
# =============================================================================

set -euo pipefail

BASE_URL=${HELIXOR_BASE_URL:-http://localhost:8000}
: "${HELIUS_WEBHOOK_AUTH_TOKEN:?Set HELIUS_WEBHOOK_AUTH_TOKEN before running this script}"
AUTH_TOKEN=$HELIUS_WEBHOOK_AUTH_TOKEN

echo "Testing webhook endpoint at: $BASE_URL"

# 1. Health check
echo ""
echo "→ GET /health"
curl -sf "$BASE_URL/health" && echo " ✓"

# 2. Auth required check
echo ""
echo "→ POST /webhook (no auth — expecting 401)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/webhook" \
    -H "Content-Type: application/json" -d '[]')
[[ "$STATUS" == "401" ]] && echo "  ✓ 401 as expected" || { echo "  ✗ got $STATUS"; exit 1; }

# 3. Empty array
echo ""
echo "→ POST /webhook (empty array, valid auth)"
curl -sf -X POST "$BASE_URL/webhook" \
    -H "Authorization: $AUTH_TOKEN" \
    -H "Content-Type: application/json" -d '[]' | python3 -m json.tool

# 4. Insert a real-looking tx (will be skipped — agent not registered)
echo ""
echo "→ POST /webhook (1 tx, unknown agent — expect inserted=0, skipped=1)"
NOW=$(date +%s)
PAYLOAD=$(cat <<EOF
[{
    "signature": "TEST$(date +%s%N | head -c 40)",
    "slot":      265000000,
    "timestamp": $NOW,
    "type":      "TRANSFER",
    "feePayer":  "FAKEAGENTwalletXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "fee":       5000,
    "instructions": [{"programId": "11111111111111111111111111111111"}],
    "accountData":  [{"account": "FAKEAGENTwalletXXXXXXXXXXXXXXXXXXXXXXXXXX", "nativeBalanceChange": -5000}]
}]
EOF
)

curl -sf -X POST "$BASE_URL/webhook" \
    -H "Authorization: $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" | python3 -m json.tool

# 5. Status
echo ""
echo "→ GET /status"
curl -sf "$BASE_URL/status" | python3 -m json.tool

echo ""
echo "Manual webhook test complete."
echo "If everything returned 200, the webhook receiver is working."
echo ""
echo "To test end-to-end with a registered agent:"
echo "  1. Register an agent on-chain (Day 2's register_agent)"
echo "  2. Wait for agent_sync to pick it up (~30s)"
echo "  3. Send a real transaction from that agent"
echo "  4. Within 5s, query: SELECT * FROM agent_transactions ORDER BY id DESC LIMIT 1;"
