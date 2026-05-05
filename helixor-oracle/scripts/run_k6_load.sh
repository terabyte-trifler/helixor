#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-api}"

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 is not installed. Install with: brew install k6" >&2
  exit 127
fi

case "$TARGET" in
  api)
    k6 run load/k6/api_load.js
    ;;
  webhook)
    k6 run load/k6/webhook_load.js
    ;;
  all)
    k6 run load/k6/api_load.js
    k6 run load/k6/webhook_load.js
    ;;
  *)
    echo "Usage: $0 [api|webhook|all]" >&2
    exit 2
    ;;
esac
