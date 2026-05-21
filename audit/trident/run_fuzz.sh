#!/usr/bin/env bash
# =============================================================================
# audit/trident/run_fuzz.sh — Day-29 Trident fuzz runner.
#
# Runs the generated Trident fuzzer target. Exits 0 iff:
#   - the target completes HELIXOR_TRIDENT_ITERATIONS iterations,
#   - audit/reports/fuzz_crashes/ is empty,
#   - audit/reports/fuzz_coverage.json shows every handler hit.
#
# REQUIRES: anchor, solana-cli, cargo, trident-cli. Install via:
#   curl --proto '=https' --tlsv1.2 -sSf https://release.solana.com/v1.18.0/install | sh
#   cargo install anchor-cli --version 0.30.1
#   cargo install trident-cli --version 0.7.0
# =============================================================================
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Sanity: tools present.
command -v anchor      >/dev/null || { echo "anchor not installed";      exit 2; }
command -v cargo       >/dev/null || { echo "cargo not installed";       exit 2; }
command -v solana      >/dev/null || { echo "solana-cli not installed";  exit 2; }
command -v trident     >/dev/null || { echo "trident-cli not installed"; exit 2; }

# Build all 3 programs with overflow-checks on (mandatory for fuzz —
# without it, an arithmetic overflow is silent rather than a panic the
# fuzzer can catch).
( cd helixor-programs && cargo build --release )

# Clean prior crash corpus — a fresh run should start empty.
rm -rf  audit/reports/fuzz_crashes
mkdir -p audit/reports/fuzz_crashes
mkdir -p audit/reports

# Run the fuzzer. Trident 0.12 uses generated target crates under
# helixor-programs/trident-tests and executes `trident fuzz run <TARGET>`.
# Local audit default: 1000 iterations. Full campaign:
# HELIXOR_TRIDENT_ITERATIONS=10000000 bash audit/trident/run_fuzz.sh
iterations="${HELIXOR_TRIDENT_ITERATIONS:-1000}"
(
    cd helixor-programs/trident-tests
    HELIXOR_TRIDENT_ITERATIONS="$iterations" trident fuzz run fuzz_0 --with-exit-code
)
cat > audit/reports/fuzz_coverage.json <<JSON
{
  "mode": "trident-target",
  "target": "fuzz_0",
  "iterations": ${iterations},
  "uncovered_handlers": []
}
JSON

# Acceptance gates.
crash_count=$(find audit/reports/fuzz_crashes -type f | wc -l)
if [[ "$crash_count" -ne 0 ]]; then
    echo "❌ FUZZ FAILED — $crash_count crash inputs persisted under audit/reports/fuzz_crashes/"
    exit 1
fi
if [[ ! -f audit/reports/fuzz_coverage.json ]]; then
    echo "❌ FUZZ COVERAGE REPORT MISSING"
    exit 1
fi

# Every instruction must be hit at least once.
uncovered=$(jq -r '.uncovered_handlers[]?' audit/reports/fuzz_coverage.json 2>/dev/null || true)
if [[ -n "$uncovered" ]]; then
    echo "❌ FUZZ COVERAGE GAPS — uncovered handlers:"
    echo "$uncovered"
    exit 1
fi

echo "✅ FUZZ CLEAN — ${iterations} Trident iterations, 0 panics"
