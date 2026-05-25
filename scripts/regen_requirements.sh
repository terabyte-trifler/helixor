#!/usr/bin/env bash
# =============================================================================
# scripts/regen_requirements.sh — VULN-25 hash-locked requirements regen.
#
# Reads every `helixor-*/requirements.in` and emits the corresponding
# `helixor-*/requirements.txt` with full transitive closures and SHA256
# hashes for every package via `pip-compile --generate-hashes`.
#
# Production deploys MUST install with `pip install --require-hashes -r
# helixor-<pkg>/requirements.txt` so a hash drift (compromised mirror,
# MITM, registered ghost version) trips before any code is imported.
#
# This script is run by humans, not by CI — committing the regenerated
# .txt files is part of the dependency-upgrade PR. CI (and the audit
# scanner) only verify the files are PRESENT and use the hash syntax.
#
# Requires `pip-tools`:   pip install pip-tools
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v pip-compile >/dev/null; then
    echo "❌ pip-compile not found. Install with: pip install pip-tools" >&2
    exit 1
fi

for pkg in helixor-oracle helixor-api helixor-indexer; do
    if [[ ! -f "$pkg/requirements.in" ]]; then
        echo "⊘  $pkg/requirements.in missing, skipping" >&2
        continue
    fi
    echo "── $pkg ──"
    # --generate-hashes:  every line gets --hash=sha256:...
    # --resolver=backtracking: matches pip's default; deterministic.
    # --no-emit-index-url: don't bake the dev mirror into the committed file.
    # --no-strip-extras:   preserve `pkg[extra]` form (e.g. psycopg[binary]).
    pip-compile \
        --generate-hashes \
        --resolver=backtracking \
        --no-emit-index-url \
        --no-strip-extras \
        --output-file "$pkg/requirements.txt" \
        "$pkg/requirements.in"
done

echo
echo "✅ regenerated. Commit BOTH the .in and the .txt files."
echo "   Then production deploys run:"
echo "     pip install --require-hashes -r <pkg>/requirements.txt"
