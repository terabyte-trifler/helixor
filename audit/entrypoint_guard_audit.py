#!/usr/bin/env python3
"""
audit/entrypoint_guard_audit.py — verify every Helixor entrypoint
imports the network guard.

Day 30 — the mainnet refusal gate is only useful if every entrypoint
ACTUALLY uses it. A new service added later that forgets to call
`enforce_network_guard` would be a silent regression — the kind of bug
an external auditor would otherwise have to spot manually.

This auditor enumerates entrypoint files (any Python file with
`if __name__ == "__main__"` or a `def main()` that's invoked from
`__main__`), and asserts each one calls `enforce_network_guard`.

Allow-listed entrypoints are documented inline (test harnesses,
build-time scripts, anything that should not need the guard).

Run from the repo root:
    python3 audit/entrypoint_guard_audit.py
Exits 0 if clean, 1 if any entrypoint is missing the guard.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# Where to look
# ─────────────────────────────────────────────────────────────────────────────

SEARCH_ROOTS = [
    REPO_ROOT / "helixor-oracle",
    REPO_ROOT / "helixor-indexer",
    REPO_ROOT / "helixor-api",
]

# Allow-listed entrypoint paths — the guard does not need to fire here.
# Each entry is justified inline.
ALLOWLIST = {
    # Test harness — never starts the service, only exercises the code.
    "tests": "test file",
    # Examples / one-shot tools that are explicitly local-only.
    "examples": "example script",
    # The audit hub itself.
    "audit": "audit script — does not start a service",
    # Proto codegen helpers.
    "proto/generate.py": "build-time script",
    # The mainnet-refusal module itself (would be circular).
    "network_guard.py": "the guard itself",
}


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint detection
# ─────────────────────────────────────────────────────────────────────────────

def looks_like_entrypoint(text: str) -> bool:
    """True if a file looks like a service entrypoint."""
    return 'if __name__ == "__main__"' in text or "if __name__ == '__main__'" in text


def has_guard_call(text: str) -> bool:
    """True if the file imports the guard and calls enforce_network_guard."""
    return (
        "enforce_network_guard" in text
        or "from oracle.network_guard" in text
        or "network_guard.enforce" in text
    )


def is_allowlisted(rel_path: str) -> str | None:
    for fragment, reason in ALLOWLIST.items():
        if fragment in rel_path:
            return reason
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    findings: list[tuple[str, str]] = []
    entrypoints_found: list[str] = []

    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            text = path.read_text()
            if not looks_like_entrypoint(text):
                continue
            rel = str(path.relative_to(REPO_ROOT))
            allow_reason = is_allowlisted(rel)
            if allow_reason is not None:
                continue
            entrypoints_found.append(rel)
            if not has_guard_call(text):
                findings.append((
                    rel,
                    "entrypoint does not call enforce_network_guard()",
                ))

    print("\n=== ENTRYPOINT GUARD AUDIT — Day 30 ===\n")
    if entrypoints_found:
        print("Entrypoints checked:")
        for rel in entrypoints_found:
            ok = not any(f[0] == rel for f in findings)
            print(f"  {'✅' if ok else '❌'}  {rel}")
    else:
        print("(no entrypoints found — adjust SEARCH_ROOTS or ALLOWLIST)")
    print()
    if findings:
        print(f"❌ {len(findings)} entrypoint(s) missing the network guard:")
        for path, msg in findings:
            print(f"  {path}: {msg}")
        print()
        print("Add at the top of the entrypoint's main():")
        print()
        print("    from oracle.network_guard import enforce_network_guard")
        print("    enforce_network_guard(service='<name>')")
        return 1
    print(f"✅ CLEAN — {len(entrypoints_found)} entrypoint(s), all guarded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
