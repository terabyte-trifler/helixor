"""
oracle/library_verification.py — TA-4: cryptography-library runtime
verification.

THE TRUST ASSUMPTION (audit)
-----------------------------
    "Python cryptography library is uncompromised — no verification."

The supply-chain audit (`audit/supply_chain_check.py`) already enforces
that `requirements.in` exact-pins every direct dependency, and the
release script (`scripts/regen_requirements.sh`) generates a
hash-locked `requirements.txt`. Production deploys MUST use
`pip install --require-hashes -r requirements.txt` — but if a
deployer skips that flag, today nothing fails loudly at runtime.

This file resolves that gap. `verify_library_versions()` is called once,
at oracle / API process startup, and:

  1. Reads the pinned versions from the manifest constant
     `EXPECTED_LIBRARY_VERSIONS` (mirrored from `requirements.in`).
  2. Reads the INSTALLED version of each library via
     `importlib.metadata.version()`.
  3. Raises `LibraryVerificationError` if any version mismatches.

A process that boots with a non-pinned crypto library exits before
opening a network port — the divergence is loud, not silent.

UPDATING THE PIN
----------------
When `requirements.in` is bumped, `EXPECTED_LIBRARY_VERSIONS` MUST be
bumped in the same commit. The TA-4 audit gate
(`audit/trust_assumption_check.py`) verifies the two stay in lockstep.
"""

from __future__ import annotations

import importlib.metadata
from collections.abc import Mapping
from dataclasses import dataclass


# =============================================================================
# THE PIN — mirrored from helixor-oracle/requirements.in
# =============================================================================
#
# The mapping is intentionally narrow: only the security-critical and
# native-code packages, where a silent version drift is the dangerous
# case. Pure-Python utilities are covered by --require-hashes alone;
# loud-runtime-mismatch coverage focuses on the bytes a compromise hits
# first.

EXPECTED_LIBRARY_VERSIONS: Mapping[str, str] = {
    # Ed25519 signing — single most security-critical dep.
    "cryptography": "48.0.0",
    # Solana RPC client.
    "solana":       "0.36.12",
    # Rust-backed native extension (compiled bytes run on import).
    "solders":      "0.27.1",
    # gRPC transport — native + protocol-critical.
    "grpcio":       "1.80.0",
    "protobuf":     "7.35.0",
    # TimescaleDB driver — native + DB-credential-handling.
    "asyncpg":      "0.30.0",
}


# =============================================================================
# Errors + report
# =============================================================================

class LibraryVerificationError(RuntimeError):
    """
    Raised when an installed library version does not match the TA-4
    manifest. The deploy is refused — re-install with
    `pip install --require-hashes -r requirements.txt`.
    """


@dataclass(frozen=True, slots=True)
class LibraryVerificationReport:
    """Per-library check outcome, for observability + tests."""
    library:           str
    expected_version:  str
    installed_version: str

    @property
    def matches(self) -> bool:
        return self.expected_version == self.installed_version


# =============================================================================
# verify_library_versions — startup-time gate
# =============================================================================

def verify_library_versions(
    *,
    manifest: Mapping[str, str] | None = None,
    version_lookup: "callable[[str], str] | None" = None,
) -> tuple[LibraryVerificationReport, ...]:
    """
    Verify installed crypto / native library versions against the TA-4
    manifest. Returns the per-library report tuple on success; raises
    `LibraryVerificationError` on any mismatch.

    `manifest` defaults to `EXPECTED_LIBRARY_VERSIONS`; tests inject a
    small manifest. `version_lookup` defaults to
    `importlib.metadata.version`; tests inject a deterministic map.
    """
    pinned = manifest if manifest is not None else EXPECTED_LIBRARY_VERSIONS
    lookup = version_lookup or importlib.metadata.version

    reports: list[LibraryVerificationReport] = []
    mismatches: list[LibraryVerificationReport] = []

    for lib, expected in pinned.items():
        try:
            installed = lookup(lib)
        except importlib.metadata.PackageNotFoundError:
            raise LibraryVerificationError(
                f"TA-4: required library {lib!r} (pin {expected}) is NOT "
                f"installed — refusing to start. Re-run pip install with "
                f"--require-hashes.",
            ) from None

        report = LibraryVerificationReport(
            library=lib,
            expected_version=expected,
            installed_version=installed,
        )
        reports.append(report)
        if not report.matches:
            mismatches.append(report)

    if mismatches:
        rendered = ", ".join(
            f"{r.library}: pin={r.expected_version} installed={r.installed_version}"
            for r in mismatches
        )
        raise LibraryVerificationError(
            f"TA-4: {len(mismatches)} library version(s) drifted from the "
            f"TA-4 manifest — refusing to start. Re-install with "
            f"`pip install --require-hashes -r requirements.txt`. "
            f"Mismatches: [{rendered}].",
        )

    return tuple(reports)


__all__ = [
    "EXPECTED_LIBRARY_VERSIONS",
    "LibraryVerificationError",
    "LibraryVerificationReport",
    "verify_library_versions",
]
