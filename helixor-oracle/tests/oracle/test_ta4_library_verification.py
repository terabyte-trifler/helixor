"""
tests/oracle/test_ta4_library_verification.py — TA-4 runtime crypto-library
verification.

Pins:
  - The EXPECTED_LIBRARY_VERSIONS manifest stays in lockstep with
    requirements.in (cryptography, solana, solders, grpcio, protobuf,
    asyncpg).
  - verify_library_versions() raises LibraryVerificationError on a
    version drift.
  - Missing package raises LibraryVerificationError (not a silent skip).
  - Happy path: matching versions return per-library reports.
"""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import pytest

from oracle.library_verification import (
    EXPECTED_LIBRARY_VERSIONS,
    LibraryVerificationError,
    LibraryVerificationReport,
    verify_library_versions,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
REQUIREMENTS_IN = REPO_ROOT / "helixor-oracle" / "requirements.in"


# ----------------------------------------------------------------------------
# Manifest stays in lockstep with requirements.in
# ----------------------------------------------------------------------------

def _parse_requirements_in() -> dict[str, str]:
    pinned: dict[str, str] = {}
    pin_re = re.compile(r"^([A-Za-z0-9._\-]+)==([A-Za-z0-9._\-+]+)\s*$")
    for line in REQUIREMENTS_IN.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = pin_re.match(stripped)
        if m:
            pinned[m.group(1).lower()] = m.group(2)
    return pinned


def test_manifest_pins_subset_of_requirements_in():
    """
    Every library in the TA-4 manifest must appear in requirements.in
    with the same pinned version. The manifest is the security-critical
    subset; requirements.in is the full direct-dep surface.
    """
    pinned_in_file = _parse_requirements_in()
    for lib, version in EXPECTED_LIBRARY_VERSIONS.items():
        assert lib.lower() in pinned_in_file, (
            f"manifest lists {lib} but requirements.in does not pin it"
        )
        assert pinned_in_file[lib.lower()] == version, (
            f"manifest pins {lib}=={version} but requirements.in pins "
            f"{lib}=={pinned_in_file[lib.lower()]} — they MUST agree."
        )


def test_manifest_covers_security_critical_libs():
    """
    The TA-4 manifest MUST include cryptography (Ed25519 signing) and the
    native-code packages (solders, grpcio, protobuf, asyncpg). These are
    the libraries where a silent version drift is dangerous; pure-Python
    utilities are covered by --require-hashes alone.
    """
    must_cover = {"cryptography", "solana", "solders", "grpcio", "protobuf", "asyncpg"}
    assert set(EXPECTED_LIBRARY_VERSIONS.keys()) >= must_cover


# ----------------------------------------------------------------------------
# verify_library_versions — happy path
# ----------------------------------------------------------------------------

def test_verify_returns_report_per_lib_on_match():
    fake_manifest = {"libA": "1.2.3", "libB": "4.5.6"}
    versions = {"libA": "1.2.3", "libB": "4.5.6"}
    reports = verify_library_versions(
        manifest=fake_manifest,
        version_lookup=versions.__getitem__,
    )
    assert len(reports) == 2
    assert all(r.matches for r in reports)
    assert {r.library for r in reports} == {"libA", "libB"}


# ----------------------------------------------------------------------------
# verify_library_versions — drift detection
# ----------------------------------------------------------------------------

def test_verify_raises_on_single_drift():
    fake_manifest = {"libA": "1.0.0"}
    versions = {"libA": "1.0.1"}
    with pytest.raises(LibraryVerificationError) as excinfo:
        verify_library_versions(
            manifest=fake_manifest, version_lookup=versions.__getitem__,
        )
    msg = str(excinfo.value)
    assert "TA-4" in msg
    assert "libA" in msg
    assert "1.0.0" in msg
    assert "1.0.1" in msg


def test_verify_raises_on_missing_package():
    fake_manifest = {"libA": "1.0.0"}

    def lookup(name):
        raise importlib.metadata.PackageNotFoundError(name)

    with pytest.raises(LibraryVerificationError) as excinfo:
        verify_library_versions(manifest=fake_manifest, version_lookup=lookup)
    assert "NOT" in str(excinfo.value)
    assert "libA" in str(excinfo.value)


def test_verify_reports_all_drifts_in_one_error():
    fake_manifest = {"libA": "1.0.0", "libB": "2.0.0", "libC": "3.0.0"}
    versions = {"libA": "1.0.0", "libB": "2.0.1", "libC": "3.0.99"}
    with pytest.raises(LibraryVerificationError) as excinfo:
        verify_library_versions(
            manifest=fake_manifest, version_lookup=versions.__getitem__,
        )
    msg = str(excinfo.value)
    assert "libB" in msg
    assert "libC" in msg
    assert "libA" not in msg  # matched, not reported


# ----------------------------------------------------------------------------
# Live verification against the actual installed environment
# ----------------------------------------------------------------------------

def test_live_verification_against_installed_environment():
    """
    For every library in the TA-4 manifest that IS installed in the
    current environment, the version MUST match the pin. Missing
    libraries are tolerated here (CI venvs do not install asyncpg, which
    is production-only) — the production-runtime call to
    verify_library_versions() WILL raise on a missing package.

    This is the test that catches "someone bumped requirements.in but
    forgot the manifest" AND vice-versa.
    """
    for lib, expected in EXPECTED_LIBRARY_VERSIONS.items():
        try:
            installed = importlib.metadata.version(lib)
        except importlib.metadata.PackageNotFoundError:
            continue  # not installed in this test env; OK
        assert installed == expected, (
            f"{lib} installed=={installed} but manifest pins {expected}"
        )


def test_library_verification_report_matches_predicate():
    r = LibraryVerificationReport(
        library="x", expected_version="1.0", installed_version="1.0",
    )
    assert r.matches
    r2 = LibraryVerificationReport(
        library="x", expected_version="1.0", installed_version="1.1",
    )
    assert not r2.matches
