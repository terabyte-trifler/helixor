"""
tests/oracle/test_hcr3_state_isolation.py — HCR-3 state-isolation tests.

Pins:
  - Constants: every signing-path module is named explicitly; every
    forbidden import is named explicitly.
  - Clean source -> isolated report.
  - One forbidden import -> SharedStateDependencyError with offender.
  - Multiple violations are all reported in one pass.
  - Missing signing-path module is itself a HARD finding.
  - Import inside a docstring / comment is NOT a violation.
  - The live oracle tree is currently isolated (the gate's reason
    for existing — a regression here means a real one).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from oracle.state_isolation import (
    SHARED_STATE_FORBIDDEN_IMPORTS,
    SIGNING_PATH_MODULES,
    SharedStateDependencyError,
    _filesystem_source_lookup,
    verify_signing_path_isolation,
)


REPO_ROOT = Path(__file__).resolve().parents[2].parent


# ----------------------------------------------------------------------------
# Constants — the contract is on the constants
# ----------------------------------------------------------------------------

def test_cluster_signing_modules_are_in_the_set():
    # The trust-bearing modules MUST be in the contract; if a future
    # refactor renames one without updating SIGNING_PATH_MODULES, the
    # gate would silently stop checking it. Pin the load-bearing names.
    for name in (
        "oracle.cluster.signer",
        "oracle.cluster.aggregation",
        "oracle.cluster.cert_signing",
        "scoring.composite",
        "slashing.consensus",
    ):
        assert name in SIGNING_PATH_MODULES


def test_kafka_and_redis_are_forbidden():
    # These are the marquee shared-state clients; HCR-3 exists to refuse
    # them. Pin so a future "cleanup" cannot drop them from the list.
    for name in ("aiokafka", "confluent_kafka", "redis", "aioredis"):
        assert name in SHARED_STATE_FORBIDDEN_IMPORTS


# ----------------------------------------------------------------------------
# Clean-source happy path
# ----------------------------------------------------------------------------

def test_clean_signing_path_returns_isolated_report():
    clean = {
        "oracle.cluster.signer": (
            "from collections.abc import Sequence\n"
            "from oracle.cluster.messages import NodeMessage\n"
            "def sign(...): pass\n"
        ),
        "scoring.composite": (
            "from scoring.weights import Weights\n"
            "def compute_composite_score(...): pass\n"
        ),
    }
    report = verify_signing_path_isolation(
        clean.get,
        signing_path_modules=tuple(clean),
        forbidden_imports=("aiokafka", "redis"),
    )
    assert report.is_isolated
    assert set(report.checked_modules) == set(clean)
    assert report.violations == ()
    assert report.missing_modules == ()


# ----------------------------------------------------------------------------
# Forbidden-import failure modes
# ----------------------------------------------------------------------------

def test_aiokafka_import_in_signer_rejected():
    dirty = {
        "oracle.cluster.signer": (
            "import aiokafka\n"
            "def sign(...): pass\n"
        ),
    }
    with pytest.raises(SharedStateDependencyError, match="HCR-3") as excinfo:
        verify_signing_path_isolation(
            dirty.get,
            signing_path_modules=("oracle.cluster.signer",),
            forbidden_imports=("aiokafka",),
        )
    assert excinfo.value.report.violations == (
        ("oracle.cluster.signer", "aiokafka"),
    )


def test_from_redis_import_client_rejected():
    dirty = {
        "scoring.composite": "from redis import Redis\n",
    }
    with pytest.raises(SharedStateDependencyError) as excinfo:
        verify_signing_path_isolation(
            dirty.get,
            signing_path_modules=("scoring.composite",),
            forbidden_imports=("redis",),
        )
    assert excinfo.value.report.violations == (
        ("scoring.composite", "redis"),
    )


def test_multiple_violations_all_reported():
    dirty = {
        "oracle.cluster.signer":    "import aiokafka\n",
        "oracle.cluster.aggregation": "from redis import Redis\n",
    }
    with pytest.raises(SharedStateDependencyError) as excinfo:
        verify_signing_path_isolation(
            dirty.get,
            signing_path_modules=tuple(dirty),
            forbidden_imports=("aiokafka", "redis"),
        )
    violations = set(excinfo.value.report.violations)
    assert ("oracle.cluster.signer", "aiokafka") in violations
    assert ("oracle.cluster.aggregation", "redis") in violations


# ----------------------------------------------------------------------------
# Comment / docstring tolerance
# ----------------------------------------------------------------------------

def test_forbidden_name_in_comment_is_not_a_violation():
    # The point of the audit gate is to catch a real import, not the
    # word `aiokafka` in a docstring discussing what is NOT allowed.
    safe = {
        "oracle.cluster.signer": (
            '"""This module deliberately does NOT import aiokafka."""\n'
            "# import aiokafka  -- forbidden by HCR-3\n"
            "def sign(...): pass\n"
        ),
    }
    report = verify_signing_path_isolation(
        safe.get,
        signing_path_modules=tuple(safe),
        forbidden_imports=("aiokafka",),
    )
    assert report.is_isolated


# ----------------------------------------------------------------------------
# Missing-module failure
# ----------------------------------------------------------------------------

def test_missing_signing_path_module_is_hard_finding():
    # If a signing-path module disappears, the gate cannot prove
    # isolation; that's itself a HARD finding.
    with pytest.raises(SharedStateDependencyError) as excinfo:
        verify_signing_path_isolation(
            lambda _name: None,
            signing_path_modules=("oracle.cluster.signer",),
            forbidden_imports=("aiokafka",),
        )
    assert "oracle.cluster.signer" in excinfo.value.report.missing_modules


# ----------------------------------------------------------------------------
# The live oracle tree is currently isolated
# ----------------------------------------------------------------------------

def test_live_oracle_tree_is_isolated():
    lookup = _filesystem_source_lookup(REPO_ROOT)
    report = verify_signing_path_isolation(lookup)
    assert report.is_isolated, (
        "HCR-3 regression on the live tree:\n"
        + "\n".join(
            f"  {mod} -> {imp}" for mod, imp in report.violations
        ) + (
            "\nMissing modules: " + ", ".join(report.missing_modules)
            if report.missing_modules else ""
        )
    )
