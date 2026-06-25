"""
oracle/state_isolation.py — HCR-3: signing-path shared-state isolation.

THE HIDDEN CENTRALIZATION RISK (audit)
--------------------------------------
    "If all oracle nodes share a single Kafka/Redis instance, it
    becomes a SPOF and a high-value attack target."

The cluster's THRESHOLD-SIGNING path — composite scoring, per-node
verdict signing, cross-node aggregation, on-chain commit — is the
trust-bearing layer. It is determinism-critical (TA-3) and must
produce byte-identical outputs across cluster members.

The audit's concern is that if that path takes a transitive
dependency on shared infrastructure (Kafka, Redis, memcached), then
the SHARED INSTANCE becomes:

  1. A SPOF — one bus outage halts every cluster member's signing
     path simultaneously, breaking liveness even though the per-node
     keys are independent.
  2. A high-value attack target — corrupting one Kafka cluster's
     contents corrupts every cluster member's input identically, and
     the "we have 5 independent operators" defense collapses because
     they're all reading from the same poisoned topic.

THE MITIGATION (this file)
--------------------------
The oracle codebase is structured so that ALL shared-bus traffic
crosses ONE bridge: `oracle/cluster/kafka_ingest.py`. The bridge
consumes from an injected `Broker` interface (in-memory or
confluent-adapter) and emits structured `AgentEpochInput` objects
into the cluster's signing pipeline. Everything downstream of the
bridge is PURE — it operates only on those structured inputs.

HCR-3 is the enforcement that this layering does NOT regress. The
constant `SIGNING_PATH_MODULES` enumerates every Python module in the
trust-bearing path; `SHARED_STATE_FORBIDDEN_IMPORTS` enumerates the
client libraries those modules MUST NOT import. The verifier
`verify_signing_path_isolation()` walks the source of each
signing-path module and refuses if any forbidden import is found.

Two call sites:

  * `audit/centralization_check.py` greps the source at CI time.
  * The oracle node's boot sequence (future hook) can call
    `verify_signing_path_isolation(_default_lookup)` to fail-closed
    at startup.

The check is INTENTIONALLY shallow — it greps for top-level imports.
A determined patch could obfuscate the import (e.g. via
`importlib`) but that level of obfuscation is itself a review
trigger; HCR-3's job is to catch the accidental regression where a
contributor adds `import aiokafka` to `cluster/signer.py` because
"the bus has a thing I need."

DETERMINISM
-----------
Pure stdlib. The source lookup is injected so the check is fully
testable without touching the filesystem. Two operators given the
same module sources produce the same report.

INTERACTION WITH SPOF-#5
------------------------
SPOF-#5 closed the SHARED-INFRA-DOWN risk by making Kafka itself an
HA cluster (3 brokers, RF=3, min.insync=2). HCR-3 is the COMPLEMENT:
even with an HA bus, the cluster's signing path MUST NOT transitively
trust the bus's contents. The two gates together mean: (a) the bus
survives a one-broker loss (SPOF-#5), AND (b) a bus-content
compromise cannot reach the signing path (HCR-3).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass


# =============================================================================
# The contract: who's in the signing path and what they may NOT import
# =============================================================================
#
# The signing-path set is the source of truth for HCR-3. Adding a module
# to this set is a deliberate act — that module is now in the trust path
# and any shared-infra import in it MUST be refused.

SIGNING_PATH_MODULES: tuple[str, ...] = (
    # On-chain commit + score-submission helpers (the trust boundary).
    "oracle.commit_baseline",
    "oracle.epoch_runner",
    # Cluster threshold-signing path.
    "oracle.cluster.aggregation",
    "oracle.cluster.cert_signing",
    "oracle.cluster.cluster_runner",
    "oracle.cluster.commit_reveal_round",
    "oracle.cluster.commit_reveal_runner",
    "oracle.cluster.pipeline",
    "oracle.cluster.signer",
    "oracle.cluster.source_attestation",
    # The verdict pipeline + slashing detector (per-node trust-bearing).
    "slashing.consensus",
    "slashing.divergence",
    # Determinism-critical scoring kernel.
    "scoring.composite",
)


#: Client libraries the signing path MUST NOT depend on. The list is
#: intentionally conservative — protocol buses (Kafka, Redis,
#: memcached, NATS) plus their async wrappers. A signing-path module
#: that needs to read from a bus must do so VIA the injected
#: `Broker` interface in `oracle/cluster/kafka_ingest.py`, never by
#: importing the bus client directly.
SHARED_STATE_FORBIDDEN_IMPORTS: tuple[str, ...] = (
    "aiokafka",
    "kafka",
    "confluent_kafka",
    "redis",
    "aioredis",
    "memcache",
    "pymemcache",
    "nats",
    "asyncpg",   # the DB is shared infra; signing must not need it
    "psycopg2",
    "psycopg",
    "sqlalchemy",
)


# Pre-compiled patterns for the source-grep. Matched at top-of-line so
# that a string literal mentioning `aiokafka` inside a comment / docstring
# does NOT trigger.
_IMPORT_RE = re.compile(
    r"^(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)


# =============================================================================
# Errors / report
# =============================================================================

class SharedStateDependencyError(RuntimeError):
    """
    Raised when a signing-path module imports a forbidden shared-state
    client library. The `.report` attribute carries every offending
    (module, import) pair so the operator can fix the regression in
    one pass.
    """

    def __init__(self, message: str, report: "StateIsolationReport"):
        super().__init__(message)
        self.report = report


@dataclass(frozen=True, slots=True)
class StateIsolationReport:
    """
    One run of the HCR-3 check.

    `checked_modules`   modules whose source was inspected.
    `missing_modules`   modules in the signing-path set whose source
                        could not be resolved (treated as a HARD
                        finding — a signing-path module that has
                        disappeared is itself a regression).
    `violations`        every (module, forbidden_import) found in the
                        signing-path sources.
    """
    checked_modules:  tuple[str, ...]
    missing_modules:  tuple[str, ...]
    violations:       tuple[tuple[str, str], ...]

    @property
    def is_isolated(self) -> bool:
        return not self.violations and not self.missing_modules


# =============================================================================
# The verifier
# =============================================================================

def verify_signing_path_isolation(
    source_lookup: Callable[[str], str | None],
    *,
    signing_path_modules: Iterable[str] = SIGNING_PATH_MODULES,
    forbidden_imports:    Iterable[str] = SHARED_STATE_FORBIDDEN_IMPORTS,
) -> StateIsolationReport:
    """
    Verify that every signing-path module's source contains no
    top-level import of a forbidden shared-state client.

    Parameters
    ----------
    source_lookup
        `name -> str | None`. Returns the source code of the named
        module, or None if the module cannot be located. The CI gate
        passes a filesystem-backed lookup; tests pass a dict-backed
        lookup.

    Raises
    ------
    SharedStateDependencyError
        On any forbidden import, OR any signing-path module whose
        source cannot be located. The report is attached so the
        operator can see every offender in one pass.
    """
    checked: list[str] = []
    missing: list[str] = []
    violations: list[tuple[str, str]] = []
    forbidden_set = frozenset(forbidden_imports)

    for module in signing_path_modules:
        src = source_lookup(module)
        if src is None:
            missing.append(module)
            continue
        checked.append(module)
        for match in _IMPORT_RE.finditer(src):
            top_name = match.group(1)
            if top_name in forbidden_set:
                violations.append((module, top_name))

    report = StateIsolationReport(
        checked_modules=tuple(checked),
        missing_modules=tuple(missing),
        violations=tuple(violations),
    )

    if not report.is_isolated:
        bits = []
        if violations:
            bits.append(
                "forbidden shared-state imports in the signing path: "
                + ", ".join(f"{m} -> {i}" for m, i in violations)
            )
        if missing:
            bits.append(
                "signing-path modules whose source could not be located: "
                + ", ".join(missing)
            )
        raise SharedStateDependencyError(
            "HCR-3: " + "; ".join(bits) + ". The signing path must take "
            "shared-bus inputs ONLY via the injected Broker interface in "
            "oracle/cluster/kafka_ingest.py — a direct client import in a "
            "trust-bearing module is the HCR-3 failure mode.",
            report,
        )
    return report


# =============================================================================
# Filesystem-backed default lookup
# =============================================================================

def _filesystem_source_lookup(repo_root) -> Callable[[str], str | None]:
    """
    Build a source_lookup that resolves `oracle.cluster.signer` to
    `<repo>/phylanx-oracle/oracle/cluster/signer.py` and reads it.

    Lives in this file so the audit gate can use it without
    re-implementing the path math.
    """
    from pathlib import Path

    root = Path(repo_root) / "phylanx-oracle"

    def lookup(name: str) -> str | None:
        rel = Path(*name.split(".")).with_suffix(".py")
        path = root / rel
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

    return lookup


__all__ = [
    "SIGNING_PATH_MODULES",
    "SHARED_STATE_FORBIDDEN_IMPORTS",
    "SharedStateDependencyError",
    "StateIsolationReport",
    "verify_signing_path_isolation",
    "_filesystem_source_lookup",
]
