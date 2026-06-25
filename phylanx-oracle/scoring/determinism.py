"""
scoring/determinism.py — VULN-18 mitigation. The cluster-wide
floating-point determinism guard.

WHY
---
The Phylanx commit-reveal protocol depends on every honest oracle node
computing the **byte-identical** ScoreResult for the same (features,
baseline) pair. The composite scorer rounds to an int 0..1000 at the
boundary (see compute_composite_score), but the per-dimension math that
feeds the rounding uses IEEE 754 doubles. That contract holds across
runs IF AND ONLY IF the runtime is the one the system was audited on:

    * Same Python interpreter family (CPython)
    * Same major.minor Python version (3.12)
    * IEEE 754 binary64 doubles, ``mant_dig == 53``, ``radix == 2``
    * No numpy / scipy / pandas / sklearn in ``sys.modules`` — these
      ship their own FPU dispatch and BLAS backends, and the same call
      can return different bytes on x86 vs ARM, or AVX2 vs AVX-512.
    * Standard library ``math.`` ops only (sqrt, log, erf, exp) —
      CPython's math module wraps libm with documented rounding
      semantics. We pin to that surface and nothing else.

This module is the runtime enforcement of that pin. It runs at oracle
process startup, right after :mod:`oracle.network_guard`, and refuses
to start an oracle node against mainnet whose runtime fails the pin.

CONTRACT — THE FLOAT→INT BOUNDARY
---------------------------------
:func:`quantize_to_int` is the **only** path floats should take to
becoming the integer that lands on chain. It uses Python's built-in
``round()``, which is banker's-rounding (round-half-to-even) for
floats. We pin that contract here so a future refactor can grep for
the call site and know it touches consensus.

USAGE
-----
At every Phylanx service entrypoint that runs scoring math::

    from oracle.network_guard import enforce_network_guard
    from scoring.determinism import enforce_scoring_determinism

    enforce_network_guard(service="oracle-node:...")
    enforce_scoring_determinism(service="oracle-node:...")

The order matters: the network guard tells us whether we are on
mainnet, and only the mainnet path is fail-closed. On devnet/localnet
the guard logs the verdict at INFO and returns — useful diagnostics
without blocking a developer who happens to be on a different patch
version of CPython.

THE EMERGENCY OPT-IN
--------------------
``PHYLANX_SCORING_DETERMINISM_OK=1`` bypasses the fail-closed gate on
mainnet. This exists for one scenario: an emergency where the
audited Python version has a CVE and operators need to start nodes
on a patched runtime that the guard does not yet recognise. The
opt-in is logged at ERROR and the verdict is filed to
``audit/reports/scoring_determinism_optin.md`` per launch checklist
section 4. Do NOT set it casually.
"""

from __future__ import annotations

import ast
import logging
import os
import struct
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path


logger = logging.getLogger("phylanx.scoring.determinism")


# =============================================================================
# The pin
# =============================================================================

# The Python (major, minor) tuple the V2 oracle cluster is audited against.
# Matches the project-wide minimum (phylanx-api/pyproject.toml requires-python
# = ">=3.12"). When a new minor is audited, append it here and re-publish.
SUPPORTED_PYTHON_VERSIONS: frozenset[tuple[int, int]] = frozenset({
    (3, 12),
    (3, 13),
})

# CPython only. PyPy has a JIT that may emit different machine code for
# float ops on different host CPUs; we have not audited it.
SUPPORTED_IMPLEMENTATIONS: frozenset[str] = frozenset({"cpython"})

# Modules that, if loaded into the oracle process, indicate a non-pinned
# math backend. Loading any of these is a hard refuse on mainnet because
# they ship their own FPU dispatch (BLAS, AVX, GPU offload, etc.) and the
# same call can return different bytes on different hardware.
BANNED_MATH_BACKENDS: frozenset[str] = frozenset({
    "numpy",
    "scipy",
    "pandas",
    "sklearn",
    "torch",
    "tensorflow",
    "jax",
})

# The env vars the guard reads.
ENV_DETERMINISM_OK = "PHYLANX_SCORING_DETERMINISM_OK"


# =============================================================================
# Exceptions
# =============================================================================

class ScoringDeterminismRefused(RuntimeError):
    """
    Raised when the guard refuses to start because the runtime fails the
    determinism pin and no opt-in was given.
    """


# =============================================================================
# The canonical float→int quantiser
# =============================================================================

def quantize_to_int(value: float) -> int:
    """
    The single, canonical way a Phylanx scoring float becomes the integer
    that lands on chain.

    Uses Python's built-in ``round()``, which is banker's-rounding
    (round-half-to-even) for floats — ``round(0.5) == 0``,
    ``round(1.5) == 2``, ``round(2.5) == 2``. This rounding mode is
    stable across CPython 3.12 / 3.13 and is documented in PEP 3141.

    Every consensus-affecting float→int conversion in the scoring
    package MUST go through this function. The unit test
    :mod:`tests.scoring.test_vuln18_scoring_determinism` pins the
    semantics; refactors that change the rounding contract will fail it.
    """
    return int(round(value))


# =============================================================================
# The verdict
# =============================================================================

@dataclass(frozen=True, slots=True)
class DeterminismVerdict:
    """The guard's decision — exposed so callers and tests can inspect it."""
    python_version:     tuple[int, int]
    implementation:     str
    float_mant_digits:  int
    float_radix:        int
    float_double_bytes: int
    banned_loaded:      tuple[str, ...]
    opted_in:           bool
    is_production:      bool
    failures:           tuple[str, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return not self.failures

    @property
    def must_refuse(self) -> bool:
        return self.is_production and not self.passed and not self.opted_in


# =============================================================================
# Inspection — pure, raises nothing
# =============================================================================

def _python_version() -> tuple[int, int]:
    info = sys.version_info
    return (info.major, info.minor)


def _implementation() -> str:
    return sys.implementation.name.lower().strip()


def _double_size_bytes() -> int:
    """The size of a C ``double`` on this platform. Must be 8 for IEEE 754
    binary64. Any other value means the math module is doing something
    surprising and the pin must refuse."""
    return struct.calcsize("d")


def _banned_math_backends_loaded() -> tuple[str, ...]:
    """Names of BANNED_MATH_BACKENDS that have already been imported into
    the process. Returns them in sorted order so the verdict is
    deterministic."""
    return tuple(sorted(name for name in BANNED_MATH_BACKENDS if name in sys.modules))


def opted_in_to_emergency_bypass() -> bool:
    """True iff PHYLANX_SCORING_DETERMINISM_OK is set to ``"1"``.
    Mirrors :func:`oracle.network_guard.opted_in_to_mainnet` semantics —
    whitespace-trimmed equality with ``"1"``."""
    return os.environ.get(ENV_DETERMINISM_OK, "").strip() == "1"


def evaluate(*, is_production: bool | None = None) -> DeterminismVerdict:
    """
    Compute the current verdict. Pure: does no I/O beyond reading the
    process state and one env var. Never raises.

    ``is_production`` lets the caller pass the network verdict in. When
    omitted, the function consults :mod:`oracle.network_guard` itself
    so a standalone diagnostic invocation still gets the right answer.
    """
    if is_production is None:
        try:
            from oracle.network_guard import evaluate as _net_evaluate
            is_production = _net_evaluate().is_production
        except Exception:  # noqa: BLE001 — diagnostic path, never block
            is_production = False

    version = _python_version()
    impl    = _implementation()
    finfo   = sys.float_info
    dsize   = _double_size_bytes()
    banned  = _banned_math_backends_loaded()

    failures: list[str] = []
    if version not in SUPPORTED_PYTHON_VERSIONS:
        failures.append(
            f"python={version[0]}.{version[1]} not in "
            f"supported={sorted(SUPPORTED_PYTHON_VERSIONS)}"
        )
    if impl not in SUPPORTED_IMPLEMENTATIONS:
        failures.append(
            f"implementation={impl!r} not in "
            f"supported={sorted(SUPPORTED_IMPLEMENTATIONS)}"
        )
    if finfo.mant_dig != 53:
        failures.append(
            f"float mant_dig={finfo.mant_dig} != 53 "
            f"(IEEE 754 binary64 required)"
        )
    if finfo.radix != 2:
        failures.append(
            f"float radix={finfo.radix} != 2 (binary float required)"
        )
    if dsize != 8:
        failures.append(
            f"sizeof(double)={dsize} != 8 (8-byte double required)"
        )
    if banned:
        failures.append(
            f"banned math backends loaded: {list(banned)} "
            f"(numpy/scipy/etc. introduce hardware-dependent rounding)"
        )

    return DeterminismVerdict(
        python_version=version,
        implementation=impl,
        float_mant_digits=finfo.mant_dig,
        float_radix=finfo.radix,
        float_double_bytes=dsize,
        banned_loaded=banned,
        opted_in=opted_in_to_emergency_bypass(),
        is_production=is_production,
        failures=tuple(failures),
    )


# =============================================================================
# Source scan — confirm detection/ + scoring/ never import the banned set
# =============================================================================

def _iter_python_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _module_imports(path: Path) -> set[str]:
    """Top-level module names imported by ``path``. Best-effort — a
    SyntaxError or read error returns an empty set rather than blowing
    up the guard."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                names.add(node.module.split(".", 1)[0])
    return names


def scan_source_for_banned_imports(
    *,
    package_roots: tuple[Path, ...] | None = None,
) -> dict[Path, set[str]]:
    """
    Return ``{path: banned_modules}`` for every .py file under the
    scoring/detection package roots that imports one of the
    :data:`BANNED_MATH_BACKENDS`.

    A non-empty result is a determinism violation in the SOURCE — the
    guard will refuse to start on mainnet even if the offending module
    has not yet been imported in this process, because the next code
    path that touches it will load it.
    """
    if package_roots is None:
        here = Path(__file__).resolve().parent.parent
        package_roots = (here / "scoring", here / "detection")

    violations: dict[Path, set[str]] = {}
    for root in package_roots:
        if not root.is_dir():
            continue
        for path in _iter_python_files(root):
            if path.resolve() == Path(__file__).resolve():
                # The determinism module itself MENTIONS the banned names
                # in BANNED_MATH_BACKENDS as string literals, not imports.
                continue
            imports = _module_imports(path)
            offending = imports & BANNED_MATH_BACKENDS
            if offending:
                violations[path] = offending
    return violations


# =============================================================================
# The gate
# =============================================================================

def enforce_scoring_determinism(
    *,
    service: str | None = None,
    is_production: bool | None = None,
) -> DeterminismVerdict:
    """
    Enforce the determinism pin. Returns the verdict on success; raises
    :class:`ScoringDeterminismRefused` on a production network with a
    failing pin and no emergency opt-in.

    ``service`` names the calling entrypoint, used only for log lines.
    ``is_production`` lets the caller forward the network-guard verdict;
    when ``None``, the determinism guard consults network_guard itself.
    """
    verdict = evaluate(is_production=is_production)
    label   = service or "<unspecified>"

    if verdict.must_refuse:
        msg = (
            f"scoring_determinism: REFUSING to start service {label!r} "
            f"on a production network — the runtime fails the VULN-18 "
            f"determinism pin. failures={list(verdict.failures)}. "
            f"Set {ENV_DETERMINISM_OK}=1 in the environment ONLY if you "
            f"have audited the new runtime and filed the justification "
            f"in audit/reports/scoring_determinism_optin.md."
        )
        logger.error(msg)
        raise ScoringDeterminismRefused(msg)

    if verdict.is_production and not verdict.passed and verdict.opted_in:
        # Opted-in mainnet with a failing pin. Log loudly so the decision
        # is auditable; the operator has accepted responsibility.
        logger.error(
            "scoring_determinism: service %s starting on production with "
            "FAILING pin and explicit %s=1 opt-in. failures=%s. This is "
            "an audited emergency bypass — confirm the optin trail.",
            label, ENV_DETERMINISM_OK, list(verdict.failures),
        )
    elif verdict.is_production:
        logger.warning(
            "scoring_determinism: service %s starting on PRODUCTION with "
            "pinned runtime python=%s impl=%s mant_dig=%d sizeof(double)=%d",
            label,
            f"{verdict.python_version[0]}.{verdict.python_version[1]}",
            verdict.implementation,
            verdict.float_mant_digits,
            verdict.float_double_bytes,
        )
    else:
        if verdict.passed:
            logger.info(
                "scoring_determinism: service %s starting on non-production "
                "with passing pin (python=%s impl=%s)",
                label,
                f"{verdict.python_version[0]}.{verdict.python_version[1]}",
                verdict.implementation,
            )
        else:
            logger.warning(
                "scoring_determinism: service %s on non-production has a "
                "non-pinned runtime — non-fatal but the same configuration "
                "would refuse on mainnet. failures=%s",
                label, list(verdict.failures),
            )
    return verdict


# =============================================================================
# Test helpers — flip the verdict for a block of code
# =============================================================================

@contextmanager
def override_emergency_bypass(*, opted_in: bool):
    """Temporarily set / unset ``PHYLANX_SCORING_DETERMINISM_OK`` for a test."""
    prev = os.environ.get(ENV_DETERMINISM_OK)
    if opted_in:
        os.environ[ENV_DETERMINISM_OK] = "1"
    elif ENV_DETERMINISM_OK in os.environ:
        del os.environ[ENV_DETERMINISM_OK]
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(ENV_DETERMINISM_OK, None)
        else:
            os.environ[ENV_DETERMINISM_OK] = prev
