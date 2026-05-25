"""
tests/scoring/test_vuln18_scoring_determinism.py — VULN-18 pin tests.

The commit-reveal protocol depends on every honest oracle node producing
byte-identical ScoreResults for the same input. The composite scorer
rounds to an int 0..1000 at the boundary, but the per-dimension math
that feeds the rounding uses IEEE 754 doubles. Those doubles are only
guaranteed to round identically on the audited runtime.

This file pins:
  - the canonical float→int quantiser (quantize_to_int) — banker's rounding
  - the Python version + implementation acceptance set
  - the IEEE 754 binary64 pin (mant_dig / radix / sizeof double)
  - the no-numpy/no-scipy contract (both in sys.modules AND in source)
  - the mainnet refusal gate (and its emergency opt-in)
  - that composite.py routes its conversion through quantize_to_int
"""

from __future__ import annotations

import logging
import struct
import sys
from datetime import datetime, timezone

import pytest

from detection.types import DIMENSION_MAX_SCORES, DimensionId, DimensionResult
from oracle.network_guard import override_network
from scoring import compute_composite_score, quantize_to_int
from scoring.determinism import (
    BANNED_MATH_BACKENDS,
    ENV_DETERMINISM_OK,
    SUPPORTED_IMPLEMENTATIONS,
    SUPPORTED_PYTHON_VERSIONS,
    DeterminismVerdict,
    ScoringDeterminismRefused,
    enforce_scoring_determinism,
    evaluate,
    opted_in_to_emergency_bypass,
    override_emergency_bypass,
    scan_source_for_banned_imports,
)


REF_TIME = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# quantize_to_int — the canonical float→int contract
# =============================================================================

class TestQuantizeToInt:
    """
    Pin the rounding contract. Every consensus-affecting conversion goes
    through this function; the test catches anyone who tries to swap the
    rounding mode for math.floor / math.ceil / "round-half-away-from-zero".
    """

    def test_returns_int_type(self):
        assert isinstance(quantize_to_int(0.0), int)
        assert isinstance(quantize_to_int(123.456), int)

    def test_rounds_below_half_down(self):
        assert quantize_to_int(0.4)   == 0
        assert quantize_to_int(1.49)  == 1
        assert quantize_to_int(999.4) == 999

    def test_rounds_above_half_up(self):
        assert quantize_to_int(0.6)    == 1
        assert quantize_to_int(1.51)   == 2
        assert quantize_to_int(999.51) == 1000

    def test_banker_rounding_on_exact_halves(self):
        """
        Python 3 ``round()`` uses banker's rounding (round-half-to-even).
        The whole cluster depends on this — a swap to "round half up"
        would re-bias every contribution by ~0.5 on average.
        """
        # 0.5 -> 0 (even), 1.5 -> 2 (even), 2.5 -> 2 (even), 3.5 -> 4 (even)
        assert quantize_to_int(0.5) == 0
        assert quantize_to_int(1.5) == 2
        assert quantize_to_int(2.5) == 2
        assert quantize_to_int(3.5) == 4
        assert quantize_to_int(4.5) == 4

    def test_handles_negative(self):
        assert quantize_to_int(-0.5) == 0     # banker's: -0.5 -> 0 (even)
        assert quantize_to_int(-1.5) == -2    # banker's: -1.5 -> -2 (even)
        assert quantize_to_int(-2.5) == -2    # banker's: -2.5 -> -2 (even)

    def test_idempotent_on_int_valued_floats(self):
        for v in (0.0, 1.0, 500.0, 1000.0):
            assert quantize_to_int(v) == int(v)


# =============================================================================
# evaluate() — the verdict shape
# =============================================================================

class TestEvaluate:

    def test_verdict_is_frozen(self):
        verdict = evaluate(is_production=False)
        assert isinstance(verdict, DeterminismVerdict)
        with pytest.raises(Exception):
            verdict.failures = ("mutated",)  # type: ignore[misc]

    def test_verdict_reports_runtime_facts(self):
        verdict = evaluate(is_production=False)
        assert verdict.python_version == (sys.version_info.major, sys.version_info.minor)
        assert verdict.implementation == sys.implementation.name.lower()
        assert verdict.float_mant_digits == sys.float_info.mant_dig
        assert verdict.float_radix == sys.float_info.radix
        assert verdict.float_double_bytes == struct.calcsize("d")

    def test_passes_on_current_runtime(self):
        """
        Sanity: the test runner is, by definition, on a runtime that
        passes the pin. If this fails, the SUPPORTED_PYTHON_VERSIONS set
        is out of sync with reality.
        """
        verdict = evaluate(is_production=False)
        assert verdict.passed, f"current runtime fails the pin: {verdict.failures}"

    def test_no_banned_backends_in_sys_modules(self):
        verdict = evaluate(is_production=False)
        assert verdict.banned_loaded == ()


# =============================================================================
# The supported set — pinning what mainnet accepts
# =============================================================================

class TestSupportedSet:

    def test_python_pin_includes_currently_running_version(self):
        cur = (sys.version_info.major, sys.version_info.minor)
        assert cur in SUPPORTED_PYTHON_VERSIONS, (
            f"the test process runs on Python {cur} but the audited set "
            f"is {sorted(SUPPORTED_PYTHON_VERSIONS)} — bump the set or "
            f"the runtime"
        )

    def test_only_cpython(self):
        assert "cpython" in SUPPORTED_IMPLEMENTATIONS
        # JIT-based implementations are intentionally excluded.
        assert "pypy" not in SUPPORTED_IMPLEMENTATIONS

    def test_banned_set_pins_known_offenders(self):
        # The headline offenders MUST be in the banned set; this catches a
        # well-meaning refactor that drops one.
        assert "numpy" in BANNED_MATH_BACKENDS
        assert "scipy" in BANNED_MATH_BACKENDS
        assert "pandas" in BANNED_MATH_BACKENDS
        assert "sklearn" in BANNED_MATH_BACKENDS


# =============================================================================
# Source scan — the static guarantee that detection/scoring stay clean
# =============================================================================

class TestSourceScan:

    def test_scoring_and_detection_have_no_banned_imports(self):
        """
        VULN-18 forbids numpy/scipy/pandas/sklearn anywhere under
        detection/ or scoring/. The runtime sys.modules check catches
        loaded backends; this STATIC check catches them before they ever
        run.
        """
        violations = scan_source_for_banned_imports()
        assert violations == {}, (
            "VULN-18: banned math backend imported in a determinism-critical "
            f"module: {dict((str(p), sorted(m)) for p, m in violations.items())}"
        )


# =============================================================================
# Emergency bypass — exact-"1" with whitespace trim
# =============================================================================

class TestEmergencyBypass:

    def test_unset_is_not_opted_in(self, monkeypatch):
        monkeypatch.delenv(ENV_DETERMINISM_OK, raising=False)
        assert opted_in_to_emergency_bypass() is False

    def test_exact_one_is_opted_in(self, monkeypatch):
        monkeypatch.setenv(ENV_DETERMINISM_OK, "1")
        assert opted_in_to_emergency_bypass() is True

    def test_whitespace_is_trimmed(self, monkeypatch):
        # Mirrors the project-wide HELIXOR_MAINNET_OK convention.
        monkeypatch.setenv(ENV_DETERMINISM_OK, "  1\n")
        assert opted_in_to_emergency_bypass() is True

    @pytest.mark.parametrize("bad", ["true", "yes", "TRUE", "0", "", "  ", "10", "01"])
    def test_other_values_are_not_opted_in(self, monkeypatch, bad):
        monkeypatch.setenv(ENV_DETERMINISM_OK, bad)
        assert opted_in_to_emergency_bypass() is False

    def test_override_context_restores(self, monkeypatch):
        monkeypatch.delenv(ENV_DETERMINISM_OK, raising=False)
        assert opted_in_to_emergency_bypass() is False
        with override_emergency_bypass(opted_in=True):
            assert opted_in_to_emergency_bypass() is True
        assert opted_in_to_emergency_bypass() is False


# =============================================================================
# The gate — refusal semantics
# =============================================================================

class TestGate:

    def test_passes_on_devnet(self, caplog):
        with override_network("devnet"):
            with caplog.at_level(logging.INFO, logger="helixor.scoring.determinism"):
                verdict = enforce_scoring_determinism(service="ut")
        assert verdict.passed
        assert "scoring_determinism" in caplog.text

    def test_passes_on_localnet(self):
        with override_network("localnet"):
            verdict = enforce_scoring_determinism(service="ut")
        assert verdict.passed

    def test_passes_on_mainnet_with_pinned_runtime(self, caplog):
        with override_network("mainnet-beta", mainnet_ok=True):
            with caplog.at_level(logging.WARNING, logger="helixor.scoring.determinism"):
                verdict = enforce_scoring_determinism(service="ut")
        assert verdict.passed
        assert verdict.is_production is True
        # The mainnet warning line carries the runtime version for audit.
        assert "PRODUCTION" in caplog.text

    def test_refuses_on_mainnet_with_failing_pin(self, caplog, monkeypatch):
        # Force the pin to fail by patching the version reporter — keeps the
        # test runnable on any supported runtime.
        from scoring import determinism as det

        def fake_python_version() -> tuple[int, int]:
            return (2, 7)  # not in SUPPORTED_PYTHON_VERSIONS

        monkeypatch.setattr(det, "_python_version", fake_python_version)
        with override_network("mainnet-beta", mainnet_ok=True):
            with caplog.at_level(logging.ERROR, logger="helixor.scoring.determinism"):
                with pytest.raises(ScoringDeterminismRefused) as exc:
                    enforce_scoring_determinism(service="ut")
        assert "REFUSING" in str(exc.value)
        assert "python=2.7" in str(exc.value)
        assert ENV_DETERMINISM_OK in str(exc.value)

    def test_mainnet_failing_pin_passes_with_emergency_optin(self, caplog, monkeypatch):
        from scoring import determinism as det

        monkeypatch.setattr(det, "_python_version", lambda: (2, 7))
        with override_network("mainnet-beta", mainnet_ok=True):
            with override_emergency_bypass(opted_in=True):
                with caplog.at_level(logging.ERROR, logger="helixor.scoring.determinism"):
                    verdict = enforce_scoring_determinism(service="ut")
        assert verdict.passed is False
        assert verdict.opted_in is True
        # The ERROR log line is the audit trail.
        assert "audited emergency bypass" in caplog.text

    def test_failing_pin_on_devnet_is_non_fatal(self, caplog, monkeypatch):
        from scoring import determinism as det

        monkeypatch.setattr(det, "_python_version", lambda: (2, 7))
        with override_network("devnet"):
            with caplog.at_level(logging.WARNING, logger="helixor.scoring.determinism"):
                verdict = enforce_scoring_determinism(service="ut")
        assert verdict.passed is False
        assert verdict.is_production is False  # devnet
        # Non-fatal — but the log line documents the disagreement.
        assert "would refuse on mainnet" in caplog.text

    def test_refuses_on_mainnet_when_numpy_loaded(self, monkeypatch, caplog):
        """
        Even on the audited Python, importing numpy into the oracle
        process is a hard refuse — it ships its own FPU dispatch.
        """
        # Don't actually import numpy; inject a sentinel into sys.modules
        # so the loaded-backends scan trips.
        monkeypatch.setitem(sys.modules, "numpy", object())
        with override_network("mainnet-beta", mainnet_ok=True):
            with caplog.at_level(logging.ERROR, logger="helixor.scoring.determinism"):
                with pytest.raises(ScoringDeterminismRefused) as exc:
                    enforce_scoring_determinism(service="ut")
        assert "numpy" in str(exc.value)


# =============================================================================
# Composite integration — the conversion really goes through quantize_to_int
# =============================================================================

def _build_results(score_per_dim: int) -> dict[DimensionId, DimensionResult]:
    """Build five DimensionResults each at the given raw score, capped at max."""
    out: dict[DimensionId, DimensionResult] = {}
    for dim in DimensionId.ordered():
        max_score = DIMENSION_MAX_SCORES[dim]
        s = min(score_per_dim, max_score)
        out[dim] = DimensionResult(
            dimension=dim, score=s, max_score=max_score,
            flags=0, sub_scores={}, algo_version=1,
        )
    return out


class TestCompositeRoutesThroughQuantizer:
    """
    The composite scorer must use quantize_to_int — not raw int(round())
    or math.floor or anything else. The test patches quantize_to_int and
    verifies it gets called for the per-dimension contributions.
    """

    def test_all_max_score_routes_through_quantizer(self, baseline, monkeypatch):
        from scoring import composite as comp

        call_count = {"n": 0}
        real_q = comp.quantize_to_int

        def counting_q(value):
            call_count["n"] += 1
            return real_q(value)

        monkeypatch.setattr(comp, "quantize_to_int", counting_q)
        compute_composite_score(
            _build_results(1000),  # each capped to its max
            baseline,
            computed_at=REF_TIME,
        )
        # Five dimensions, each quantised once.
        assert call_count["n"] == 5

    def test_golden_score_is_byte_identical(self, baseline):
        """
        Pin the composite output for a known input — two invocations on
        the same process must return the same integer score. The actual
        cross-Python pin is enforced by SUPPORTED_PYTHON_VERSIONS at the
        runtime gate; here we lock the in-process byte-equality contract.
        """
        results = _build_results(100)
        a = compute_composite_score(results, baseline, computed_at=REF_TIME)
        b = compute_composite_score(results, baseline, computed_at=REF_TIME)
        assert a.score == b.score
        assert a.weighted_contributions == b.weighted_contributions
        # And it's an INT, not a float (the conversion happened).
        assert isinstance(a.score, int)
        for v in a.weighted_contributions.values():
            assert isinstance(v, int)
