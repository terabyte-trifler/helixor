"""
tests/detection/test_security_patterns.py — attack-pattern library integrity.

The library is data; these tests are its schema + sanity guarantees.
"""

from __future__ import annotations

import pytest

from detection.security_patterns import (
    PATTERN_LIBRARY,
    PATTERN_LIBRARY_VERSION,
    AttackPattern,
    get_pattern,
    patterns_by_method,
)
from detection.security_types import (
    AttackCategory,
    DetectionMethod,
    Severity,
)


# =============================================================================
# Library shape
# =============================================================================

class TestLibraryShape:

    def test_has_31_patterns(self):
        assert len(PATTERN_LIBRARY) == 31

    def test_all_ids_unique(self):
        ids = [p.id for p in PATTERN_LIBRARY]
        assert len(ids) == len(set(ids))

    def test_ids_follow_scheme(self):
        for p in PATTERN_LIBRARY:
            assert p.id.startswith("HLX-SEC-")

    def test_library_version_is_set(self):
        assert isinstance(PATTERN_LIBRARY_VERSION, int)
        assert PATTERN_LIBRARY_VERSION >= 1


# =============================================================================
# Per-pattern contract
# =============================================================================

class TestPatternContract:

    @pytest.mark.parametrize("pattern", PATTERN_LIBRARY, ids=lambda p: p.id)
    def test_every_pattern_has_false_positive_notes(self, pattern):
        # The single most important field — every pattern must document
        # when it may misfire.
        assert pattern.false_positive_notes
        assert len(pattern.false_positive_notes) > 20

    @pytest.mark.parametrize("pattern", PATTERN_LIBRARY, ids=lambda p: p.id)
    def test_every_pattern_has_description(self, pattern):
        assert pattern.description
        assert len(pattern.description) > 20

    @pytest.mark.parametrize("pattern", PATTERN_LIBRARY, ids=lambda p: p.id)
    def test_method_matches_data(self, pattern):
        # The method must have its corresponding matcher populated.
        if pattern.method is DetectionMethod.REGEX:
            assert pattern.regex is not None
        elif pattern.method is DetectionMethod.SEMANTIC:
            assert pattern.semantic_templates
        elif pattern.method in (DetectionMethod.STRUCTURAL, DetectionMethod.COMPOSITE):
            assert pattern.structural_key

    @pytest.mark.parametrize("pattern", PATTERN_LIBRARY, ids=lambda p: p.id)
    def test_severity_and_category_typed(self, pattern):
        assert isinstance(pattern.severity, Severity)
        assert isinstance(pattern.category, AttackCategory)


# =============================================================================
# Coverage — the library spans the threat classes
# =============================================================================

class TestCoverage:

    def test_covers_multiple_categories(self):
        cats = {p.category for p in PATTERN_LIBRARY}
        # The library should span a broad set of threat classes.
        assert len(cats) >= 8

    def test_covers_all_detection_methods(self):
        methods = {p.method for p in PATTERN_LIBRARY}
        assert DetectionMethod.REGEX in methods
        assert DetectionMethod.SEMANTIC in methods
        assert DetectionMethod.STRUCTURAL in methods

    def test_has_critical_patterns(self):
        # The library must contain unambiguous (CRITICAL) attack signatures.
        crit = [p for p in PATTERN_LIBRARY if p.severity is Severity.CRITICAL]
        assert len(crit) >= 1

    def test_severity_spread(self):
        # Not every pattern is CRITICAL — a real library spans severities.
        sevs = {p.severity for p in PATTERN_LIBRARY}
        assert len(sevs) >= 3


# =============================================================================
# Construction validation
# =============================================================================

class TestConstructionValidation:

    def test_rejects_missing_false_positive_notes(self):
        with pytest.raises(ValueError, match="false_positive_notes"):
            AttackPattern(
                id="X", category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.LOW, method=DetectionMethod.STRUCTURAL,
                description="a long enough description for the check",
                false_positive_notes="",   # empty → rejected
                structural_key="k",
            )

    def test_rejects_regex_method_without_regex(self):
        with pytest.raises(ValueError, match="REQUIRES|requires a regex"):
            AttackPattern(
                id="X", category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.LOW, method=DetectionMethod.REGEX,
                description="a long enough description for the check",
                false_positive_notes="a long enough fp note for the check",
                regex=None,
            )


# =============================================================================
# Lookups
# =============================================================================

class TestLookups:

    def test_get_pattern_by_id(self):
        p = get_pattern("HLX-SEC-001")
        assert p.id == "HLX-SEC-001"

    def test_get_pattern_missing_raises(self):
        with pytest.raises(KeyError):
            get_pattern("HLX-SEC-999")

    def test_patterns_by_method(self):
        regex_patterns = patterns_by_method(DetectionMethod.REGEX)
        assert all(p.method is DetectionMethod.REGEX for p in regex_patterns)
        assert len(regex_patterns) >= 1
