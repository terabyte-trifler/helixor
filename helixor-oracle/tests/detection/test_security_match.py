"""
tests/detection/test_security_match.py — security match primitives.

Each primitive — text normalisation, regex, token-Jaccard, containment,
structural predicates — tested in isolation.
"""

from __future__ import annotations

import re

import pytest

from detection._security_match import (
    best_template_similarity,
    containment_score,
    jaccard_similarity,
    normalise_text,
    programs_outside_declared,
    regex_search,
    repeated_value_ratio,
    tokenize,
)


# =============================================================================
# normalise_text
# =============================================================================

class TestNormaliseText:

    def test_empty(self):
        assert normalise_text("") == ""

    def test_lowercases(self):
        assert normalise_text("IGNORE THIS") == "ignore this"

    def test_strips_zero_width(self):
        # zero-width space between letters
        assert normalise_text("ig\u200bnore") == "ignore"

    def test_collapses_letter_spacing(self):
        # the classic "i g n o r e" obfuscation
        assert "ignore" in normalise_text("i g n o r e")

    def test_collapses_dotted_obfuscation(self):
        assert "ignore" in normalise_text("i.g.n.o.r.e")

    def test_leaves_normal_prose(self):
        # ordinary short words must not be glued together
        out = normalise_text("a big dog ran")
        assert out == "a big dog ran"

    def test_collapses_whitespace_runs(self):
        assert normalise_text("too    many   spaces") == "too many spaces"


# =============================================================================
# regex_search
# =============================================================================

class TestRegexSearch:

    def test_match_returns_substring(self):
        pat = re.compile(r"ignore\s+\w+", re.IGNORECASE)
        assert regex_search(pat, "please ignore that") == "ignore that"

    def test_no_match_returns_none(self):
        pat = re.compile(r"ignore", re.IGNORECASE)
        assert regex_search(pat, "perfectly benign") is None

    def test_empty_text_returns_none(self):
        pat = re.compile(r"x")
        assert regex_search(pat, "") is None


# =============================================================================
# tokenize + jaccard + containment
# =============================================================================

class TestTokenize:

    def test_alphanumeric_tokens(self):
        assert tokenize("Hello, World! 123") == frozenset({"hello", "world", "123"})

    def test_empty(self):
        assert tokenize("") == frozenset()

    def test_dedups(self):
        assert tokenize("spam spam spam") == frozenset({"spam"})


class TestJaccard:

    def test_identical_sets(self):
        s = frozenset({"a", "b", "c"})
        assert jaccard_similarity(s, s) == 1.0

    def test_disjoint_sets(self):
        assert jaccard_similarity(frozenset({"a"}), frozenset({"b"})) == 0.0

    def test_partial_overlap(self):
        # {a,b} ∩ {b,c} = {b}; ∪ = {a,b,c} → 1/3
        a = frozenset({"a", "b"})
        b = frozenset({"b", "c"})
        assert jaccard_similarity(a, b) == pytest.approx(1 / 3)

    def test_empty_is_zero(self):
        assert jaccard_similarity(frozenset(), frozenset({"a"})) == 0.0


class TestContainment:

    def test_full_containment(self):
        # template fully present in text
        text = frozenset({"send", "your", "key", "now", "please"})
        template = frozenset({"send", "your", "key"})
        assert containment_score(text, template) == 1.0

    def test_partial_containment(self):
        text = frozenset({"send", "your"})
        template = frozenset({"send", "your", "key", "now"})
        assert containment_score(text, template) == 0.5

    def test_containment_robust_to_extra_text(self):
        # containment, unlike jaccard, is not diluted by extra benign tokens
        template = frozenset({"send", "key"})
        short = frozenset({"send", "key"})
        long = frozenset({"send", "key"} | {f"w{i}" for i in range(50)})
        assert containment_score(short, template) == containment_score(long, template) == 1.0

    def test_empty_template_is_zero(self):
        assert containment_score(frozenset({"a"}), frozenset()) == 0.0


class TestBestTemplateSimilarity:

    def test_picks_highest(self):
        text = frozenset({"send", "private", "key"})
        templates = [
            frozenset({"buy", "token"}),
            frozenset({"send", "private", "key"}),   # exact
            frozenset({"hello"}),
        ]
        assert best_template_similarity(text, templates) == 1.0

    def test_no_templates_is_zero(self):
        assert best_template_similarity(frozenset({"a"}), []) == 0.0


# =============================================================================
# structural predicates
# =============================================================================

class TestProgramsOutsideDeclared:

    def test_all_declared(self):
        declared = frozenset({"A", "B"})
        assert programs_outside_declared(["A", "B", "A"], declared) == set()

    def test_some_outside(self):
        declared = frozenset({"A"})
        assert programs_outside_declared(["A", "EVIL"], declared) == {"EVIL"}

    def test_empty_declared_returns_empty(self):
        # No declaration → cannot judge → empty.
        assert programs_outside_declared(["A", "B"], frozenset()) == set()


class TestRepeatedValueRatio:

    def test_all_distinct(self):
        assert repeated_value_ratio([1, 2, 3, 4]) == 0.0

    def test_all_repeats(self):
        # [x,x,x,x] → 3 repeats / 4 = 0.75
        assert repeated_value_ratio([1, 1, 1, 1]) == 0.75

    def test_single_value(self):
        assert repeated_value_ratio([1]) == 0.0

    def test_empty(self):
        assert repeated_value_ratio([]) == 0.0
