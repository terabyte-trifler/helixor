"""
detection/_security_match.py — deterministic match primitives for the
security pattern library.

Three detection mechanisms, all pure stdlib, all deterministic (Phase-4 BFT
rule — no embedding models, no ML):

  REGEX      — compiled regular expressions over textual fields.
  SEMANTIC   — token-set Jaccard similarity against known-bad phrase
               templates. NOT an embedding model: a deterministic
               bag-of-tokens overlap score. Catches paraphrased / obfuscated
               variants that an exact regex misses, without the
               cross-version non-determinism of a learned embedding.
  STRUCTURAL — predicate helpers over program IDs / account roles.

All functions here are small, isolated, and individually unit-tested.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence


# =============================================================================
# Text normalisation
# =============================================================================

# Common adversarial obfuscation: zero-width chars, homoglyph spacing,
# excessive punctuation between letters. We normalise before matching so
# "i g n o r e" and "ignore" collide.
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060], None,
)


def normalise_text(text: str) -> str:
    """
    Normalise text for matching:
      - strip zero-width characters
      - lowercase
      - collapse runs of whitespace/punctuation used to break up keywords
        ("i.g.n.o.r.e" -> "ignore", "i g n o r e" -> "ignore" only when the
        gaps are single separators between single letters)

    Deterministic. The de-spacing is conservative: it only joins
    single-letter tokens separated by single separators, so ordinary prose
    ("a b c" as real words) is left alone unless it is clearly letter-spacing.
    """
    if not text:
        return ""
    t = text.translate(_ZERO_WIDTH).lower()

    # Conservative de-spacing: collapse sequences of "<letter><sep>" where the
    # letters are single chars — the classic "i g n o r e" / "i-g-n-o-r-e"
    # obfuscation. Require >= 4 such single letters in a row to avoid eating
    # normal short words.
    def _collapse(m: re.Match) -> str:
        return re.sub(r"[\s\.\-_*]+", "", m.group(0))

    t = re.sub(r"(?:\b\w[\s\.\-_*]+){3,}\w\b", _collapse, t)

    # Collapse remaining whitespace runs.
    t = re.sub(r"\s+", " ", t).strip()
    return t


# =============================================================================
# REGEX matching
# =============================================================================

def regex_search(pattern: re.Pattern, text: str) -> str | None:
    """
    Search `text` (already normalised by the caller) with a compiled regex.
    Returns the matched substring (for evidence) or None.
    """
    if not text:
        return None
    m = pattern.search(text)
    return m.group(0) if m else None


# =============================================================================
# SEMANTIC similarity — deterministic token-set Jaccard
# =============================================================================

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> frozenset[str]:
    """Lowercase alphanumeric tokens as a set. Deterministic."""
    return frozenset(_TOKEN_RE.findall(text.lower()))


def jaccard_similarity(a: frozenset[str], b: frozenset[str]) -> float:
    """
    |A ∩ B| / |A ∪ B|, in [0, 1]. 1.0 = identical token sets, 0.0 = disjoint.
    Empty-vs-empty is defined as 0.0 (no evidence of similarity).
    """
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def best_template_similarity(
    text_tokens: frozenset[str],
    templates:   Sequence[frozenset[str]],
) -> float:
    """
    The highest Jaccard similarity between `text_tokens` and any known-bad
    template token-set. This is the "semantic similarity score" — a
    deterministic stand-in for embedding similarity that catches
    paraphrased attack phrases.
    """
    if not templates:
        return 0.0
    return max(jaccard_similarity(text_tokens, t) for t in templates)


def containment_score(
    text_tokens:     frozenset[str],
    template_tokens: frozenset[str],
) -> float:
    """
    Fraction of the TEMPLATE's tokens present in the text:
        |template ∩ text| / |template|

    Unlike Jaccard, containment is not penalised by extra text around the
    attack phrase — an injection buried in a long benign message still
    scores high. Used alongside Jaccard for robustness.
    """
    if not template_tokens:
        return 0.0
    return len(text_tokens & template_tokens) / len(template_tokens)


# =============================================================================
# STRUCTURAL predicates
# =============================================================================

def programs_outside_declared(
    invoked:  Iterable[str],
    declared: frozenset[str],
) -> set[str]:
    """
    Program IDs that were invoked but NOT in the agent's declared tool set.
    Empty `declared` → returns empty (agent didn't declare; can't judge).
    """
    if not declared:
        return set()
    return {p for p in invoked if p and p not in declared}


def repeated_value_ratio(values: Sequence) -> float:
    """
    Fraction of `values` that are duplicates of an earlier value.
    1.0 = every value after the first is a repeat; 0.0 = all distinct.
    Used to detect mechanical/scripted patterns.
    """
    if len(values) <= 1:
        return 0.0
    seen: set = set()
    repeats = 0
    for v in values:
        if v in seen:
            repeats += 1
        else:
            seen.add(v)
    return repeats / len(values)
