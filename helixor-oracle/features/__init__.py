"""
helixor-oracle / features — V2 feature extraction.

Public API:
    extract(transactions, window) -> FeatureVector    the pure entry point
    FeatureVector                                     frozen 100-field output
    Transaction, ExtractionWindow, ActionType         input types
    FEATURE_SCHEMA_VERSION                            schema version constant

Everything else (_stats, the per-group computers) is private.
"""

from __future__ import annotations

from features.extractor import extract
from features.types import (
    ActionType,
    ExtractionWindow,
    Transaction,
    classify_program,
)
from features.vector import (
    FEATURE_SCHEMA_VERSION,
    GROUP_SIZES,
    TOTAL_FEATURES,
    FeatureVector,
)

__all__ = [
    "extract",
    "FeatureVector",
    "Transaction",
    "ExtractionWindow",
    "ActionType",
    "classify_program",
    "FEATURE_SCHEMA_VERSION",
    "GROUP_SIZES",
    "TOTAL_FEATURES",
]
