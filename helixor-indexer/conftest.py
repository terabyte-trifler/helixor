"""
conftest.py — pytest path setup for the Helixor indexer test suite.

The indexer imports both its own `indexer` package and the oracle's shared
types (`features.types.Transaction`, `db.repository`). This puts both
package roots on `sys.path` so the test suite resolves them.
"""

from __future__ import annotations

import sys
from pathlib import Path

_INDEXER_ROOT = Path(__file__).resolve().parent
_ORACLE_ROOT = _INDEXER_ROOT.parent / "helixor-oracle"

for root in (_INDEXER_ROOT, _ORACLE_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
