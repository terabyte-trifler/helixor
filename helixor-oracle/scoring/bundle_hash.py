"""
scoring/bundle_hash.py — AW-04 canonical scoring-bundle hash.

THE AUDIT FINDING
-----------------
AW-04 (Scoring Engine is a Black Box). Pre-AW-04 the cert carried
`scoring_algo_version` + `scoring_weights_version` (VULN-22) — integer
labels that pin which numbered version of the algorithm was used. The
labels prove which release-line ran, but they do NOT prove WHICH SOURCE
BYTES executed under that label. A malicious cluster could ship a tree
that calls itself "algo v2" while having patched the composite logic,
and the on-chain record could not tell.

THE FIX
-------
Compute a single 32-byte SHA-256 over the canonical source bytes of the
scoring kernel (`scoring/composite.py`, `scoring/weights.py`,
`scoring/_gaming.py`, `scoring/determinism.py`, plus the dimension /
flag schema in `detection/types.py`) PLUS the algo + weights version
labels. Bind that hash into every cert-payload digest. A third party
running `verify_score_computation`:

  1. Clones helixor at the published release tag.
  2. Runs `compute_scoring_bundle_hash()` against the cloned tree.
  3. Compares to `cert.scoring_code_hash`.

A cluster that patches the source but publishes the same hash is now
catchable: the published code's hash will not match the on-chain hash.
A cluster that publishes a matching hash but ran different code has
forged the cert's signature in a way the threshold-signed digest now
detects (the threshold sigs cover the hash; a wrong-code cluster cannot
produce signatures over the right hash without controlling N keys).

THE BUNDLE MEMBERSHIP
---------------------
The bundle is the CONSENSUS-CRITICAL surface of the scoring kernel —
the code whose byte-identical execution every node depends on for
cluster agreement. NOT every Python file in the repo:

  - `scoring/composite.py`   — the composite scorer
  - `scoring/weights.py`     — the weight vector + schema fingerprint
  - `scoring/_gaming.py`     — gaming + confidence + delta guard rail
  - `scoring/determinism.py` — float→int quantization + runtime guards
  - `detection/types.py`     — DimensionId / DimensionResult / FlagBit
                                schema (changing a flag bit = changing
                                the meaning of the score)

Test files, fixtures, and infrastructure modules are EXCLUDED.
Adding/removing a bundle member is a deliberate act: it changes the
hash, which by-construction invalidates every prior cert's hash binding
— which is the intended semantic (a new bundle is a new algorithm
version, full stop).

DETERMINISM
-----------
The hash is computed as:

    sha256(
        b"helixor-scoring-bundle-v1\\n" ||
        for path in sorted(bundle_paths):
            path.encode("utf-8")            ||
            b"\\n"                          ||
            sha256(file_bytes).digest()     ||  # 32 bytes
            b"\\n"
        ||
        f"algo=v{SCORING_ALGO_VERSION}\\n".encode("utf-8") ||
        f"weights=v{SCORING_WEIGHTS_VERSION}\\n".encode("utf-8")
    )

`path` is the REPO-RELATIVE path from helixor-oracle/ (e.g.
`scoring/composite.py`). Files are read in BINARY mode — newline
conversion is forbidden (LF only by .gitattributes; CI verifies). The
domain-tag prefix `helixor-scoring-bundle-v1` reserves room for a v2
bundle scheme later without ambiguity.

The version labels are folded in AT THE END so a tree-state-only hash
collision (two bundles with identical source bytes but different
version constants) cannot occur — Python doesn't have unmodified
constants on disk, but the explicit fold makes the binding airtight.

CALLERS
-------
- `oracle.cluster.cert_signing.cert_payload_digest` — folds
  `scoring_code_hash` into the threshold-signed digest at sign time.
- `oracle.cluster.pipeline` — computes the hash once at startup and
  passes it into every cert digest.
- `audit/scoring_provenance_check.py` — pins that every production
  call passes the hash kwarg.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence


# =============================================================================
# Bundle membership — pinned constant. Adding/removing a member changes the
# hash and is a deliberate algorithm-version bump.
# =============================================================================

# Paths are repo-relative from `helixor-oracle/`. Order does NOT matter for
# the hash (we sort) but the list is the canonical declaration of what
# constitutes the scoring kernel.
_BUNDLE_MEMBERS: tuple[str, ...] = (
    "scoring/composite.py",
    "scoring/weights.py",
    "scoring/_gaming.py",
    "scoring/determinism.py",
    "detection/types.py",
)

# Domain tag — the b"" prefix that distinguishes a v1 scoring-bundle hash
# from anything else that might one day be hashed in this codebase. Bump if
# the canonical layout itself changes (NOT for bundle-member changes).
_BUNDLE_DOMAIN_TAG = b"helixor-scoring-bundle-v1\n"


# =============================================================================
# Public API
# =============================================================================

def bundle_members() -> tuple[str, ...]:
    """The canonical bundle-member list (sorted). Read-only."""
    return tuple(sorted(_BUNDLE_MEMBERS))


def _repo_root() -> Path:
    """
    Return the `helixor-oracle/` directory — the root the bundle paths
    are relative to. This module lives at
    `helixor-oracle/scoring/bundle_hash.py`; parent.parent is
    `helixor-oracle/`.
    """
    return Path(__file__).resolve().parent.parent


def compute_scoring_bundle_hash(
    *,
    repo_root: Path | None = None,
    members:   Sequence[str] | None = None,
) -> bytes:
    """
    Return the 32-byte SHA-256 over the canonical scoring bundle.

    `repo_root` defaults to the `helixor-oracle/` directory containing
    this module — production callers should NOT override it; the kwarg
    exists for tests that fabricate a synthetic bundle on a tmpdir.

    `members` defaults to the pinned tuple — same caveat.

    Raises `FileNotFoundError` if any member is missing (the bundle is
    NOT optional; a missing file is a deploy regression).
    """
    # Defer import to avoid a circular load at module-import time
    # (composite.py imports weights, weights imports detection, etc.).
    from scoring.composite import SCORING_ALGO_VERSION
    from scoring.weights import SCORING_WEIGHTS_VERSION

    root = repo_root if repo_root is not None else _repo_root()
    paths = tuple(sorted(members)) if members is not None else bundle_members()

    h = hashlib.sha256()
    h.update(_BUNDLE_DOMAIN_TAG)
    for rel_path in paths:
        full = root / rel_path
        # Binary read — never let the platform's newline translation
        # touch consensus-critical bytes. .gitattributes pins LF; CI
        # verifies. A CRLF-translated checkout would still hash the
        # CRLF bytes here, so this raises the alarm visibly via a
        # mismatching hash rather than failing silently.
        file_bytes = full.read_bytes()
        h.update(rel_path.encode("utf-8"))
        h.update(b"\n")
        h.update(hashlib.sha256(file_bytes).digest())
        h.update(b"\n")
    h.update(f"algo=v{SCORING_ALGO_VERSION}\n".encode("utf-8"))
    h.update(f"weights=v{SCORING_WEIGHTS_VERSION}\n".encode("utf-8"))
    return h.digest()


def scoring_bundle_hash_hex() -> str:
    """Convenience hex form for logs + diagnostics."""
    return compute_scoring_bundle_hash().hex()
