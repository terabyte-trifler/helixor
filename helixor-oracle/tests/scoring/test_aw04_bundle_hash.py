"""
tests/scoring/test_aw04_bundle_hash.py — AW-04 canonical scoring-bundle hash.

THE INVARIANT UNDER TEST
------------------------
`compute_scoring_bundle_hash()` returns a 32-byte SHA-256 over a strictly-
defined canonical input:

    sha256(
        b"helixor-scoring-bundle-v1\\n" ||
        for each sorted path:
            path_bytes || b"\\n" || sha256(file_bytes) || b"\\n"
        ||
        f"algo=v{ALGO_V}\\n".encode() ||
        f"weights=v{WEIGHTS_V}\\n".encode()
    )

Properties this file pins:
  - Output is 32 bytes.
  - Same call -> byte-identical hash (determinism).
  - Path ORDER passed in is irrelevant (the function sorts).
  - Changing ANY bundle file's content changes the hash.
  - Adding/removing a bundle member changes the hash.
  - Changing the algo or weights version label changes the hash.
  - The domain tag is folded in (no prefix => different hash).
  - Bundle members all exist in the real tree.

The synthetic fixtures use `repo_root=tmp_path` so the tests do not touch
the real scoring kernel; production callers never override the kwarg.
"""

from __future__ import annotations

import hashlib

import pytest

from scoring.bundle_hash import (
    _BUNDLE_DOMAIN_TAG,
    _BUNDLE_MEMBERS,
    bundle_members,
    compute_scoring_bundle_hash,
    scoring_bundle_hash_hex,
)


# =============================================================================
# Synthetic-tree fixtures
# =============================================================================

def _write_synthetic_bundle(root, contents: dict[str, bytes]) -> None:
    """
    Materialise a fake bundle under `root` so the hash function reads
    real files. The dict keys are repo-relative paths (matching the
    `bundle_members()` contract).
    """
    for rel, body in contents.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)


def _synthetic_members() -> tuple[str, ...]:
    return (
        "scoring/a.py",
        "scoring/b.py",
        "detection/c.py",
    )


def _populate_synthetic(root) -> None:
    _write_synthetic_bundle(root, {
        "scoring/a.py":    b"# a\nprint('a')\n",
        "scoring/b.py":    b"# b\nprint('b')\n",
        "detection/c.py":  b"# c\nprint('c')\n",
    })


# =============================================================================
# Output shape + determinism
# =============================================================================

class TestBundleHashShape:

    def test_hash_is_32_bytes(self):
        h = compute_scoring_bundle_hash()
        assert isinstance(h, bytes)
        assert len(h) == 32

    def test_hex_form_is_64_chars(self):
        hx = scoring_bundle_hash_hex()
        assert isinstance(hx, str)
        assert len(hx) == 64
        # Every char is a valid lowercase hex digit.
        assert all(c in "0123456789abcdef" for c in hx)

    def test_deterministic(self):
        # Production call twice -> byte-identical bytes. The bundle is
        # the basis for every cluster's threshold-signed digest.
        a = compute_scoring_bundle_hash()
        b = compute_scoring_bundle_hash()
        assert a == b


# =============================================================================
# bundle_members — the canonical declaration
# =============================================================================

class TestBundleMembers:

    def test_returns_sorted_tuple(self):
        m = bundle_members()
        assert isinstance(m, tuple)
        assert list(m) == sorted(m), \
            "bundle_members() must be sorted — the hash sorts before reading"

    def test_pinned_files_exist_in_tree(self):
        # Production safety: every pinned bundle member must be a real
        # file. A missing member is a deploy regression and would raise
        # FileNotFoundError at first cluster startup — better to catch
        # it in CI.
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]  # helixor-oracle/
        for rel in _BUNDLE_MEMBERS:
            assert (root / rel).is_file(), f"bundle member missing: {rel}"

    def test_pinned_member_set_is_what_design_doc_says(self):
        # If you add/remove a bundle member, every prior cert's hash
        # binding is invalidated by construction. The list belongs in a
        # design doc; this test pins the current state so the doc and
        # the code cannot drift silently.
        assert set(bundle_members()) == {
            "scoring/composite.py",
            "scoring/weights.py",
            "scoring/_gaming.py",
            "scoring/determinism.py",
            "detection/types.py",
        }


# =============================================================================
# Canonical-form invariants — exercised on a synthetic bundle
# =============================================================================

class TestCanonicalForm:

    def test_path_order_irrelevant(self, tmp_path):
        _populate_synthetic(tmp_path)
        members = _synthetic_members()

        ordered = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=members,
        )
        # Pass the members in REVERSE order — the function must sort
        # internally before reading.
        reversed_ = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=tuple(reversed(members)),
        )
        assert ordered == reversed_

    def test_changing_a_file_changes_the_hash(self, tmp_path):
        _populate_synthetic(tmp_path)
        before = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=_synthetic_members(),
        )
        # Mutate one of the bundle files — anything from a single-byte
        # change upward must alter the hash.
        (tmp_path / "scoring/a.py").write_bytes(b"# a (mutated)\nprint('a!')\n")
        after = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=_synthetic_members(),
        )
        assert before != after

    def test_adding_a_member_changes_the_hash(self, tmp_path):
        _populate_synthetic(tmp_path)
        base = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=_synthetic_members(),
        )
        # Add one more bundle member — same five originals, plus a new
        # file at a different path.
        (tmp_path / "scoring/d.py").write_bytes(b"# d\nprint('d')\n")
        extended = _synthetic_members() + ("scoring/d.py",)
        bigger = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=extended,
        )
        assert base != bigger

    def test_removing_a_member_changes_the_hash(self, tmp_path):
        _populate_synthetic(tmp_path)
        base = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=_synthetic_members(),
        )
        smaller = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=_synthetic_members()[:-1],
        )
        assert base != smaller

    def test_missing_member_raises(self, tmp_path):
        _populate_synthetic(tmp_path)
        # Reference a path that was never written — the bundle is NOT
        # optional; a missing file must surface as a FileNotFoundError
        # rather than silently degrading the hash.
        with pytest.raises(FileNotFoundError):
            compute_scoring_bundle_hash(
                repo_root=tmp_path,
                members=_synthetic_members() + ("does/not/exist.py",),
            )

    def test_path_string_is_folded_into_hash(self, tmp_path):
        # Two synthetic bundles with IDENTICAL file contents but DIFFERENT
        # path strings must hash differently — the canonical form folds
        # the path name in between the domain tag and the file digest.
        (tmp_path / "scoring").mkdir()
        body = b"identical contents\n"
        (tmp_path / "scoring" / "x.py").write_bytes(body)
        (tmp_path / "scoring" / "y.py").write_bytes(body)
        ha = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=("scoring/x.py",),
        )
        hb = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=("scoring/y.py",),
        )
        assert ha != hb


# =============================================================================
# Domain-tag + version-label binding
# =============================================================================

class TestDomainTagAndVersionLabels:

    def test_domain_tag_is_v1(self):
        # The tag reserves room for a v2 bundle scheme. Pinning it here
        # ensures the wire format stays stable across refactors.
        assert _BUNDLE_DOMAIN_TAG == b"helixor-scoring-bundle-v1\n"

    def test_manual_hash_matches_compute_scoring_bundle_hash(self, tmp_path):
        # Build the bundle hash by hand using the documented canonical
        # form and verify the function produces byte-identical bytes.
        # This is the most explicit pin we can write — every aspect of
        # the encoding is reconstructed here.
        from scoring.composite import SCORING_ALGO_VERSION
        from scoring.weights import SCORING_WEIGHTS_VERSION

        _populate_synthetic(tmp_path)
        members = _synthetic_members()

        h = hashlib.sha256()
        h.update(_BUNDLE_DOMAIN_TAG)
        for rel in sorted(members):
            file_bytes = (tmp_path / rel).read_bytes()
            h.update(rel.encode("utf-8"))
            h.update(b"\n")
            h.update(hashlib.sha256(file_bytes).digest())
            h.update(b"\n")
        h.update(f"algo=v{SCORING_ALGO_VERSION}\n".encode("utf-8"))
        h.update(f"weights=v{SCORING_WEIGHTS_VERSION}\n".encode("utf-8"))
        expected = h.digest()

        produced = compute_scoring_bundle_hash(
            repo_root=tmp_path, members=members,
        )
        assert produced == expected
