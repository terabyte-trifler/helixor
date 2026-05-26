"""
tests/test_ta2_runner_verified_source.py — TA-2 runner pre-flight gate.

Pins:
  - GeyserIndexer on a mainnet cluster REFUSES a raw (unverified)
    StreamSource by raising UnverifiedStreamSourceError.
  - GeyserIndexer accepts ConsensusStream (which advertises
    is_verified_consensus_source = True).
  - Non-mainnet clusters bypass the check (devnet/localnet still work
    with one endpoint, as documented in SPOF-#8).
  - is_verified_consensus_source(...) is duck-typed on the attribute,
    NOT on the class identity — so a misconfigured stub cannot pose as
    one by inheriting from ConsensusStream.
"""

from __future__ import annotations

import pytest

from indexer.consensus import ConsensusStream
from indexer.production_config import (
    CLUSTER_ENV,
    UnverifiedStreamSourceError,
    assert_source_verified_for_cluster,
    is_verified_consensus_source,
)
from indexer.stream import ListStreamSource


def _stub_writer():
    """Minimal IngestionWriter stub; runner.__init__ only needs an object."""
    return object()


# ----------------------------------------------------------------------------
# is_verified_consensus_source — duck-typed marker
# ----------------------------------------------------------------------------

def test_consensus_stream_class_exposes_marker():
    assert ConsensusStream.is_verified_consensus_source is True


def test_raw_list_stream_source_is_unverified():
    src = ListStreamSource([])
    assert is_verified_consensus_source(src) is False


def test_marker_is_strictly_true():
    class Truthy:
        is_verified_consensus_source = "yes"  # truthy but not True
    assert is_verified_consensus_source(Truthy()) is False


def test_marker_must_be_present():
    class Empty:
        pass
    assert is_verified_consensus_source(Empty()) is False


# ----------------------------------------------------------------------------
# assert_source_verified_for_cluster — pre-flight gate
# ----------------------------------------------------------------------------

def test_devnet_accepts_any_source():
    src = ListStreamSource([])
    # No raise expected: non-mainnet cluster bypasses the gate.
    assert_source_verified_for_cluster(src, cluster="devnet")


def test_localnet_accepts_any_source():
    src = ListStreamSource([])
    assert_source_verified_for_cluster(src, cluster="localnet")


@pytest.mark.parametrize(
    "cluster", ["mainnet", "mainnet-beta", "production", "prod"],
)
def test_mainnet_refuses_unverified_source(cluster):
    src = ListStreamSource([])
    with pytest.raises(UnverifiedStreamSourceError) as excinfo:
        assert_source_verified_for_cluster(src, cluster=cluster)
    msg = str(excinfo.value)
    assert "TA-2" in msg
    assert cluster in msg
    assert "ListStreamSource" in msg


def test_mainnet_accepts_verified_source():
    class Fake(ListStreamSource):
        is_verified_consensus_source = True
    src = Fake([])
    assert_source_verified_for_cluster(src, cluster="mainnet")


def test_cluster_falls_back_to_env_var(monkeypatch):
    monkeypatch.setenv(CLUSTER_ENV, "mainnet")
    src = ListStreamSource([])
    with pytest.raises(UnverifiedStreamSourceError):
        assert_source_verified_for_cluster(src)


def test_empty_cluster_treated_as_non_mainnet(monkeypatch):
    monkeypatch.delenv(CLUSTER_ENV, raising=False)
    src = ListStreamSource([])
    # No raise: an unset cluster is not mainnet by definition.
    assert_source_verified_for_cluster(src)


# ----------------------------------------------------------------------------
# GeyserIndexer constructor — wired through
# ----------------------------------------------------------------------------

def test_geyser_indexer_constructor_refuses_unverified_on_mainnet(monkeypatch):
    from indexer.runner import GeyserIndexer

    monkeypatch.setenv(CLUSTER_ENV, "mainnet")
    src = ListStreamSource([])
    writer = object()
    with pytest.raises(UnverifiedStreamSourceError):
        GeyserIndexer(src, writer)


def test_geyser_indexer_constructor_accepts_unverified_on_devnet(monkeypatch):
    from indexer.runner import GeyserIndexer

    monkeypatch.setenv(CLUSTER_ENV, "devnet")
    src = ListStreamSource([])
    GeyserIndexer(src, _stub_writer())  # no raise


def test_geyser_indexer_constructor_accepts_verified_on_mainnet(monkeypatch):
    from indexer.runner import GeyserIndexer

    class FakeVerifiedSource(ListStreamSource):
        is_verified_consensus_source = True

    monkeypatch.setenv(CLUSTER_ENV, "mainnet")
    src = FakeVerifiedSource([])
    GeyserIndexer(src, _stub_writer())  # no raise
