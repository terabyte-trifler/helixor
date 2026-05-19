"""
oracle/cluster/transport.py — the cluster transport abstraction.

A node talks to its peers through a `ClusterTransport`. Two implementations:

  - `InProcessTransport` — peers are objects in the same process, wired
    into a shared registry. No sockets, no gRPC, fully deterministic.
    This is what the test suite and a single-process simulation use, and
    it is what lets the cluster protocol be developed and tested with ZERO
    gRPC dependency.
  - `GrpcTransport` (oracle/cluster/grpc_transport.py) — the real
    inter-node transport over gRPC. It translates the native messages
    (oracle/cluster/messages.py) to/from the generated protobuf at the
    socket boundary, so the node logic never sees protobuf.

Both satisfy the `ClusterTransport` Protocol, so a node is identical
whether it runs in a test harness or a real 5-node deployment.

THE SERVER SIDE — `ClusterService`
----------------------------------
A node also has to ANSWER its peers' RPCs. `ClusterService` is the
interface a node implements to be a server; the transport routes an
inbound RPC to it. Day 23 ships `PingService` (the liveness handler);
Days 24-28 add the commit / reveal handlers.
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from oracle.cluster.messages import (
    CommitRequest,
    CommitResponse,
    PingRequest,
    PingResponse,
    RevealRequest,
    RevealResponse,
)


# =============================================================================
# The server-side interface — what a node implements to answer peers
# =============================================================================

@runtime_checkable
class ClusterService(Protocol):
    """The handler interface a node exposes to its peers."""

    def ping(self, request: PingRequest) -> PingResponse: ...

    def commit(self, request: CommitRequest) -> CommitResponse: ...

    def reveal(self, request: RevealRequest) -> RevealResponse: ...


# =============================================================================
# The client-side interface — how a node calls a peer
# =============================================================================

@runtime_checkable
class ClusterTransport(Protocol):
    """
    The client side: how a node sends an RPC to a peer identified by id.
    A node holds one transport and uses it to reach every peer.
    """

    def ping(self, peer_id: str, request: PingRequest) -> PingResponse: ...

    def commit(self, peer_id: str, request: CommitRequest) -> CommitResponse: ...

    def reveal(self, peer_id: str, request: RevealRequest) -> RevealResponse: ...


class PeerUnreachable(Exception):
    """Raised when a transport cannot reach a named peer."""


# =============================================================================
# InProcessTransport — peers in the same process
# =============================================================================

class InProcessRegistry:
    """
    A shared registry mapping node_id -> ClusterService. Every node in an
    in-process cluster registers its service here; an InProcessTransport
    routes RPCs through it.

    This is a faithful model of the network: a call to a peer invokes that
    peer's real service handler — the same code path the gRPC transport
    would reach over a socket — just without the socket. Thread-safe.
    """

    def __init__(self) -> None:
        self._services: dict[str, ClusterService] = {}
        self._lock = threading.RLock()

    def register(self, node_id: str, service: ClusterService) -> None:
        with self._lock:
            if node_id in self._services:
                raise ValueError(f"node {node_id} already registered")
            self._services[node_id] = service

    def unregister(self, node_id: str) -> None:
        """Remove a node — models a node going offline."""
        with self._lock:
            self._services.pop(node_id, None)

    def get(self, node_id: str) -> ClusterService | None:
        with self._lock:
            return self._services.get(node_id)

    def members(self) -> list[str]:
        with self._lock:
            return sorted(self._services)


class InProcessTransport:
    """
    A `ClusterTransport` that routes RPCs through an `InProcessRegistry`.

    A call to `ping(peer_id, ...)` looks the peer up in the registry and
    invokes its real service handler. An unregistered (offline) peer raises
    `PeerUnreachable` — the same failure a gRPC transport surfaces when a
    socket connection fails — so failure handling is exercised identically.
    """

    def __init__(self, registry: InProcessRegistry) -> None:
        self._registry = registry

    def _service(self, peer_id: str) -> ClusterService:
        service = self._registry.get(peer_id)
        if service is None:
            raise PeerUnreachable(f"peer {peer_id} is not reachable")
        return service

    def ping(self, peer_id: str, request: PingRequest) -> PingResponse:
        return self._service(peer_id).ping(request)

    def commit(self, peer_id: str, request: CommitRequest) -> CommitResponse:
        return self._service(peer_id).commit(request)

    def reveal(self, peer_id: str, request: RevealRequest) -> RevealResponse:
        return self._service(peer_id).reveal(request)
