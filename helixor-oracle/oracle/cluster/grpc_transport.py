"""
oracle/cluster/grpc_transport.py — the gRPC inter-node transport.

This is the EDGE: the real transport that carries cluster RPCs between
oracle nodes on different machines, over gRPC.

DEPENDENCY ISOLATION
--------------------
`grpcio` is a production dependency with a native extension. Helixor's
rule is zero runtime dependencies in the determinism-critical path — and
the cluster LOGIC (node scoring, consensus arithmetic) honours that by
depending only on the native message types and the `ClusterTransport`
interface. This module is where gRPC actually enters, and it is
deliberately the ONLY place:

  - `grpc` and the generated stubs are imported INSIDE the constructor,
    never at module load — importing this module does not require grpcio,
  - the testable cluster logic uses `InProcessTransport` and never imports
    this module at all.

So a developer can build and test the entire cluster protocol with no
gRPC installed; gRPC is needed only to actually deploy nodes on separate
machines.

TRANSLATION AT THE BOUNDARY
---------------------------
The cluster logic speaks the native dataclasses in
`oracle/cluster/messages.py`. gRPC speaks protobuf. This module translates
at the socket boundary — native -> protobuf on the way out, protobuf ->
native on the way in — so the logic never sees a protobuf object.

The protobuf stubs are generated from `oracle/proto/cluster.proto` with:

    python -m grpc_tools.protoc -I oracle/proto \\
        --python_out=oracle/proto --grpc_python_out=oracle/proto \\
        oracle/proto/cluster.proto

That produces `cluster_pb2.py` + `cluster_pb2_grpc.py`. This module is
written against those generated names; the generation step is a build
step, run in an environment with grpcio-tools.
"""

from __future__ import annotations

import logging

from oracle.cluster.messages import (
    AgentScore,
    CommitRequest,
    CommitResponse,
    GetScoresRequest,
    GetScoresResponse,
    PingRequest,
    PingResponse,
    RevealRequest,
    RevealResponse,
)
from oracle.cluster.transport import ClusterService, PeerUnreachable

logger = logging.getLogger("helixor.oracle.cluster.grpc")


# =============================================================================
# Peer address book
# =============================================================================

class PeerDirectory:
    """Maps a peer node_id to its gRPC address ("host:port")."""

    def __init__(self, addresses: dict[str, str]) -> None:
        self._addresses = dict(addresses)

    def address_of(self, peer_id: str) -> str:
        if peer_id not in self._addresses:
            raise PeerUnreachable(f"no address known for peer {peer_id}")
        return self._addresses[peer_id]

    def peer_ids(self) -> list[str]:
        return sorted(self._addresses)


# =============================================================================
# Native <-> protobuf translation
# =============================================================================
#
# These helpers are the ONLY place native message types meet protobuf. They
# are written against the generated `cluster_pb2` names. Kept as free
# functions so they are unit-testable in isolation once the stubs exist.

def _ping_request_to_pb(request: PingRequest, pb2):
    return pb2.PingRequest(node_id=request.node_id, nonce=request.nonce)


def _ping_response_from_pb(message) -> PingResponse:
    return PingResponse(
        node_id=message.node_id,
        nonce=message.nonce,
        current_epoch=message.current_epoch,
    )


def _commit_request_to_pb(request: CommitRequest, pb2):
    return pb2.CommitRequest(
        node_id=request.node_id,
        epoch=request.epoch,
        commit_hash=request.commit_hash,
    )


def _commit_response_from_pb(message) -> CommitResponse:
    return CommitResponse(accepted=message.accepted, reason=message.reason)


def _agent_score_to_pb(score: AgentScore, pb2):
    return pb2.AgentScore(
        agent_wallet=score.agent_wallet,
        score=score.score,
        alert_tier=score.alert_tier,
        flags=score.flags,
        immediate_red=score.immediate_red,
        confidence=score.confidence,
    )


def _reveal_request_to_pb(request: RevealRequest, pb2):
    return pb2.RevealRequest(
        node_id=request.node_id,
        epoch=request.epoch,
        scores=[_agent_score_to_pb(s, pb2) for s in request.scores],
        salt=request.salt,
    )


def _reveal_response_from_pb(message) -> RevealResponse:
    return RevealResponse(verified=message.verified, reason=message.reason)


def _agent_score_from_pb(message) -> AgentScore:
    return AgentScore(
        agent_wallet=message.agent_wallet,
        score=message.score,
        alert_tier=message.alert_tier,
        flags=message.flags,
        immediate_red=message.immediate_red,
        confidence=message.confidence,
    )


def _get_scores_request_to_pb(request: GetScoresRequest, pb2):
    return pb2.GetScoresRequest(node_id=request.node_id, epoch=request.epoch)


def _get_scores_response_from_pb(message) -> GetScoresResponse:
    return GetScoresResponse(
        node_id=message.node_id,
        epoch=message.epoch,
        available=message.available,
        scores=tuple(_agent_score_from_pb(s) for s in message.scores),
    )


# =============================================================================
# GrpcTransport — the client side
# =============================================================================

class GrpcTransport:
    """
    A `ClusterTransport` over gRPC. Each RPC opens (or reuses) a channel to
    the peer's address, translates the native request to protobuf, calls,
    and translates the response back.

    `grpc` and the generated stubs are imported in `__init__` — importing
    this module does not require grpcio.
    """

    def __init__(
        self,
        directory: PeerDirectory,
        *,
        root_certificates: bytes | None = None,
        private_key: bytes | None = None,
        certificate_chain: bytes | None = None,
    ) -> None:
        try:
            import grpc                              # noqa: F401
            from oracle.proto import cluster_pb2, cluster_pb2_grpc  # noqa: F401
        except ImportError as exc:                   # pragma: no cover
            raise RuntimeError(
                "GrpcTransport needs the 'grpcio' package and the generated "
                "protobuf stubs (run grpc_tools.protoc on cluster.proto). "
                "The cluster logic and its tests use InProcessTransport, "
                "which needs neither."
            ) from exc
        self._directory = directory
        self._grpc = grpc
        self._pb2 = cluster_pb2
        self._pb2_grpc = cluster_pb2_grpc
        self._channels: dict[str, object] = {}
        self._root_certificates = root_certificates
        self._private_key = private_key
        self._certificate_chain = certificate_chain

    def _stub(self, peer_id: str):
        address = self._directory.address_of(peer_id)
        if peer_id not in self._channels:
            if self._root_certificates is None:
                self._channels[peer_id] = self._grpc.insecure_channel(address)
            else:
                credentials = self._grpc.ssl_channel_credentials(
                    root_certificates=self._root_certificates,
                    private_key=self._private_key,
                    certificate_chain=self._certificate_chain,
                )
                self._channels[peer_id] = self._grpc.secure_channel(
                    address, credentials,
                )
        return self._pb2_grpc.OracleClusterStub(self._channels[peer_id])

    def ping(self, peer_id: str, request: PingRequest) -> PingResponse:
        try:
            stub = self._stub(peer_id)
            pb_response = stub.Ping(_ping_request_to_pb(request, self._pb2))
            return _ping_response_from_pb(pb_response)
        except self._grpc.RpcError as exc:           # pragma: no cover
            raise PeerUnreachable(f"gRPC Ping to {peer_id} failed: {exc}") from exc

    def commit(self, peer_id: str, request: CommitRequest) -> CommitResponse:
        try:
            stub = self._stub(peer_id)
            pb_response = stub.Commit(_commit_request_to_pb(request, self._pb2))
            return _commit_response_from_pb(pb_response)
        except self._grpc.RpcError as exc:           # pragma: no cover
            raise PeerUnreachable(f"gRPC Commit to {peer_id} failed: {exc}") from exc

    def reveal(self, peer_id: str, request: RevealRequest) -> RevealResponse:
        try:
            stub = self._stub(peer_id)
            pb_response = stub.Reveal(_reveal_request_to_pb(request, self._pb2))
            return _reveal_response_from_pb(pb_response)
        except self._grpc.RpcError as exc:           # pragma: no cover
            raise PeerUnreachable(f"gRPC Reveal to {peer_id} failed: {exc}") from exc

    def get_scores(
        self, peer_id: str, request: GetScoresRequest,
    ) -> GetScoresResponse:
        try:
            stub = self._stub(peer_id)
            pb_response = stub.GetScores(
                _get_scores_request_to_pb(request, self._pb2)
            )
            return _get_scores_response_from_pb(pb_response)
        except self._grpc.RpcError as exc:           # pragma: no cover
            raise PeerUnreachable(
                f"gRPC GetScores to {peer_id} failed: {exc}"
            ) from exc

    def close(self) -> None:
        """Close all open channels."""
        for channel in self._channels.values():
            channel.close()
        self._channels.clear()


# =============================================================================
# GrpcClusterServicer — the server side
# =============================================================================

def make_grpc_servicer(service: ClusterService):
    """
    Build a gRPC servicer that routes inbound RPCs to a node's
    `ClusterService` handlers.

    Returns an object suitable for
    `cluster_pb2_grpc.add_OracleClusterServicer_to_server`. Imports the
    generated stubs lazily — calling this needs grpcio + the stubs.
    """
    try:
        from oracle.proto import cluster_pb2, cluster_pb2_grpc
    except ImportError as exc:                       # pragma: no cover
        raise RuntimeError(
            "make_grpc_servicer needs the generated protobuf stubs"
        ) from exc

    class _Servicer(cluster_pb2_grpc.OracleClusterServicer):
        """Translates inbound protobuf to native, calls the handler, back."""

        def Ping(self, request, context):            # noqa: N802
            native = PingRequest(node_id=request.node_id, nonce=request.nonce)
            response = service.ping(native)
            return cluster_pb2.PingResponse(
                node_id=response.node_id,
                nonce=response.nonce,
                current_epoch=response.current_epoch,
            )

        def Commit(self, request, context):          # noqa: N802
            native = CommitRequest(
                node_id=request.node_id,
                epoch=request.epoch,
                commit_hash=bytes(request.commit_hash),
            )
            response = service.commit(native)
            return cluster_pb2.CommitResponse(
                accepted=response.accepted, reason=response.reason,
            )

        def Reveal(self, request, context):          # noqa: N802
            native = RevealRequest(
                node_id=request.node_id,
                epoch=request.epoch,
                scores=tuple(
                    AgentScore(
                        agent_wallet=s.agent_wallet,
                        score=s.score,
                        alert_tier=s.alert_tier,
                        flags=s.flags,
                        immediate_red=s.immediate_red,
                        confidence=s.confidence,
                    )
                    for s in request.scores
                ),
                salt=bytes(request.salt),
            )
            response = service.reveal(native)
            return cluster_pb2.RevealResponse(
                verified=response.verified, reason=response.reason,
            )

        def GetScores(self, request, context):       # noqa: N802
            native = GetScoresRequest(
                node_id=request.node_id, epoch=request.epoch,
            )
            response = service.get_scores(native)
            return cluster_pb2.GetScoresResponse(
                node_id=response.node_id,
                epoch=response.epoch,
                available=response.available,
                scores=[
                    cluster_pb2.AgentScore(
                        agent_wallet=s.agent_wallet,
                        score=s.score,
                        alert_tier=s.alert_tier,
                        flags=s.flags,
                        immediate_red=s.immediate_red,
                        confidence=s.confidence,
                    )
                    for s in response.scores
                ],
            )

    return _Servicer()
