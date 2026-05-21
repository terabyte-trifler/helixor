"""
oracle/cluster/run_cluster_node.py — run one oracle node as a gRPC process.

Day 24's spec: "3 node processes (locally: 3 ports; production: 3 VMs in 3
regions)." This is the entrypoint that makes a node a real OS process
listening on a real port.

LOCALLY — three terminals, three ports:

    python -m oracle.cluster.run_cluster_node --node-id oracle-node-0 \\
        --port 50051 --peers oracle-node-1=localhost:50052,oracle-node-2=localhost:50053
    python -m oracle.cluster.run_cluster_node --node-id oracle-node-1 \\
        --port 50052 --peers oracle-node-0=localhost:50051,oracle-node-2=localhost:50053
    python -m oracle.cluster.run_cluster_node --node-id oracle-node-2 \\
        --port 50053 --peers oracle-node-0=localhost:50051,oracle-node-1=localhost:50052

PRODUCTION — the same command on three VMs in three regions, with each
node's `--peers` pointing at the others' public addresses.

HONEST SCOPE
------------
This harness needs `grpcio` and the generated protobuf stubs — it is a
DEPLOYMENT entrypoint, not part of the test path. The test suite uses
`InProcessTransport`, which is a faithful model of the network (it routes
to a peer's real handler) and needs no gRPC. So the cluster protocol is
fully verified without this file; this file is how you actually deploy it.

The node it serves is the same `OracleNode` the tests exercise — this
module only wraps it in a gRPC server and a `GrpcTransport` to peers.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from oracle.cluster.grpc_transport import (
    GrpcTransport,
    PeerDirectory,
    make_grpc_servicer,
)
from oracle.cluster.identity import NodeKeypair
from oracle.node import ClusterMembership, OracleNode

logger = logging.getLogger("helixor.oracle.cluster.harness")


def _parse_peers(spec: str) -> dict[str, str]:
    """Parse `id=host:port,id=host:port` into {node_id: address}."""
    peers: dict[str, str] = {}
    if not spec:
        return peers
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError(f"bad --peers entry {item!r} (want id=host:port)")
        node_id, address = item.split("=", 1)
        peers[node_id.strip()] = address.strip()
    return peers


def build_node(
    node_id:    str,
    peer_addrs: dict[str, str],
    *,
    seed:       bytes | None = None,
) -> OracleNode:
    """
    Build an `OracleNode` for a gRPC deployment: a keypair, a membership
    from the peer list, and a `GrpcTransport` pointed at the peers.

    `seed` makes the keypair deterministic — for a reproducible local
    cluster. A production node omits it and gets a fresh random keypair.
    """
    keypair = (
        NodeKeypair.from_seed(node_id, seed) if seed is not None
        else NodeKeypair.generate(node_id)
    )
    # Peer identities. In a real deployment a node learns its peers'
    # pubkeys from the on-chain OracleConfig.oracle_keys; here, for the
    # local harness, peers are seeded deterministically by id.
    peers = tuple(
        NodeKeypair.from_seed(pid, pid.encode()).identity
        for pid in sorted(peer_addrs)
    )
    membership = ClusterMembership(self_identity=keypair.identity, peers=peers)
    transport = GrpcTransport(PeerDirectory(peer_addrs))
    return OracleNode(keypair, membership, transport=transport)


def serve(node: OracleNode, port: int) -> None:
    """
    Start a gRPC server for `node` on `port` and block until interrupted.
    Needs grpcio — imported here so importing this module does not.
    """
    import grpc
    from concurrent import futures

    from oracle.proto import cluster_pb2_grpc

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    cluster_pb2_grpc.add_OracleClusterServicer_to_server(
        make_grpc_servicer(node), server,
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logger.info("node %s serving on port %d (%d-node cluster)",
                node.node_id, port, node.membership.size)

    stop = threading.Event()

    def _shutdown(*_args):
        logger.info("node %s shutting down", node.node_id)
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    stop.wait()
    server.stop(grace=2.0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one Helixor oracle node as a gRPC process.",
    )
    parser.add_argument("--node-id", required=True,
                        help="this node's cluster id, e.g. oracle-node-0")
    parser.add_argument("--port", type=int, required=True,
                        help="the port to serve gRPC on")
    parser.add_argument("--peers", default="",
                        help="comma-separated id=host:port for each peer")
    parser.add_argument("--seed", default="",
                        help="optional deterministic keypair seed "
                             "(local clusters only — never in production)")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # ── Day 30: mainnet refusal gate ────────────────────────────────────────
    # Refuse to start against mainnet without an explicit HELIXOR_MAINNET_OK
    # opt-in. The guard reads the env, logs the verdict, and raises
    # ProductionRefused on misconfig — caught by the outer try/except below
    # so the operator sees a clear error message rather than a stack trace.
    from oracle.network_guard import enforce_network_guard, ProductionRefused
    try:
        enforce_network_guard(service=f"oracle-node:{args.node_id}")
    except ProductionRefused as exc:
        # The error message itself is the runbook.
        logger.error(str(exc))
        return 2

    try:
        peer_addrs = _parse_peers(args.peers)
        seed = args.seed.encode() if args.seed else None
        node = build_node(args.node_id, peer_addrs, seed=seed)
        serve(node, args.port)
        return 0
    except KeyboardInterrupt:                        # pragma: no cover
        return 0
    except Exception as exc:                         # noqa: BLE001
        logger.error("node failed to start: %s", exc)
        return 1


if __name__ == "__main__":                           # pragma: no cover
    sys.exit(main())
