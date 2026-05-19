"""
oracle/cluster/identity.py — oracle-node identity and signing.

A cluster node has a cryptographic IDENTITY: an Ed25519 keypair (Solana's
signature scheme). The node's public key is its on-chain identity — it is
one of the `oracle_keys` in the `OracleConfig` PDA — and the node SIGNS its
commit-reveal messages so peers can verify authorship.

WHERE THIS SITS RELATIVE TO THE DETERMINISM RULE
------------------------------------------------
Helixor keeps zero runtime dependencies in the DETERMINISM-critical path —
feature extraction, scoring, consensus arithmetic — so the cluster reaches
byte-identical conclusions on every machine. Signing is NOT in that path:
it is an edge concern (authenticating who sent a message), and a signature
over a fixed message is itself deterministic. So this module uses the
`cryptography` library's Ed25519 — the same primitive Solana uses — which
is correct and appropriate at this edge.

The `NodeKeypair` abstraction means the rest of the node code depends on
the *interface*, not on `cryptography` directly.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass


# Ed25519 via the `cryptography` library — Solana's signature scheme.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    _ED25519_AVAILABLE = True
except ImportError:                                # pragma: no cover
    _ED25519_AVAILABLE = False


class SigningUnavailable(RuntimeError):
    """Raised when Ed25519 signing is needed but `cryptography` is absent."""


# =============================================================================
# NodeIdentity — a node's public identity
# =============================================================================

@dataclass(frozen=True, slots=True)
class NodeIdentity:
    """
    A node's PUBLIC identity — safe to share with peers and to publish in
    the on-chain OracleConfig. Carries no secret material.

    `node_id` is the human-readable cluster id (e.g. "oracle-node-0").
    `public_key` is the 32-byte Ed25519 public key — the node's on-chain
    pubkey.
    """
    node_id:    str
    public_key: bytes

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("NodeIdentity.node_id must be non-empty")
        if len(self.public_key) != 32:
            raise ValueError(
                f"public_key must be 32 bytes, got {len(self.public_key)}"
            )

    @property
    def public_key_b64(self) -> str:
        """The public key, base64 — a convenient display / config form."""
        return base64.b64encode(self.public_key).decode("ascii")

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify `signature` over `message` against this node's public key.
        Returns False on any verification failure (never raises for a bad
        signature — only for a missing crypto backend).
        """
        if not _ED25519_AVAILABLE:                  # pragma: no cover
            raise SigningUnavailable(
                "Ed25519 verification needs the 'cryptography' package"
            )
        try:
            pub = Ed25519PublicKey.from_public_bytes(self.public_key)
            pub.verify(signature, message)
            return True
        except Exception:                           # noqa: BLE001
            return False


# =============================================================================
# NodeKeypair — a node's full keypair (holds the secret)
# =============================================================================

class NodeKeypair:
    """
    A node's Ed25519 keypair. Holds the SECRET key — never serialised, never
    logged, never sent over the wire. A node signs its commit-reveal
    messages with this; peers verify with the matching `NodeIdentity`.

    Construct a fresh random keypair with `generate`, or a DETERMINISTIC one
    from a seed with `from_seed` — the latter is for reproducible tests and
    must NEVER be used for a production node.
    """

    __slots__ = ("_node_id", "_private_key", "_identity")

    def __init__(self, node_id: str, private_key: "Ed25519PrivateKey") -> None:
        if not _ED25519_AVAILABLE:                  # pragma: no cover
            raise SigningUnavailable(
                "NodeKeypair needs the 'cryptography' package for Ed25519"
            )
        self._node_id = node_id
        self._private_key = private_key
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._identity = NodeIdentity(node_id=node_id, public_key=public_bytes)

    # ── Constructors ────────────────────────────────────────────────────────

    @classmethod
    def generate(cls, node_id: str) -> "NodeKeypair":
        """A fresh, random keypair — the production path."""
        if not _ED25519_AVAILABLE:                  # pragma: no cover
            raise SigningUnavailable(
                "NodeKeypair.generate needs the 'cryptography' package"
            )
        return cls(node_id, Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, node_id: str, seed: bytes) -> "NodeKeypair":
        """
        A DETERMINISTIC keypair from a 32-byte seed. For reproducible tests
        and local simulations ONLY — a production node must use `generate`.
        """
        if not _ED25519_AVAILABLE:                  # pragma: no cover
            raise SigningUnavailable(
                "NodeKeypair.from_seed needs the 'cryptography' package"
            )
        # Ed25519 private keys are exactly 32 bytes — derive deterministically.
        material = hashlib.sha256(seed).digest()
        priv = Ed25519PrivateKey.from_private_bytes(material)
        return cls(node_id, priv)

    # ── Identity ────────────────────────────────────────────────────────────

    @property
    def identity(self) -> NodeIdentity:
        """The node's PUBLIC identity — safe to share."""
        return self._identity

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def public_key(self) -> bytes:
        return self._identity.public_key

    # ── Signing ─────────────────────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        """Sign `message` with the node's secret key. Returns a 64-byte sig."""
        return self._private_key.sign(message)

    def __repr__(self) -> str:
        # Never expose secret material in a repr.
        return f"NodeKeypair(node_id={self._node_id!r}, public)"
