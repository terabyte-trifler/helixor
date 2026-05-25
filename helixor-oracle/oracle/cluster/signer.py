"""
oracle/cluster/signer.py — VULN-25 mitigation: pluggable signing surface.

THE EVASION THIS BLOCKS
-----------------------
The oracle node's Ed25519 private key sits in memory during every
signing operation. A supply-chain compromise of `cryptography` (or
any dependency that ends up transitively imported alongside it) is
worst-case CATASTROPHIC: a malicious release can exfiltrate the key
on first `sign()` call, and the attacker holds a valid cluster key
for the rest of the epoch.

THE FIX
-------
Three layers of defence:

  1. **Narrow interface** — every call site that needs a signature
     depends on the `Signer` Protocol, not on `NodeKeypair` directly.
     A future HSM-backed implementation drops in without changing the
     callers.

  2. **HSM-ready swap point** — `HSMSigner` is a typed stub that
     raises NotImplementedError today. Production deployments wire
     in a real HSM client (YubiHSM, AWS KMS, Cubist, Fireblocks
     MPC, etc.) by subclassing it. When that happens the private
     key NEVER lives in oracle-node process memory; the HSM
     performs the Ed25519 operation behind a hardware boundary.

  3. **Hash-locked deps** — the `cryptography` library version that
     produces signatures off the in-process `InProcessSigner` is
     pinned by SHA256 in `helixor-oracle/requirements.txt`. A
     supply-chain swap fails the `--require-hashes` install before
     the bytes ever load.

This module contains NO crypto primitives itself — `InProcessSigner`
delegates to `oracle.cluster.identity.NodeKeypair`, which is the
SINGLE place `cryptography` is imported. That import boundary is
what the supply-chain audit scanner pins.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


# =============================================================================
# Signer protocol — the narrow surface every caller depends on
# =============================================================================

@runtime_checkable
class Signer(Protocol):
    """
    A minimal Ed25519 signing surface.

    Two attributes are required:
      - `public_key`: the 32-byte Ed25519 public key (so the cert
        builder can attach the right precompile pubkey).
      - `sign(message)`: return the 64-byte Ed25519 signature.

    Two concrete implementations satisfy this Protocol:
      - `InProcessSigner` (this module) — wraps a `NodeKeypair`.
      - `HSMSigner` (stub) — the wire-up point for an HSM-backed
        signer that never holds the secret in process memory.
    """

    @property
    def public_key(self) -> bytes:
        ...

    def sign(self, message: bytes) -> bytes:
        ...


# =============================================================================
# In-process signer — the default today
# =============================================================================

class InProcessSigner:
    """
    Wraps a `NodeKeypair` in the `Signer` protocol. The private key
    lives in this process's memory.

    `cryptography`'s `Ed25519PrivateKey.sign()` is called inside
    `NodeKeypair.sign`; we do NOT import `cryptography` here. That
    keeps the supply-chain blast surface to ONE module
    (`oracle/cluster/identity.py`).
    """

    __slots__ = ("_keypair",)

    def __init__(self, keypair) -> None:  # type: NodeKeypair  (avoid import cycle)
        # Duck-typed: any object exposing `public_key` and `sign` works.
        # We refuse the construction if the duck-type is wrong so a
        # misconfigured wiring fails loudly here, not at sign time.
        if not hasattr(keypair, "public_key") or not callable(
            getattr(keypair, "sign", None)
        ):
            raise TypeError(
                "InProcessSigner needs an object with `.public_key` and "
                f"a callable `.sign`, got {type(keypair).__name__}"
            )
        self._keypair = keypair

    @property
    def public_key(self) -> bytes:
        return self._keypair.public_key

    def sign(self, message: bytes) -> bytes:
        return self._keypair.sign(message)

    def __repr__(self) -> str:
        # Never expose secret material — defer to the keypair's own
        # secret-free repr.
        return f"InProcessSigner({self._keypair!r})"


# =============================================================================
# HSM-backed signer — the production wire-up point
# =============================================================================

class HSMSigner:
    """
    A typed stub for an HSM-backed Ed25519 signer.

    THE PRIVATE KEY NEVER LIVES IN PROCESS MEMORY when this is in
    use. A production deployment subclasses this and routes `sign`
    through the chosen HSM (YubiHSM, AWS KMS, Cubist, Fireblocks
    MPC, etc.). The base class refuses to sign so a misconfigured
    mainnet deploy that forgot to wire the HSM fails LOUDLY rather
    than silently falling back to an in-process key.

    Construction takes the HSM-resident key's 32-byte Ed25519 PUBLIC
    key (needed off-box to populate cert precompile records and the
    OracleConfig PDA). Subclasses implement `sign`.
    """

    __slots__ = ("_public_key",)

    def __init__(self, public_key: bytes) -> None:
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise ValueError(
                "HSMSigner.public_key must be a 32-byte Ed25519 pubkey, "
                f"got {len(public_key) if hasattr(public_key, '__len__') else type(public_key).__name__}"
            )
        self._public_key = bytes(public_key)

    @property
    def public_key(self) -> bytes:
        return self._public_key

    def sign(self, message: bytes) -> bytes:  # noqa: ARG002
        # Subclasses MUST override. The base raises so a misconfigured
        # production deploy fails before it can mint a cert.
        raise NotImplementedError(
            "HSMSigner is a stub — subclass and route `sign` through your "
            "HSM client. The base refuses on purpose: a silent fallback "
            "to in-process signing would defeat VULN-25 mitigation #2."
        )

    def __repr__(self) -> str:
        return "HSMSigner(<HSM-resident key>)"
