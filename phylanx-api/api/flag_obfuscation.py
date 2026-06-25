"""
api/flag_obfuscation.py — VULN-24 mitigation #4: public flag obfuscation.

THE EVASION THIS BLOCKS
-----------------------
The on-chain `HealthCertificate.flags` is a u32 bitmask where bit
positions correspond 1:1 to specific detectors:

  bit 5  = ENSEMBLE_INCOMPLETE
  bit 6  = DIMENSION_CLAMPED
  bit 8  = drift.PSI    bit 16 = anomaly.METHOD_1
  bit 10 = drift.CUSUM  bit 21 = anomaly.ISOFOREST
  …                      …

An adversarial-ML attacker can read the flags from a public endpoint
after each epoch and learn EXACTLY which detectors fired on the agent's
last input. With that feedback loop, they craft the next epoch's input
to flip just the bits they need flipped — the metric becomes
differentiable from the attacker's seat.

THE FIX
-------
The on-chain bitmask stays exactly as it is — verifiers and oracle
nodes need the raw bits to challenge byzantine reveals. But the PUBLIC
REST API returns:

  flag_set_token  — an opaque sha256-derived hex digest over the
                    (flags, agent_wallet, epoch) tuple. Two epochs
                    with the same flags produce DIFFERENT tokens for
                    the same agent, and different agents with the
                    same flags produce different tokens. The token
                    leaks zero bits about WHICH detectors fired.
  flag_count      — the number of bits set (popcount). A consumer
                    that wants to display "N detectors fired" still
                    can, without learning the bit identities.

The `immediate_red` boolean stays as a top-level field because that
is the ONE bit a consumer must be able to act on (it is the
fast-path red-alert signal). Every other bit is detector-internal.

DETERMINISM
-----------
Pure function. Same inputs → byte-identical outputs across the API
fleet. The token is NOT meant to be unguessable in a cryptographic
sense (a brute-force over a single epoch can match a token to a
flag-set if the attacker knows all candidate flag-sets); it is meant
to break the per-epoch read-then-craft feedback loop by removing the
canonical mapping. Combined with the audit's other three mitigations
(window jitter, ensemble quorum, per-dim velocity guard), the loop
is broken in three independent ways.
"""

from __future__ import annotations

import hashlib


# Algorithm version of the token construction. Bumping rotates every
# emitted token across the API fleet; folded into the hash so an algo
# change deterministically changes outputs.
FLAG_OBFUSCATION_ALGO_VERSION: int = 1

# Token width in hex chars. 16 hex chars = 64 bits — long enough that
# collisions across a normal request volume are not a concern, short
# enough to keep response bodies compact.
TOKEN_HEX_CHARS: int = 16


def popcount(flags: int) -> int:
    """Number of 1-bits in `flags`. Validates the bitmask is a u32."""
    if not isinstance(flags, int) or isinstance(flags, bool):
        raise TypeError(f"flags must be int, got {type(flags).__name__}")
    if not (0 <= flags <= 0xFFFFFFFF):
        raise ValueError(f"flags must be a u32 (0..2^32-1), got {flags}")
    return bin(flags).count("1")


def compute_flag_token(
    *,
    flags:        int,
    agent_wallet: str,
    epoch:        int,
) -> str:
    """
    An opaque 16-hex-char token derived from `(flags, agent_wallet, epoch)`.

    Two requests for the SAME agent at the SAME epoch produce the same
    token (deterministic across API replicas). Different agents, or the
    same agent at a different epoch, produce different tokens even when
    `flags` is identical — so an observer cannot equate token equality
    across epochs with "same detectors fired".

    Pure / deterministic. Raises on out-of-range inputs.
    """
    if not isinstance(flags, int) or isinstance(flags, bool):
        raise TypeError(f"flags must be int, got {type(flags).__name__}")
    if not (0 <= flags <= 0xFFFFFFFF):
        raise ValueError(f"flags must be a u32 (0..2^32-1), got {flags}")
    if not isinstance(agent_wallet, str) or not agent_wallet:
        raise ValueError("agent_wallet must be a non-empty string")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise ValueError(f"epoch must be a non-negative int, got {epoch!r}")

    wallet_bytes = agent_wallet.encode("utf-8")

    h = hashlib.sha256()
    h.update(b"phylanx-flag-token\x00")
    h.update(FLAG_OBFUSCATION_ALGO_VERSION.to_bytes(2, "big"))
    h.update(flags.to_bytes(4, "big"))
    h.update(epoch.to_bytes(8, "big"))
    h.update(len(wallet_bytes).to_bytes(2, "big"))
    h.update(wallet_bytes)

    return h.hexdigest()[:TOKEN_HEX_CHARS]
