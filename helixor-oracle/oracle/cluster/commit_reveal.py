"""
oracle/cluster/commit_reveal.py — the commit-reveal protocol.

Day 24 had the cluster exchange scores DIRECTLY (the GetScores RPC). That
works only if every node is honest: a node could wait, read a peer's
scores, and echo them — contributing nothing but still counting toward the
median. Day 25 closes that hole with COMMIT-REVEAL.

THE SCHEME
----------
  Phase 1 — COMMIT. Each node computes its epoch scores, picks a random
            secret nonce, and publishes only

                commit_hash = sha256(canonical(scores) || nonce)

            The hash binds the node to those exact scores. It reveals
            nothing — sha256 is one-way, and the nonce makes the (small,
            0..1000) score space un-brute-forceable.

  Phase 2 — REVEAL. Once every node's commit is in, each node reveals its
            (scores, nonce). Every peer recomputes the hash and checks it
            equals the commit. A match PROVES the node held those scores
            BEFORE it saw anyone else's — because the commit was published
            first.

WHY A COPYING NODE FAILS
------------------------
A node that does not score independently has nothing to commit in Phase 1.
Whatever it commits (a guess, a placeholder), it is BOUND to. When it later
tries to reveal a score it copied from a peer's reveal, the copied score
will not hash to its committed value -> verification fails -> the node is
excluded. It cannot change its commit after Phase 1 closes. This is the
Day-25 done-when: "a node attempting to copy another's revealed score
fails hash verification."

CANONICAL SERIALISATION
-----------------------
The hash must be reproducible byte-for-byte by every verifier, so the
scores are serialised CANONICALLY: agents sorted by wallet, each field in
a fixed order, fixed-width integers, no floats, no whitespace ambiguity.
Pure stdlib — this is determinism-critical and stays dependency-free.

DETERMINISM vs THE NONCE
------------------------
Everything here is deterministic EXCEPT nonce generation, which MUST be
unpredictable — a guessable nonce would let an attacker brute-force a
commit. `new_nonce()` uses `secrets`; tests inject fixed nonces. Hash
computation and verification are pure and deterministic.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence

from oracle.cluster.messages import AgentScore


# The nonce is 32 bytes — large enough that it cannot be guessed or
# collided, matching the sha256 output width.
NONCE_BYTES = 32


# =============================================================================
# Nonce
# =============================================================================

def new_nonce() -> bytes:
    """
    A fresh, cryptographically random 32-byte nonce for one commit.

    MUST be unpredictable: the commit hash is sha256(scores || nonce), and
    the score space is tiny (0..1000 per agent). Without a random nonce an
    attacker could brute-force every possible score and match the hash,
    defeating the hiding property. Uses `secrets`, not `random`.
    """
    return secrets.token_bytes(NONCE_BYTES)


# =============================================================================
# Canonical serialisation of an epoch's scores
# =============================================================================

def canonical_scores(scores: Sequence[AgentScore]) -> bytes:
    """
    Serialise a node's epoch scores to a CANONICAL byte string — the same
    bytes on every node, so every verifier recomputes the identical hash.

    Canonical form:
      - agents sorted by wallet (a set of scores has no inherent order),
      - per agent, fields in a FIXED order, each as a fixed-width record,
      - a length prefix so two different agent sets cannot collide.

    Pure + deterministic.
    """
    ordered = sorted(scores, key=lambda s: s.agent_wallet)

    parts: list[bytes] = []
    # Length prefix — binds the COUNT of agents, so [A] and [A, B] differ.
    parts.append(len(ordered).to_bytes(4, "big"))

    for s in ordered:
        wallet = s.agent_wallet.encode("utf-8")
        # wallet length + wallet, so wallets cannot run together ambiguously.
        parts.append(len(wallet).to_bytes(2, "big"))
        parts.append(wallet)
        # Fixed-width integer fields, fixed order. No floats anywhere.
        parts.append(s.score.to_bytes(2, "big"))
        parts.append(s.alert_tier.to_bytes(1, "big"))
        parts.append(s.flags.to_bytes(4, "big"))
        parts.append((1 if s.immediate_red else 0).to_bytes(1, "big"))
        parts.append(s.confidence.to_bytes(2, "big"))

    return b"".join(parts)


# =============================================================================
# Commit hashing + verification
# =============================================================================

# =============================================================================
# VULN-22 — scoring-algo version pin
# =============================================================================
#
# A node running a different (scoring_algo, scoring_weights) version computes
# legitimately different scores for the same inputs — version v2.7 may
# normalise an anomaly score differently than v2.8. If two such nodes are in
# the same epoch, the version-mismatched node's score will sit far from the
# majority median; the Byzantine deviation detector would flag it and the
# watchdog would slash it for what is really a deploy-window delay.
#
# The fix is two-layered:
#
#   1. **Bind version into the commit hash.** A reveal whose (algo, weights)
#      version differs from the commit's version fails hash verification —
#      so a node cannot quietly switch versions mid-round.
#   2. **Pin one version per round** (in commit_reveal_round.py): the first
#      commit pins (algo, weights); subsequent commits with a different
#      version are SILENTLY EXCLUDED, not flagged Byzantine.
#
# `algo_version` is a (scoring_algo_version, scoring_weights_version) tuple.
# Callers may omit it (kwarg is optional) — when omitted, no version bytes
# are folded in and the pre-VULN-22 wire format is preserved for tests that
# pin the legacy hash.

AlgoVersion = tuple[int, int]


def _version_tag_bytes(algo_version: AlgoVersion | None) -> bytes:
    """
    Render the algo-version as 8 deterministic bytes (4 + 4 big-endian
    unsigned ints) to fold into the commit hash. Empty when omitted, so
    the pre-VULN-22 wire format is unchanged for legacy callers.
    """
    if algo_version is None:
        return b""
    algo, weights = algo_version
    if not (0 <= algo <= 0xFFFFFFFF):
        raise ValueError(
            f"scoring_algo_version out of u32 range: {algo}"
        )
    if not (0 <= weights <= 0xFFFFFFFF):
        raise ValueError(
            f"scoring_weights_version out of u32 range: {weights}"
        )
    return algo.to_bytes(4, "big") + weights.to_bytes(4, "big")


def _input_commitment_tag_bytes(
    input_commitments: Sequence[bytes] | None,
) -> bytes:
    """
    AW-01: render the per-agent input commitments as deterministic bytes to
    fold into the commit hash. Layout:

        u32 count (big-endian)
        for each (agent_wallet, commitment), sorted by agent_wallet:
            u16 wallet-length (big-endian) || utf-8 wallet bytes
            32 raw commitment bytes

    The commitment SEQUENCE is paired with the SAME ordering the score set
    is canonicalised under (sort by agent_wallet) so a verifier that has
    the same scores + same input commitments produces the byte-identical
    tag.

    Empty when omitted — preserves the pre-AW-01 wire format for legacy
    callers and tests that pin the prior bytes.
    """
    if input_commitments is None:
        return b""
    # Caller passes pairs as a sequence of (wallet, commitment) tuples.
    # Sort by wallet so the ordering matches `canonical_scores`.
    sorted_pairs = sorted(input_commitments, key=lambda p: p[0])
    parts: list[bytes] = [len(sorted_pairs).to_bytes(4, "big")]
    for wallet, commitment in sorted_pairs:
        if len(commitment) != 32:
            raise ValueError(
                f"input_commitment for {wallet!r} must be 32 bytes, "
                f"got {len(commitment)}"
            )
        wallet_bytes = wallet.encode("utf-8")
        if len(wallet_bytes) > 0xFFFF:
            raise ValueError(
                f"agent_wallet too long for u16 length prefix: "
                f"{len(wallet_bytes)}"
            )
        parts.append(len(wallet_bytes).to_bytes(2, "big"))
        parts.append(wallet_bytes)
        parts.append(bytes(commitment))
    return b"".join(parts)


def compute_commit_hash(
    scores:        Sequence[AgentScore],
    nonce:         bytes,
    *,
    snapshot_hash: bytes | None = None,
    algo_version:  AlgoVersion | None = None,
    input_commitments: Sequence[tuple[str, bytes]] | None = None,
) -> bytes:
    """
    The commit hash:
        sha256( [snapshot_hash ||] [algo_version ||] [input_commitments ||]
                canonical(scores) || nonce )

    Published in Phase 1; binds the node to exactly these scores without
    revealing them.

    VULN-15: when `snapshot_hash` is provided, the hash is folded into the
    commit so the commit binds to BOTH the scores AND the agent set those
    scores were computed against. If the agent set drifts between commit
    and reveal, honest verifiers recompute against a different snapshot
    hash and verification fails LOCALLY — surfacing set drift as a typed
    error instead of "your reveal didn't verify" further downstream.

    VULN-22: when `algo_version=(scoring_algo, scoring_weights)` is
    provided, both ints are folded in (4 + 4 big-endian bytes) so a
    revealing node cannot change versions between commit and reveal.

    AW-01: when `input_commitments` (a sequence of (agent_wallet, 32-byte
    commitment) pairs) is provided, the canonical tag is folded into the
    commit hash. A revealing node that wants to swap inputs after seeing
    peers' commits fails hash verification — its committed input
    commitment is fixed in stone.

    All three kwargs are optional so legacy callers (and tests pinned at
    the prior wire formats) keep working unchanged.
    """
    if len(nonce) != NONCE_BYTES:
        raise ValueError(
            f"nonce must be {NONCE_BYTES} bytes, got {len(nonce)}"
        )
    prefix = snapshot_hash if snapshot_hash is not None else b""
    version_bytes = _version_tag_bytes(algo_version)
    input_bytes = _input_commitment_tag_bytes(input_commitments)
    return hashlib.sha256(
        prefix + version_bytes + input_bytes
        + canonical_scores(scores) + nonce
    ).digest()


def verify_reveal(
    commit_hash:   bytes,
    scores:        Sequence[AgentScore],
    nonce:         bytes,
    *,
    snapshot_hash: bytes | None = None,
    algo_version:  AlgoVersion | None = None,
    input_commitments: Sequence[tuple[str, bytes]] | None = None,
) -> bool:
    """
    Verify a Phase-2 reveal against a Phase-1 commit.

    Returns True iff
        sha256([snapshot_hash ||] [algo_version ||] [input_commitments ||]
               canonical(scores) || nonce)
    equals the earlier `commit_hash` — i.e. the revealed (scores, nonce)
    is exactly what the node committed to. A copying node, whose commit
    does not match the scores it copied, fails here.

    VULN-15: pass `snapshot_hash` to verify against the same agent-set
    snapshot the commit was computed against. If the verifier's snapshot
    differs from the committer's, this returns False — exactly the
    "set drift" signal we want surfaced.

    VULN-22: pass `algo_version` to verify against the same scoring
    (algo, weights) versions the commit was computed against. A revealer
    that switched versions between commit and reveal fails here — no
    silent version drift in-flight.

    AW-01: pass `input_commitments` to verify against the same per-agent
    input-provenance commitments the commit was computed against. A
    revealer that fed itself different upstream transactions between
    commit and reveal fails here — input swaps mid-round are caught at
    the cryptographic layer, not downstream as silent score divergence.

    Uses a constant-time comparison — verification timing must not leak
    how close a forged reveal was.
    """
    if len(nonce) != NONCE_BYTES:
        return False
    try:
        prefix = snapshot_hash if snapshot_hash is not None else b""
        version_bytes = _version_tag_bytes(algo_version)
        input_bytes = _input_commitment_tag_bytes(input_commitments)
        recomputed = hashlib.sha256(
            prefix + version_bytes + input_bytes
            + canonical_scores(scores) + nonce
        ).digest()
    except (ValueError, AttributeError):
        return False
    return secrets.compare_digest(recomputed, commit_hash)
