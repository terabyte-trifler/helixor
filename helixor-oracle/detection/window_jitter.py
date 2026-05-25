"""
detection/window_jitter.py — VULN-24 mitigation #1: per-(agent, epoch)
deterministic evaluation-window jitter.

THE EVASION THIS BLOCKS
-----------------------
If the scoring window is `[epoch_start, epoch_end]` for every agent on
every epoch, a reinforcement-learning adversary learns to behave well
inside that window and badly outside it. The window is the metric; the
metric is what gets gamed.

THE FIX
-------
Per-(agent, epoch) deterministic offset bytes hashed from:

  - `agent_pubkey`            — varies per-agent so all agents don't shift together
  - `epoch_number`            — varies per-epoch so the offset is not static
  - `epoch_advance_seed`      — the UNPREDICTABLE input. The cluster passes
                                in the on-chain `EpochState.last_advanced_at`
                                (unix-seconds block time of the epoch-advance
                                tx). The attacker cannot predict the exact
                                block time of a future epoch advance, so
                                they cannot precompute their future-epoch
                                jitters and pre-time their misbehaviour.
  - `scoring_algo_version`    — same versioning chain as the rest of scoring,
                                so an algo bump rotates the jitter mapping.

THE SEED CONTRACT
-----------------
`epoch_advance_seed` MUST be a value all cluster nodes agree on (otherwise
consensus breaks) AND that the attacker cannot predict before the epoch
starts. The on-chain `EpochState.last_advanced_at` (i64 unix seconds)
satisfies both. A future implementation can swap in a recent slot hash
or a VRF output; the helper signature stays stable.

If the cluster ever passes a CONSTANT seed (e.g. an empty bytes literal),
the jitter still varies per-(agent, epoch) — which is better than
nothing — but the attacker can precompute. The audit scanner refuses
that pattern (`adversarial_ml_check.py`).

DETERMINISM
-----------
Pure function. Same inputs → byte-identical outputs across nodes. Used
by both the commit and reveal paths so all cluster nodes evaluate the
same agent over the same sub-window.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

# Maximum jitter applied to either window boundary, in seconds. Bounded
# so the evaluated window stays meaningfully inside the epoch window —
# at MAX_JITTER_SECONDS=600 we move each boundary by up to ±10 minutes
# inside a daily (86_400s) epoch.
MAX_JITTER_SECONDS:    int = 600

# Algorithm version of the jitter formula. Bump on any change to the
# input layout or hash construction; folded into the hash to ensure a
# different algo version produces a different jitter for the same agent.
JITTER_ALGO_VERSION:   int = 1


# =============================================================================
# Result
# =============================================================================

@dataclass(frozen=True, slots=True)
class EvaluationWindow:
    """The jittered sub-window an agent is evaluated over for one epoch.

    `start_offset_seconds` is added to the epoch's start; positive values
    move the start LATER. `end_offset_seconds` is subtracted from the
    epoch's end; positive values move the end EARLIER. Both are in
    [0, MAX_JITTER_SECONDS], so the jittered window is always a
    non-empty sub-window of the epoch (as long as the epoch is longer
    than 2 * MAX_JITTER_SECONDS).
    """
    start_offset_seconds: int       # in [0, MAX_JITTER_SECONDS]
    end_offset_seconds:   int       # in [0, MAX_JITTER_SECONDS]
    jitter_algo_version:  int


# =============================================================================
# Helper
# =============================================================================

def compute_window_jitter(
    *,
    agent_pubkey:          bytes,
    epoch_number:          int,
    epoch_advance_seed:    bytes,
    scoring_algo_version:  int,
    max_jitter_seconds:    int = MAX_JITTER_SECONDS,
) -> EvaluationWindow:
    """
    Deterministic per-(agent, epoch) jitter offsets.

    The returned offsets are in [0, max_jitter_seconds]. All cluster
    nodes compute the same offsets given the same inputs (consensus
    safe). The attacker cannot predict the offsets without the
    `epoch_advance_seed`, which is unknown until the epoch advances
    on chain.

    `agent_pubkey` SHOULD be the 32-byte Ed25519 public key. Any
    bytes-like value is accepted; length is not enforced because some
    test environments use shorter test pubkeys. The hash absorbs the
    length so two pubkeys of different length cannot collide.

    Raises ValueError on invalid sizing.
    """
    if not isinstance(agent_pubkey, (bytes, bytearray)):
        raise TypeError(
            f"agent_pubkey must be bytes, got {type(agent_pubkey).__name__}"
        )
    if not isinstance(epoch_advance_seed, (bytes, bytearray)):
        raise TypeError(
            f"epoch_advance_seed must be bytes, "
            f"got {type(epoch_advance_seed).__name__}"
        )
    if epoch_number < 0:
        raise ValueError(f"epoch_number must be >= 0, got {epoch_number}")
    if scoring_algo_version < 1:
        raise ValueError(
            f"scoring_algo_version must be >= 1, got {scoring_algo_version}"
        )
    if max_jitter_seconds < 0:
        raise ValueError(
            f"max_jitter_seconds must be >= 0, got {max_jitter_seconds}"
        )

    # Hash construction: length-prefix each field so two different
    # input splits cannot produce the same hash. Banker's-rounding-free,
    # consensus-safe.
    h = hashlib.sha256()
    h.update(b"helixor-window-jitter\x00")
    h.update(JITTER_ALGO_VERSION.to_bytes(2, "big"))
    h.update(scoring_algo_version.to_bytes(4, "big"))
    h.update(len(agent_pubkey).to_bytes(2, "big"))
    h.update(bytes(agent_pubkey))
    h.update(epoch_number.to_bytes(8, "big"))
    h.update(len(epoch_advance_seed).to_bytes(2, "big"))
    h.update(bytes(epoch_advance_seed))
    digest = h.digest()

    # Two independent 4-byte words → two independent offsets in
    # [0, max_jitter_seconds]. The modulo introduces a tiny bias
    # (negligible at these moduli, but called out for honesty).
    cap = max_jitter_seconds + 1
    start_word = int.from_bytes(digest[0:4], "big")
    end_word   = int.from_bytes(digest[4:8], "big")
    start_offset = start_word % cap if cap > 0 else 0
    end_offset   = end_word   % cap if cap > 0 else 0

    return EvaluationWindow(
        start_offset_seconds=start_offset,
        end_offset_seconds=end_offset,
        jitter_algo_version=JITTER_ALGO_VERSION,
    )
