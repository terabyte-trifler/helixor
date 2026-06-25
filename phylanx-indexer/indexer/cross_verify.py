"""
indexer/cross_verify.py — VULN-11 mitigation #2: independent RPC cross-check.

THE PRINCIPLE
-------------
The signed-envelope verifier (`indexer/auth.py`) proves that a streamed
update was produced by a trusted Geyser source. But if that source is
itself compromised — a Helius cluster signing forged updates, or a
malicious plugin binary loaded into a validator — the signature is
authentic and the bytes still lie.

The defence is INDEPENDENT-CHANNEL cross-verification: for a sample of
streamed updates, hit a DIFFERENT RPC endpoint (a plain `getTransaction`
call against a node that does NOT share the Geyser endpoint's identity)
and check that what they report matches what the stream told us.

Disagreement on (slot, success) is the smoking gun — only the on-chain
truth is the same for both channels; a forgery diverges. We REJECT the
update on disagreement, increment a counter, and surface to the runner.
The deployment alerts on a non-zero rejection rate.

WHY SAMPLE
----------
Cross-checking every update would double RPC cost and add per-update
latency, defeating the 500ms SLA. A small sample (default 5%) is enough
to detect a systematic forge — an attacker who knows the sample rate
still cannot predict WHICH updates we will sample, so the only way to
avoid detection is to never lie. That is the deterrent we want.

PURE / TESTABLE
---------------
The RPC client is behind the `RpcSignatureVerifier` Protocol. Tests
inject a `FakeRpcVerifier`; deployment supplies a real one calling
`getTransaction`. The sampler uses an injected `random.Random` so tests
are deterministic.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from indexer.types import GeyserTransactionUpdate

logger = logging.getLogger("phylanx.indexer.cross_verify")


# =============================================================================
# Exceptions
# =============================================================================

class CrossVerificationFailed(Exception):
    """An update's stream-reported state disagrees with the independent RPC."""


# =============================================================================
# RPC contract
# =============================================================================

@dataclass(frozen=True, slots=True)
class RpcSignatureStatus:
    """
    The fields we cross-check from an independent RPC.

    `slot` is the slot the transaction landed in; `is_successful` is
    `meta.err is None`. These are the two fields a forger MUST get right
    AND that an honest RPC would always agree on.
    """
    slot:          int
    is_successful: bool


@runtime_checkable
class RpcSignatureVerifier(Protocol):
    """
    The protocol the cross-verifier calls. Implementations:

      * `JsonRpcSignatureVerifier`  — deployment, calls `getTransaction`
        against an RPC endpoint independent of the Geyser source.
      * `FakeRpcVerifier`           — tests.

    Returning `None` means "the RPC has no record of this signature" —
    treated by `SamplingCrossVerifier` as a verification FAILURE, because
    a streamed update with no on-chain trace is the forge signature.
    """

    def fetch_status(self, signature: str) -> RpcSignatureStatus | None: ...


# =============================================================================
# SamplingCrossVerifier — the gate
# =============================================================================

class SamplingCrossVerifier:
    """
    Wraps a stream of `GeyserTransactionUpdate`s and randomly samples a
    fraction `sample_rate` for cross-verification against an independent
    RPC. Updates that pass (or are not sampled) flow through. Updates that
    FAIL the cross-check are dropped and counted.

    `sample_rate=0.0`  — disable cross-verification (pass-through).
    `sample_rate=1.0`  — verify every update (test / paranoia mode).
    `sample_rate=0.05` — production default; statistically detects a
                        systematic forge within ~60 updates.

    Determinism: callers can pass `rng=random.Random(seed)` for
    reproducible test sampling. In production, leave it None (default
    `random.Random()` with system entropy) so an attacker cannot predict
    the sampling sequence and time their forgeries around it.
    """

    __slots__ = (
        "_source", "_verifier", "_sample_rate", "_rng",
        "_sampled", "_passed", "_rejected", "_last_error",
    )

    def __init__(
        self,
        source:       Iterator[GeyserTransactionUpdate],
        verifier:     RpcSignatureVerifier,
        sample_rate:  float = 0.05,
        rng:          random.Random | None = None,
    ) -> None:
        if not 0.0 <= sample_rate <= 1.0:
            raise ValueError(
                f"sample_rate must be in [0.0, 1.0], got {sample_rate}"
            )
        self._source = source
        self._verifier = verifier
        self._sample_rate = sample_rate
        self._rng = rng if rng is not None else random.Random()
        self._sampled = 0
        self._passed = 0
        self._rejected = 0
        self._last_error: str | None = None

    @property
    def sampled_count(self) -> int:
        return self._sampled

    @property
    def passed_count(self) -> int:
        return self._passed

    @property
    def rejected_count(self) -> int:
        return self._rejected

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def updates(self) -> Iterator[GeyserTransactionUpdate]:
        """
        Yield every update that either was not sampled OR was sampled and
        passed cross-verification.
        """
        for update in self._source:
            if self._sample_rate <= 0.0 or self._rng.random() >= self._sample_rate:
                yield update
                continue

            self._sampled += 1
            try:
                _check_against_rpc(update, self._verifier)
            except CrossVerificationFailed as exc:
                self._rejected += 1
                self._last_error = str(exc)
                logger.warning(
                    "cross-verification failed for signature %s: %s",
                    update.signature[:16], exc,
                )
                continue

            self._passed += 1
            yield update


# =============================================================================
# The pure check — exported for callers that want eager (un-sampled) checks
# =============================================================================

def cross_check(
    update:   GeyserTransactionUpdate,
    verifier: RpcSignatureVerifier,
) -> None:
    """
    Hit `verifier` for `update.signature` and raise
    `CrossVerificationFailed` if the result disagrees with the stream.

    Disagreement cases (any one fails closed):
      * RPC has no record of the signature.
      * RPC reports a different slot.
      * RPC reports a different `is_successful`.
    """
    _check_against_rpc(update, verifier)


def _check_against_rpc(
    update:   GeyserTransactionUpdate,
    verifier: RpcSignatureVerifier,
) -> None:
    status = verifier.fetch_status(update.signature)
    if status is None:
        raise CrossVerificationFailed(
            f"independent RPC has no record of signature {update.signature[:16]}"
        )
    if status.slot != update.slot:
        raise CrossVerificationFailed(
            f"slot mismatch: stream={update.slot}, rpc={status.slot}"
        )
    if status.is_successful != update.is_successful:
        raise CrossVerificationFailed(
            f"success-flag mismatch: stream={update.is_successful}, "
            f"rpc={status.is_successful}"
        )


__all__ = [
    "CrossVerificationFailed",
    "RpcSignatureStatus", "RpcSignatureVerifier",
    "SamplingCrossVerifier", "cross_check",
]
