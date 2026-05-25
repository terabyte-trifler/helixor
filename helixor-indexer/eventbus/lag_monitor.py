"""
eventbus/lag_monitor.py — VULN-14 MITIGATION: consumer-lag awareness for
the certificate-issuance path.

THE AUDIT FINDING (paraphrased)
-------------------------------
HIGH. The detection pipeline is connected to the broker via a consumer
group. An attacker who can inflate publish rate (the VULN-07 fast path, a
geyser-storm) can drive the group's lag well past the epoch boundary —
inducing a STALE SCORING WINDOW. The scoring engine still issues
certificates against the LAST records it managed to process; the records
proving the agent's misbehaviour are sitting unprocessed on the partition
log behind the lag. Result: the oracle keeps emitting GREEN certificates
for an agent whose recent behaviour, if it had been scored, would have
revoked the agent.

THE MITIGATION
--------------
Two pieces, this file is the first one:

  (1) HERE — a `ConsumerLagMonitor` that measures, per-partition and total,
      how many uncommitted records are sitting in the consumer-group
      backlog for a (topic, group). The numbers come from broker
      introspection (committed_offset / high_watermark) that both
      `InMemoryBroker` and any real-Kafka adapter expose.

  (2) `helixor-oracle/oracle/lag_gate.py` — wraps the oracle's per-agent
      `submit_fn` (the cert-write seam — see `oracle/epoch_runner.py`)
      with a pre-flight lag check. If lag exceeds either the
      per-partition cap or the total cap, the gate raises
      `ConsumerLagExceeded`; `run_epoch`'s per-agent try/except records
      that as an error AND CRUCIALLY DOES NOT WRITE THE CERTIFICATE.
      Better a missing cert (which downstream policy treats as fail-closed
      — see VULN-12) than a stale cert (which downstream policy honours).

WHY THE THRESHOLDS ARE TWO-DIMENSIONAL
--------------------------------------
- `max_partition_lag` catches a SINGLE hot partition that has fallen
  behind even if the group's total looks fine. Per-key ordering means a
  single backed-up partition is a single backed-up AGENT — and that one
  agent's certificate would be the stale one.
- `max_total_lag` catches a CLUSTER-WIDE backlog (e.g. consumer crash).
  A single agent's partition may be at zero lag, but if 90% of others
  are not, the oracle is mid-recovery and should not be issuing certs.

Both default to values supplied by the operator (env vars below). The
audit suggests "500ms or 1 epoch worth of transactions" — translated to
records, that is a deployment-specific number, so we expose it as
configuration rather than hard-coding a guess.

WHY NOT PRODUCE THE BACKLOG-DRAIN IN-LINE
-----------------------------------------
The lag-gate's job is to BLOCK CERT ISSUANCE, not to catch the consumer
up. Draining the backlog is the consumer's job (run more partitions /
scale out the group); the gate is the safety interlock that makes sure
the oracle does not produce signed garbage while the drain is in
progress. Mixing the two would couple the cert path to broker progress
in a way that hides liveness problems instead of surfacing them.

NB on driver independence
-------------------------
The `BrokerIntrospector` Protocol — committed_offset, high_watermark,
partition_count — is satisfied by `InMemoryBroker` as-is. The production
`ConfluentKafkaBroker` adapter will expose the same three methods over
`Consumer.committed()` + `Consumer.get_watermark_offsets()` + cluster
metadata, so this module needs no per-driver branching.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

logger = logging.getLogger("helixor.eventbus.lag_monitor")


# =============================================================================
# Defaults + env-var overrides
# =============================================================================

# Per-partition cap: how many records may sit unprocessed on any single
# partition before the cert gate trips. Per-key ordering means a single
# backed-up partition is a single backed-up AGENT, so this is the
# audit-critical knob for the stale-cert window.
_ENV_MAX_PARTITION_LAG = "HELIXOR_CONSUMER_LAG_MAX_PARTITION"
DEFAULT_MAX_PARTITION_LAG = 500

# Total cap across all partitions in the group. Catches a cluster-wide
# backlog (consumer crash, throughput collapse) even when no single
# partition crosses the per-partition cap.
_ENV_MAX_TOTAL_LAG = "HELIXOR_CONSUMER_LAG_MAX_TOTAL"
DEFAULT_MAX_TOTAL_LAG = 4_000


def _env_int(name: str, default: int) -> int:
    """
    Read a positive int from the env, falling back to `default`. A
    non-int / negative value is logged and ignored — operators get a
    visible warning rather than a silently-bypassed gate.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "env var %s=%r is not an int; using default %d", name, raw, default,
        )
        return default
    if value < 0:
        logger.warning(
            "env var %s=%d is negative; using default %d", name, value, default,
        )
        return default
    return value


# =============================================================================
# BrokerIntrospector — the read-only slice ConsumerLagMonitor depends on
# =============================================================================

@runtime_checkable
class BrokerIntrospector(Protocol):
    """
    The subset of `MessageBroker` the lag monitor needs. `InMemoryBroker`
    satisfies this Protocol as-is; the production `ConfluentKafkaBroker`
    exposes the same three methods over librdkafka primitives.

    Kept narrower than `MessageBroker` so a fake / mock for unit tests
    does not have to model produce / poll / commit just to be observed.
    """

    def committed_offset(self, topic: str, group: str, partition: int) -> int: ...

    def high_watermark(self, topic: str, partition: int) -> int: ...

    def partition_count(self, topic: str) -> int: ...


# =============================================================================
# LagSnapshot — one observation of a (topic, group)'s backlog
# =============================================================================

@dataclass(frozen=True, slots=True)
class LagSnapshot:
    """
    A single point-in-time observation of a (topic, group)'s lag.

    Lag is records-behind, NOT milliseconds-behind — Kafka has no time
    index of consumer position. Operators translate records-behind to
    seconds using their measured throughput; the gate works in records
    because that is what the broker actually exposes.

    `within_threshold` is the answer to "should the cert gate let this
    epoch through?" — the answer the gate cares about, precomputed
    against the thresholds the monitor was built with.
    """
    topic:               str
    group:               str
    per_partition_lag:   dict[int, int] = field(default_factory=dict)
    total_lag:           int = 0
    max_partition_lag:   int = 0
    captured_at:         float = 0.0
    # The thresholds the snapshot was evaluated against — pinned here so
    # downstream logs / events show the cap the snapshot tripped on, not
    # the cap that happens to be configured at log-emission time.
    threshold_partition: int = 0
    threshold_total:     int = 0
    within_threshold:    bool = True

    @property
    def offending_partitions(self) -> tuple[int, ...]:
        """Partitions whose lag exceeds `threshold_partition`. Sorted."""
        return tuple(sorted(
            p for p, lag in self.per_partition_lag.items()
            if lag > self.threshold_partition
        ))

    def reason(self) -> str:
        """
        Human-readable explanation of WHY the snapshot blocks (or empty
        string if it does not). Used as the `reason` field on the cert
        gate's exception and on the CertBlocked event.
        """
        if self.within_threshold:
            return ""
        parts: list[str] = []
        if self.total_lag > self.threshold_total:
            parts.append(
                f"total lag {self.total_lag} > cap {self.threshold_total}"
            )
        offending = self.offending_partitions
        if offending:
            parts.append(
                f"partitions {list(offending)} exceed per-partition cap "
                f"{self.threshold_partition}"
            )
        return "; ".join(parts) if parts else "lag threshold exceeded"


# =============================================================================
# ConsumerLagMonitor
# =============================================================================

class ConsumerLagMonitor:
    """
    Computes per-partition + total lag for a consumer group on a topic,
    against operator-configured thresholds.

    Pure read-only — the monitor never produces, never consumes, never
    commits. The numbers come from broker introspection so the monitor
    can run inside the oracle's epoch loop without touching the
    consumer.
    """

    def __init__(
        self,
        broker: BrokerIntrospector,
        *,
        max_partition_lag: int | None = None,
        max_total_lag:     int | None = None,
    ) -> None:
        # Resolve thresholds: explicit ctor arg > env var > module default.
        self._max_partition_lag = (
            max_partition_lag
            if max_partition_lag is not None
            else _env_int(_ENV_MAX_PARTITION_LAG, DEFAULT_MAX_PARTITION_LAG)
        )
        self._max_total_lag = (
            max_total_lag
            if max_total_lag is not None
            else _env_int(_ENV_MAX_TOTAL_LAG, DEFAULT_MAX_TOTAL_LAG)
        )
        if self._max_partition_lag < 0 or self._max_total_lag < 0:
            raise ValueError(
                "lag thresholds must be non-negative "
                f"(partition={self._max_partition_lag}, "
                f"total={self._max_total_lag})"
            )
        self._broker = broker

    # ── Accessors for introspection / tests ────────────────────────────────

    @property
    def max_partition_lag(self) -> int:
        return self._max_partition_lag

    @property
    def max_total_lag(self) -> int:
        return self._max_total_lag

    # ── Core: compute lag ──────────────────────────────────────────────────

    def lag_by_partition(self, topic: str, group: str) -> dict[int, int]:
        """
        Per-partition records-behind for `group` on `topic`.

        Lag for partition p = high_watermark(p) - committed_offset(p).
        Clamped to >= 0 (a fresh group with no committed offset reads as
        0, not as a large negative).
        """
        partitions = self._broker.partition_count(topic)
        out: dict[int, int] = {}
        for p in range(partitions):
            hw = self._broker.high_watermark(topic, p)
            committed = self._broker.committed_offset(topic, group, p)
            lag = hw - committed
            out[p] = lag if lag > 0 else 0
        return out

    def total_lag(self, topic: str, group: str) -> int:
        """Sum of per-partition lag for `group` on `topic`."""
        return sum(self.lag_by_partition(topic, group).values())

    def max_observed_partition_lag(self, topic: str, group: str) -> int:
        """
        The single hottest partition's lag. 0 if the topic has no
        partitions (defensive — `_ensure_topic` always materialises >= 1).
        """
        by_partition = self.lag_by_partition(topic, group)
        return max(by_partition.values(), default=0)

    # ── Snapshot + threshold check ─────────────────────────────────────────

    def snapshot(self, topic: str, group: str) -> LagSnapshot:
        """
        Capture a `LagSnapshot` for `(topic, group)`, evaluated against
        this monitor's thresholds. The snapshot is the unit the cert
        gate consumes — `within_threshold` is the gate's decision.
        """
        per_partition = self.lag_by_partition(topic, group)
        total = sum(per_partition.values())
        max_p = max(per_partition.values(), default=0)
        within = (
            total <= self._max_total_lag
            and max_p <= self._max_partition_lag
        )
        return LagSnapshot(
            topic=topic,
            group=group,
            per_partition_lag=per_partition,
            total_lag=total,
            max_partition_lag=max_p,
            captured_at=time.time(),
            threshold_partition=self._max_partition_lag,
            threshold_total=self._max_total_lag,
            within_threshold=within,
        )

    def is_within_threshold(self, topic: str, group: str) -> bool:
        """Convenience: just the boolean — for branching in the gate."""
        return self.snapshot(topic, group).within_threshold
