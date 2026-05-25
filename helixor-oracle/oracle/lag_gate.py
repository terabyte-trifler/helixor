"""
oracle/lag_gate.py — VULN-14 MITIGATION (oracle side).

WHAT THIS WRAPS
---------------
`oracle/epoch_runner.py` defines `SubmitFn = Callable[[str, ScoreResult], object]`
as the seam through which scored agents become on-chain certificates. The
runner already contains a per-agent try/except: a raise from `submit_fn`
records an error on that agent's result and prevents the cert write,
without aborting the whole epoch.

This file is a wrapper around a real `SubmitFn` that runs a PRE-FLIGHT
consumer-lag check before delegating. If lag exceeds the operator-
configured thresholds (per-partition OR total), the wrapper raises
`ConsumerLagExceeded` — the runner records the cert as not-submitted
and continues. Better a MISSING cert (downstream policy treats absence
as fail-closed, see VULN-12's last-known-good cache) than a STALE cert
(downstream policy honours the signature and lets the agent through).

WHY THE GATE IS AT THE CERT WRITE, NOT AT THE SCORE COMPUTATION
---------------------------------------------------------------
The score is still computed against whatever data has been processed —
it is honest about the input it had. The cert is a SIGNED, ON-CHAIN
ARTEFACT that downstream protocols enforce against. Blocking the cert
when we know the input was stale is the audit-mandated behaviour:
"refuses to issue new certs until caught up". The score still lands in
the off-chain agent_scores table for operator visibility; only the
signed, downstream-honoured artefact is withheld.

WHY THE CHECK RUNS PER AGENT (NOT ONCE PER EPOCH)
-------------------------------------------------
Two reasons:

  1. Backlog can grow DURING an epoch. A single up-front check would
     let through agents whose certs were emitted before the spike but
     not see the spike that started halfway through the agent list.
     Per-agent re-check costs O(partitions) integer subtractions —
     cheap.

  2. If lag is concentrated on ONE partition (the audit's exact attack
     — drown one agent's partition with VULN-07-style spam to delay
     that agent's revocation), per-agent re-check is what catches that
     agent specifically. The other agents on healthy partitions still
     get certs.

NB on partition-targeted blocking
---------------------------------
This module's default is "block ANY cert while lag exceeds threshold."
A finer variant ("block only the cert for the agent whose partition is
backed up") is feasible — `LagSnapshot.offending_partitions` carries
exactly that — but requires the cert path to know each agent's
partition key. That mapping is operator-deployment-specific (cluster
size, partition count) so the safer default ships first. The plumbing
to drop to partition-targeted blocking is the `partition_for` argument
of `LagGatedSubmit`; pass it and only that agent's certs are blocked.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

# The eventbus package lives in helixor-indexer; it is on sys.path in any
# deployment / test environment that needs the gate (the gate is useless
# without a broker to observe). The import is deferred to TYPE_CHECKING so
# `oracle/__init__.py` lazy-loading does not force the eventbus import on
# every oracle consumer — only on consumers that actually use the gate.
if TYPE_CHECKING:                                   # pragma: no cover
    from eventbus.lag_monitor import ConsumerLagMonitor, LagSnapshot
    from scoring import ScoreResult

logger = logging.getLogger("helixor.oracle.lag_gate")


# =============================================================================
# The exception the gate raises when lag is too high
# =============================================================================

class ConsumerLagExceeded(Exception):
    """
    Raised by `LagGatedSubmit` when the consumer-group backlog exceeds
    the operator-configured caps. Carries the offending `LagSnapshot` so
    monitors / dashboards / postmortems can see exactly what tripped the
    gate.

    The runner's existing `except Exception` around `submit_fn` catches
    this naturally — the cert is not written, the agent's result carries
    `error = "submission failed: consumer lag exceeded ..."`. No runner
    change required.
    """

    def __init__(self, snapshot: "LagSnapshot", agent_wallet: str) -> None:
        self.snapshot = snapshot
        self.agent_wallet = agent_wallet
        super().__init__(
            f"VULN-14: cert blocked for {agent_wallet} on "
            f"{snapshot.topic}/{snapshot.group} — {snapshot.reason()}"
        )


# =============================================================================
# A side-channel for monitoring — "we BLOCKED a cert"
# =============================================================================

@dataclass(frozen=True, slots=True)
class CertBlocked:
    """
    Emitted by `LagGatedSubmit` whenever a cert is blocked by the lag
    gate. Operators wire this into Prometheus / pagers as the
    audit-recommended "automated lag monitoring with cert-blocking
    triggers". The blocking already happened (the exception was raised);
    this is the observable record.
    """
    agent_wallet: str
    snapshot:     "LagSnapshot"


# A monitor callback that receives `CertBlocked` events. Defaults to a
# logger emit; production wires Prometheus / pager.
CertBlockedObserver = Callable[[CertBlocked], None]


def _default_observer(event: CertBlocked) -> None:
    logger.error(
        "VULN-14 cert BLOCKED for %s on %s/%s — %s; per-partition lag: %s",
        event.agent_wallet,
        event.snapshot.topic,
        event.snapshot.group,
        event.snapshot.reason(),
        event.snapshot.per_partition_lag,
    )


# =============================================================================
# LagGatedSubmit — the SubmitFn wrapper
# =============================================================================

class LagGatedSubmit:
    """
    Wraps a `SubmitFn` (the per-agent cert-write seam from
    `oracle/epoch_runner.py`) with a consumer-lag pre-flight check.

    Construction:
        inner_submit  — the real cert-write function (today: a recording
                        stub in tests; production: the on-chain path).
        monitor       — a `ConsumerLagMonitor` aimed at the cert path's
                        broker / topic / group.
        topic, group  — the (topic, group) the monitor checks. Default
                        is `agent.cert_events` + `oracle-cert`, matching
                        the VULN-14 topic-isolation default.
        observer      — fires when a cert is blocked (Prometheus seam).

    Use:
        gate     = LagGatedSubmit(real_submit, monitor=monitor)
        run_epoch(..., submit_fn=gate, ...)

    The wrapper is a CALLABLE — `Callable[[str, ScoreResult], object]` —
    so it is a drop-in `SubmitFn`. The runner does not know it is gated.
    """

    DEFAULT_TOPIC = "agent.cert_events"
    DEFAULT_GROUP = "oracle-cert"

    def __init__(
        self,
        inner_submit: "Callable[[str, ScoreResult], object]",
        *,
        monitor:  "ConsumerLagMonitor",
        topic:    str = DEFAULT_TOPIC,
        group:    str = DEFAULT_GROUP,
        observer: CertBlockedObserver | None = None,
    ) -> None:
        self._inner = inner_submit
        self._monitor = monitor
        self._topic = topic
        self._group = group
        self._observer = observer or _default_observer

    # ── Introspection (tests / logs) ───────────────────────────────────────

    @property
    def monitor(self) -> "ConsumerLagMonitor":
        return self._monitor

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def group(self) -> str:
        return self._group

    # ── The SubmitFn surface ───────────────────────────────────────────────

    def __call__(self, agent_wallet: str, score_result: "ScoreResult") -> object:
        snapshot = self._monitor.snapshot(self._topic, self._group)
        if not snapshot.within_threshold:
            self._observer(CertBlocked(
                agent_wallet=agent_wallet, snapshot=snapshot,
            ))
            raise ConsumerLagExceeded(snapshot, agent_wallet)
        return self._inner(agent_wallet, score_result)
