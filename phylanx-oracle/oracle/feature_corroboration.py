"""
oracle/feature_corroboration.py — ILS-2: producer-corroboration and
record-freshness floor for red-team Path 2 sub-leaf 2b ("Exploit
VULN-07: feature poisoning").

THE ATTACK PATH (Inflate-Legitimate-Score Path 2, sub-leaf 2b)
--------------------------------------------------------------
VULN-07 is the "synthetic-success transactions poison the baseline"
family. The indexer-side defence
(`phylanx-indexer/eventbus/signing.py`, `consumer.py`) already
ships:

  * Producer-side Ed25519 signing — every transaction record is
    signed at producer time before going on the `agent.transactions`
    Kafka topic.
  * Consumer-side `TrustedProducerSet` verification — the detection
    consumer (`DetectionConsumer`) refuses records that are
    unsigned, signed by a key not in the trusted set, or that fail
    verification, dead-lettering them before the processor decodes.

What none of those defences see is the SOURCE TOPOLOGY of the
records that flow into a single agent's aggregation. An attacker
who has exfiltrated a SINGLE trusted producer key (e.g. via a
compromised indexer node) can stamp thousands of poison-success
records for a target agent. Each record's signature verifies; the
trusted-producer check passes; the records reach the aggregation
layer. Over a 30-day window the synthetic activity inflates the
agent's `success_rate_30d`, `feature_means`, and txtype
distribution — and the next baseline rotation (subject to ILS-1's
cadence) bakes the poisoned features into the on-chain baseline.

The OTHER substrate VULN-07's existing defence doesn't see is
RECORD AGE. A producer key that ages out of the trusted set (say
because the indexer node was decommissioned) leaves a window for
the attacker who exfiltrated it. The attacker can BACKFILL records
with stale timestamps, signed by the still-vouched key, that
arrive months later. Each record verifies but is meant to look
"historical".

ILS-2 closes both substrates:

  * `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2` — an agent's
    aggregation window MUST contain records from at least 2
    distinct trusted producer keys. A single compromised producer
    cannot solo-poison; the attacker must compromise 2 producers
    on 2 distinct nodes (NSS-1 / NSS-2 close that substrate at
    cluster level, but the consumer-side floor is independent).
  * `MAX_PRODUCER_DOMINANCE_RATIO = 0.7` — no single producer may
    contribute more than 70% of an agent's records in one
    aggregation window. Even with multiple producers, the
    attacker cannot dominate the aggregation.
  * `MAX_RECORD_AGE_SECONDS = 24 * 3600` — records older than 24h
    are refused from aggregation. A backfilled record signed by
    a since-decommissioned producer key is rejected on age before
    its signature is even verified.

CALIBRATION
-----------
- `MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2` — the K-1 floor
  for K=3 cluster. A single producer compromise should never be
  the whole substrate of a forged aggregation. Pinned at 2 (not
  3) so a routine indexer-node restart (one producer briefly
  silent) does not refuse legitimate aggregations.
- `MAX_PRODUCER_DOMINANCE_RATIO = 0.7` — 70% is calibrated against
  observed indexer-fleet load distribution: in a healthy 3-node
  indexer fleet, the busiest node typically carries 35-50% of
  records for any one agent. 70% is the cliff edge — past it,
  the topology is structurally unhealthy. The cap is a ratio, not
  an absolute count, so it scales with agent activity.
- `MAX_RECORD_AGE_SECONDS = 24 * 3600` — 24h matches the TA-6
  certificate freshness ceiling (`MAX_AGE_SECONDS = 48*60*60`)'s
  inner half. A backfilled record claiming to be 25h old is past
  the freshness window for any active scoring; ingesting it would
  retroactively rewrite a scoring window that is supposed to be
  closed.
- `RECORD_FUTURE_TOLERANCE_SECONDS = 60` — one epoch's worth of
  clock skew. A record whose `produced_unix` is more than 60s in
  the future is REFUSED with `RECORD_TIMESTAMP_IN_FUTURE`.

INTERACTION WITH VULN-07 / ILS-1 / ILS-3 / FHS-2
------------------------------------------------
- VULN-07's `eventbus/consumer.py` does the per-record signature
  verification. ILS-2 stands on top of that: AFTER the signatures
  verify, ILS-2 looks at the SHAPE of the aggregated record set.
- ILS-1 (`baseline_rotation_guard.py`) bounds the frequency of
  baseline rotations. Without ILS-2, an attacker who compromised
  a producer key could still poison the features that ILS-1
  bakes into the baseline every 30 epochs.
- ILS-3 (`score_drift_ceiling.py`) bounds the cumulative score
  drift. Even if ILS-2 fails (an attacker compromises >= 2
  producer keys), ILS-3 catches the resulting score inflation at
  the cert layer.
- FHS-2 (`signer_provenance.py`) constrains the CLUSTER signers'
  physical topology (per-host=1, per-region=2). ILS-2 mirrors
  the same principle at the PRODUCER layer.

DETERMINISM
-----------
Pure stdlib. Counter-style aggregation across an iterable of
records and ratio arithmetic. No clock (the verifier takes
`current_unix` as input), no network, no randomness.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

#: Minimum number of distinct trusted producer keys that must
#: contribute records to an agent's aggregation window.
MIN_DISTINCT_PRODUCERS_PER_AGGREGATION = 2

#: Maximum fraction of records in one aggregation window that may
#: originate from a single producer. Ratios > this are REFUSED.
MAX_PRODUCER_DOMINANCE_RATIO = 0.7

#: Maximum age (seconds) of a record at aggregation time. Records
#: older than this are REFUSED — closes the backfill-poisoning
#: substrate.
MAX_RECORD_AGE_SECONDS = 24 * 3600

#: Seconds of future-skew tolerance for `produced_unix > current_unix`.
RECORD_FUTURE_TOLERANCE_SECONDS = 60

#: Status labels.
CORROBORATION_OK = "OK"
CORROBORATION_REFUSED = "REFUSED"

#: Reason codes.
REASON_TOO_FEW_PRODUCERS = "TOO_FEW_PRODUCERS"
REASON_PRODUCER_OVER_DOMINANCE = "PRODUCER_OVER_DOMINANCE"
REASON_RECORDS_TOO_STALE = "RECORDS_TOO_STALE"
REASON_RECORD_TIMESTAMP_IN_FUTURE = "RECORD_TIMESTAMP_IN_FUTURE"
REASON_NO_RECORDS = "NO_RECORDS"


# =============================================================================
# Errors
# =============================================================================

class FeatureCorroborationError(RuntimeError):
    """
    Raised by `enforce_feature_corroboration` when an agent's
    aggregation window fails the producer-corroboration or record-
    freshness contract.

    `.report` carries the structured verdict so the on-call operator
    can decide whether the indexer fleet has lost diversity or
    whether a single producer has been compromised.
    """

    def __init__(self, message: str, report: "FeatureCorroborationReport"):
        super().__init__(message)
        self.report = report


# =============================================================================
# Records
# =============================================================================

@dataclass(frozen=True, slots=True)
class FeatureRecord:
    """
    One ingestion record as it arrives at the scoring aggregator,
    AFTER the consumer-side VULN-07 signature check has passed.

    `producer_pubkey`  the Ed25519 pubkey of the producer that
                       signed the record (the trusted-set entry
                       under which the signature verified).
    `produced_unix`    the producer's local timestamp at sign-time.
                       Drives the staleness check.
    """
    producer_pubkey:  str
    produced_unix:    int


@dataclass(frozen=True, slots=True)
class FeatureAggregation:
    """
    An agent's records across one aggregation window.

    `agent_wallet`  the agent these records are about.
    `records`       tuple of FeatureRecord. Order does not matter.
    """
    agent_wallet:  str
    records:       tuple[FeatureRecord, ...]


@dataclass(frozen=True, slots=True)
class FeatureCorroborationReport:
    """
    Verdict of one ILS-2 check.

    `status`                 CORROBORATION_OK / CORROBORATION_REFUSED.
    `agent_wallet`           echoed.
    `record_count`           total records (including any that are
                             stale or future-dated).
    `producer_count`         |distinct producer pubkeys|.
    `dominance_ratio`        max(producer_record_count) / record_count,
                             or 0.0 if record_count == 0.
    `dominant_producer`      pubkey of the over-dominant producer, or
                             "" if no producer is over the cap.
    `stale_record_count`     records past MAX_RECORD_AGE_SECONDS.
    `future_record_count`    records past RECORD_FUTURE_TOLERANCE_SECONDS.
    `required_producers`     MIN_DISTINCT_PRODUCERS_PER_AGGREGATION.
    `max_dominance_ratio`    MAX_PRODUCER_DOMINANCE_RATIO.
    `max_record_age_seconds` MAX_RECORD_AGE_SECONDS.
    `reasons`                reason codes; empty when OK.
    """
    status:                  str
    agent_wallet:            str
    record_count:            int
    producer_count:          int
    dominance_ratio:         float
    dominant_producer:       str
    stale_record_count:      int
    future_record_count:     int
    required_producers:      int
    max_dominance_ratio:     float
    max_record_age_seconds:  int
    reasons:                 tuple[str, ...]

    @property
    def is_allowed(self) -> bool:
        return self.status == CORROBORATION_OK


# =============================================================================
# Verifier (pure)
# =============================================================================

def verify_feature_corroboration(
    aggregation: FeatureAggregation,
    *,
    current_unix: int,
) -> FeatureCorroborationReport:
    """
    Decide whether an agent's aggregation window respects the
    corroboration and freshness contract.

    The rules:
      * Empty `records` -> REFUSED, NO_RECORDS. ILS-2 refuses to
        verify against an empty set rather than silently passing.
      * Any record with `produced_unix > current_unix +
        RECORD_FUTURE_TOLERANCE_SECONDS` -> REFUSED,
        RECORD_TIMESTAMP_IN_FUTURE.
      * Any record with `current_unix - produced_unix >
        MAX_RECORD_AGE_SECONDS` -> REFUSED, RECORDS_TOO_STALE.
        (The aggregation as a whole is refused; the on-call must
        purge the stale records from the window.)
      * |distinct producer_pubkey| <
        MIN_DISTINCT_PRODUCERS_PER_AGGREGATION -> REFUSED,
        TOO_FEW_PRODUCERS.
      * max(per-producer record count) / total record count >
        MAX_PRODUCER_DOMINANCE_RATIO -> REFUSED,
        PRODUCER_OVER_DOMINANCE.

    Pure: no logging, no I/O. `current_unix` is the only time
    input.
    """
    reasons: list[str] = []
    records = aggregation.records
    record_count = len(records)

    if record_count == 0:
        return FeatureCorroborationReport(
            status=CORROBORATION_REFUSED,
            agent_wallet=aggregation.agent_wallet,
            record_count=0,
            producer_count=0,
            dominance_ratio=0.0,
            dominant_producer="",
            stale_record_count=0,
            future_record_count=0,
            required_producers=MIN_DISTINCT_PRODUCERS_PER_AGGREGATION,
            max_dominance_ratio=MAX_PRODUCER_DOMINANCE_RATIO,
            max_record_age_seconds=MAX_RECORD_AGE_SECONDS,
            reasons=(REASON_NO_RECORDS,),
        )

    stale_count = 0
    future_count = 0
    for r in records:
        if r.produced_unix > current_unix + RECORD_FUTURE_TOLERANCE_SECONDS:
            future_count += 1
        elif current_unix - r.produced_unix > MAX_RECORD_AGE_SECONDS:
            stale_count += 1

    if future_count > 0:
        reasons.append(REASON_RECORD_TIMESTAMP_IN_FUTURE)
    if stale_count > 0:
        reasons.append(REASON_RECORDS_TOO_STALE)

    producer_counts = Counter(r.producer_pubkey for r in records)
    producer_count = len(producer_counts)

    if producer_count < MIN_DISTINCT_PRODUCERS_PER_AGGREGATION:
        reasons.append(REASON_TOO_FEW_PRODUCERS)

    dominant_producer, dominant_count = producer_counts.most_common(1)[0]
    dominance_ratio = dominant_count / record_count
    if dominance_ratio > MAX_PRODUCER_DOMINANCE_RATIO:
        reasons.append(REASON_PRODUCER_OVER_DOMINANCE)
        reported_dominant = dominant_producer
    else:
        reported_dominant = ""

    status = (
        CORROBORATION_OK if not reasons else CORROBORATION_REFUSED
    )

    return FeatureCorroborationReport(
        status=status,
        agent_wallet=aggregation.agent_wallet,
        record_count=record_count,
        producer_count=producer_count,
        dominance_ratio=dominance_ratio,
        dominant_producer=reported_dominant,
        stale_record_count=stale_count,
        future_record_count=future_count,
        required_producers=MIN_DISTINCT_PRODUCERS_PER_AGGREGATION,
        max_dominance_ratio=MAX_PRODUCER_DOMINANCE_RATIO,
        max_record_age_seconds=MAX_RECORD_AGE_SECONDS,
        reasons=tuple(reasons),
    )


# =============================================================================
# Enforcement (fail-closed wrapper)
# =============================================================================

def enforce_feature_corroboration(
    aggregation: FeatureAggregation,
    *,
    current_unix: int,
) -> FeatureCorroborationReport:
    """
    Run `verify_feature_corroboration` and raise on any violation.

    Returns the report when status == CORROBORATION_OK. Raises
    `FeatureCorroborationError` otherwise — the aggregation should
    NOT be baked into the baseline or used for cert issuance.
    """
    report = verify_feature_corroboration(
        aggregation, current_unix=current_unix,
    )
    if report.is_allowed:
        return report
    raise FeatureCorroborationError(
        f"ILS-2: feature corroboration refused — "
        f"agent={report.agent_wallet!r}, "
        f"records={report.record_count}, "
        f"producers={report.producer_count} (need >= "
        f"{report.required_producers}), "
        f"dominance={report.dominance_ratio:.2f} (cap "
        f"{report.max_dominance_ratio:.2f}), "
        f"stale={report.stale_record_count}, "
        f"future={report.future_record_count}, "
        f"reasons={list(report.reasons)!r}. "
        f"Aggregation MUST be sourced from >= "
        f"{MIN_DISTINCT_PRODUCERS_PER_AGGREGATION} distinct "
        f"producers, no producer > "
        f"{MAX_PRODUCER_DOMINANCE_RATIO*100:.0f}%, no record older "
        f"than {MAX_RECORD_AGE_SECONDS}s.",
        report,
    )


__all__ = [
    "CORROBORATION_OK",
    "CORROBORATION_REFUSED",
    "FeatureAggregation",
    "FeatureCorroborationError",
    "FeatureCorroborationReport",
    "FeatureRecord",
    "MAX_PRODUCER_DOMINANCE_RATIO",
    "MAX_RECORD_AGE_SECONDS",
    "MIN_DISTINCT_PRODUCERS_PER_AGGREGATION",
    "REASON_NO_RECORDS",
    "REASON_PRODUCER_OVER_DOMINANCE",
    "REASON_RECORDS_TOO_STALE",
    "REASON_RECORD_TIMESTAMP_IN_FUTURE",
    "REASON_TOO_FEW_PRODUCERS",
    "RECORD_FUTURE_TOLERANCE_SECONDS",
    "enforce_feature_corroboration",
    "verify_feature_corroboration",
]
