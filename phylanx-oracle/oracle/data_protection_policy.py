"""
oracle/data_protection_policy.py — DP-1: data-protection policy substrate.

THE COMPLIANCE GAP (audit)
--------------------------
    "The scoring system builds behavioral profiles of agents. In
    jurisdictions with data protection law, storing behavioral data
    without consent could be a regulatory liability."

Phylanx stores agent-wallet-keyed behavioral data in three substrates:

  * TimescaleDB — `agent_transactions` (180-day retention),
    `agent_scores` (cumulative), `agent_tx_daily` (rolling 90d
    back-fill continuous aggregate).
  * Kafka topics — `agent.transactions`, `agent.alerts`,
    `agent.cert_events`, `agent.cert_events.refused`.
  * Solana on-chain accounts — `HealthCertificate`,
    `AgentRegistration`, `ChallengeRecord`. These are IMMUTABLE by
    construction (the audit's tamper-resistance story for FRP-3,
    OFAC-1, and the forge-detection mitigations rests on this).

GDPR Art. 4(1), DPDP s.2(t), and CCPA §1798.140(o) all treat a
linkable identifier + behavioral profile as personal data. Solana
pubkeys ARE linkable identifiers under all three regimes. Each
regime then converges on the same five mechanical requirements:

  1. **Lawful basis** for processing (GDPR Art. 6, DPDP Ch. III,
     CCPA "business purpose").
  2. **Storage limitation** — retention ceiling per category (GDPR
     Art. 5(1)(e), DPDP s.8(7), CCPA §1798.105(d)).
  3. **Data-subject access** — given a wallet, what is stored
     (GDPR Art. 15, DPDP s.11, CCPA §1798.110).
  4. **Erasure** — purge off-chain stores on request (GDPR Art. 17,
     DPDP s.12, CCPA §1798.105). The on-chain audit trail is an
     EXPLICITLY DISCLOSED carve-out (see "On-chain vs off-chain"
     below); the privacy notice surfaces this upfront.
  5. **Transparency** — a public privacy notice naming categories,
     bases, and the on-chain carve-out (GDPR Arts. 13-14, DPDP
     s.5, CCPA §1798.130).

THIS MODULE — what it does
--------------------------
Pins (1) and (2) machine-readably. It declares:

  * The closed set of `DataCategory` values — every per-agent store
    in the system buckets into exactly one category. New stores
    must register a category before they can ship (the audit gate
    `audit/data_protection_check.py` enforces this).
  * The closed set of `LawfulBasis` values — GDPR Art. 6 / DPDP
    Ch. III bases the protocol relies on. Every category maps to
    exactly one declared basis.
  * The closed set of `StorageLocation` values — on-chain or one of
    the named off-chain substrates. Pinned because the erasability
    boundary follows the storage location, not the data category.
  * `RetentionPolicy` records — one per (category, storage_location)
    pair — with a pinned `max_retention_seconds` ceiling and the
    `erasure_supported` flag. The values are NOT hints; the audit
    gate verifies the actual TimescaleDB migration and Prometheus
    config still match.

WHAT THIS MODULE DOES NOT DO
----------------------------
It does NOT execute deletes. Erasure is implemented in the indexer
CLI (`phylanx-indexer/cli/data_subject_request.py`); this module
declares the policy that the CLI honours.

It does NOT decide whether the protocol has consent. The lawful
basis the audit relies on for behavioral data is
LEGITIMATE_INTEREST_FRAUD_PREVENTION (GDPR Art. 6(1)(f) / DPDP
s.7(b) "fair and reasonable purposes"), NOT consent. The privacy
notice surfaces the basis and the right-to-object channel. A future
caller that needs consent-based processing must add a new
`LawfulBasis.CONSENT` member and a consent receipt substrate; today
no such caller exists.

It does NOT change any existing storage behavior. The retention
ceilings declared here MIRROR the values already pinned in the
migration / docker-compose / topic configs. The substrate is the
single source of truth the audit reads from; the values
themselves still live in their canonical config files. If the two
diverge, `audit/data_protection_check.py` fails HARD.

ON-CHAIN vs OFF-CHAIN
---------------------
Erasure (GDPR Art. 17, DPDP s.12) is technically infeasible against
the Solana ledger. The on-chain audit trail is what proves the
cluster did not silently delist an agent (OFAC-1), did not forge a
score (FRP-3 / VULN-13), and did not rewrite history (the immutable
`HealthCertificate` PDAs). Removing those accounts on demand would
dissolve the audit story the rest of the protocol depends on.

The accepted solution under GDPR Recital 26 / DPDP s.3(c) is:

  * Off-chain stores ARE subject to erasure (TimescaleDB rows,
    Kafka offsets where supported, Prometheus series).
  * On-chain stores are disclosed as a documented technical
    constraint of using a public ledger; the public privacy notice
    explains this upfront so a data subject can make an informed
    choice BEFORE registering.
  * The on-chain payload is the MINIMAL set required for audit
    (cert tier, epoch, score, signer set — no PII, no name, no
    contact, no IP). Pseudonymisation by wallet pubkey is the
    GDPR-compliant baseline.

The `erasure_supported` flag on `RetentionPolicy` captures this
boundary mechanically: any policy claiming the data is on-chain
MUST have `erasure_supported=False`; any off-chain policy MUST
have `erasure_supported=True`. The audit gate enforces the
biconditional.

DETERMINISM
-----------
Pure stdlib. No clock, no randomness, no network. Two operators
loading this module see byte-identical policies.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass


# =============================================================================
# DataCategory — closed set of per-agent storage buckets.
# =============================================================================
#
# Every per-agent store the protocol writes to MUST bucket into exactly
# one of these. Adding a new store without declaring a category here
# trips the audit gate.

class DataCategory(str, enum.Enum):
    """Closed set of per-agent data categories the protocol stores."""

    # TimescaleDB `agent_transactions` hypertable + the
    # `agent.transactions` Kafka topic. Per-agent time-series of
    # Solana transactions used as feature inputs.
    TRANSACTION_HISTORY     = "TRANSACTION_HISTORY"

    # TimescaleDB `agent_scores` table (append-only history) + the
    # rolling `agent_tx_daily` continuous aggregate. The cumulative
    # scoring trail the protocol uses to detect velocity / drift
    # anomalies.
    SCORE_HISTORY           = "SCORE_HISTORY"

    # On-chain `HealthCertificate` PDAs. One per (agent, epoch).
    # Audit-trail substrate; NOT erasable.
    CERT_HISTORY            = "CERT_HISTORY"

    # On-chain `AgentRegistration` PDA. The pubkey, owner,
    # baseline hash, registration timestamp. Mutable (active flag),
    # but never closed.
    REGISTRATION_METADATA   = "REGISTRATION_METADATA"

    # The OFAC-1 `cert_refusal_log` stream on
    # `Topic.CERT_REFUSED = "agent.cert_events.refused"`. Per-agent
    # refusal events with attributable reason codes. Off-chain but
    # NOT erasable on demand — erasing a refusal record would
    # defeat the OFAC-1 silent-delist transparency invariant.
    REFUSAL_LOG             = "REFUSAL_LOG"

    # On-chain `ChallengeRecord` PDA. One per challenged cert.
    # Audit-trail; NOT erasable.
    CHALLENGE_HISTORY       = "CHALLENGE_HISTORY"

    # Prometheus per-agent metrics. Today the metrics config does
    # not emit `agent_wallet` label cardinality, but the category
    # is reserved so that future telemetry that DOES carry the
    # label has a declared bucket.
    OPERATIONAL_TELEMETRY   = "OPERATIONAL_TELEMETRY"


# =============================================================================
# LawfulBasis — GDPR Art. 6 / DPDP Ch. III bases the protocol relies on.
# =============================================================================
#
# Each category maps to exactly one basis. The basis is what the
# privacy notice surfaces, so the closed set here drives what the
# notice can legitimately claim.

class LawfulBasis(str, enum.Enum):
    """Closed set of lawful bases the protocol relies on."""

    # GDPR Art. 6(1)(f) — legitimate interest in fraud prevention
    # and trust scoring of autonomous agents. The recital-accepted
    # default for behavioral / anti-fraud telemetry.
    LEGITIMATE_INTEREST_FRAUD_PREVENTION = (
        "LEGITIMATE_INTEREST_FRAUD_PREVENTION"
    )

    # GDPR Art. 6(1)(b) — performance of a contract. The Verified
    # Consumer integration carries explicit contract terms and a
    # partner-signed registration; the cert badge lifecycle is the
    # contract performance.
    CONTRACT_CONSUMER_INTEGRATION        = "CONTRACT_CONSUMER_INTEGRATION"

    # GDPR Art. 6(1)(c) — legal obligation. The OFAC-1 refusal log
    # is published because operator-of-record jurisdictions impose
    # transparency / sanctions-compliance obligations on the
    # operators themselves; the cluster records the refusal so the
    # operator can demonstrate compliance.
    LEGAL_OBLIGATION_SANCTIONS           = "LEGAL_OBLIGATION_SANCTIONS"

    # GDPR Art. 6(1)(c) / Recital 65 — auditability obligation.
    # The on-chain PDAs are written to preserve a tamper-resistant
    # audit trail; this is a structural commitment of the protocol
    # disclosed before registration.
    LEGAL_OBLIGATION_AUDIT_TRAIL         = "LEGAL_OBLIGATION_AUDIT_TRAIL"


# =============================================================================
# StorageLocation — where the data physically lives.
# =============================================================================
#
# The erasability boundary follows location, not category. An
# off-chain category is erasable; an on-chain category is not.

class StorageLocation(str, enum.Enum):
    """Closed set of physical storage substrates."""
    OFF_CHAIN_TIMESCALE  = "OFF_CHAIN_TIMESCALE"
    OFF_CHAIN_KAFKA      = "OFF_CHAIN_KAFKA"
    OFF_CHAIN_PROMETHEUS = "OFF_CHAIN_PROMETHEUS"
    ON_CHAIN_SOLANA      = "ON_CHAIN_SOLANA"


def is_on_chain(location: StorageLocation) -> bool:
    """True iff the storage location is the public Solana ledger."""
    return location is StorageLocation.ON_CHAIN_SOLANA


# =============================================================================
# Retention ceilings — audit-pinned values mirrored from the canonical
# config files. The audit gate verifies the configs still match.
# =============================================================================
#
# These are NOT settings. The CANONICAL value for each ceiling lives
# in its config file (the TimescaleDB migration, the docker-compose,
# the topic config). The values declared here are the values the
# audit expects to find there.

# TimescaleDB `agent_transactions` retention. Pinned in
# `phylanx-oracle/db/migrations/0009_timescaledb.sql` as
# `INTERVAL '180 days'`.
TIMESCALE_TRANSACTION_RETENTION_SECONDS = 180 * 24 * 3600

# `agent_scores` table — append-only with no DB-level retention.
# Erasure is by per-wallet DELETE, NOT by time-based prune; the
# protocol needs the full history to detect velocity / drift
# anomalies. The ceiling here is the policy-stated maximum for the
# privacy notice's retention table: 180 days from last activity.
TIMESCALE_SCORE_RETENTION_SECONDS       = 180 * 24 * 3600

# Prometheus retention. Pinned in
# `launch/deploy/docker-compose.indexer.yml` as
# `--storage.tsdb.retention.time=30d`.
PROMETHEUS_RETENTION_SECONDS            = 30 * 24 * 3600

# Kafka topic retention. The CONFLUENT_KAFKA defaults to 7d; the
# protocol does not override on `agent.transactions` (raw
# telemetry rotates fast) or on `agent.cert_events.refused` (which
# is the OFAC-1 transparency record and must remain visible long
# enough for downstream audit pipes to ingest).
KAFKA_TRANSACTIONS_RETENTION_SECONDS    = 7 * 24 * 3600
KAFKA_REFUSAL_RETENTION_SECONDS         = 30 * 24 * 3600

# Sentinel — on-chain data has no retention ceiling (Solana ledger
# is append-only and pruning happens at the validator/snapshot
# layer, NOT at the program layer).
INDEFINITE = None


# =============================================================================
# RetentionPolicy — one record per (category, storage_location).
# =============================================================================

@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """
    Pin for one (category, storage_location) pair.

    `max_retention_seconds`  — ceiling in seconds, or None for
                               indefinite (on-chain only).
    `lawful_basis`           — the GDPR Art. 6 / DPDP basis.
    `erasure_supported`      — True iff the privacy notice may
                               offer erasure for this slice. MUST
                               be False iff `storage_location` is
                               on-chain (the audit gate enforces
                               the biconditional).
    `description`            — one-line human-readable used in the
                               privacy notice retention table.
    """
    category:              DataCategory
    storage_location:      StorageLocation
    max_retention_seconds: int | None
    lawful_basis:          LawfulBasis
    erasure_supported:     bool
    description:           str

    def __post_init__(self) -> None:
        # The erasability biconditional — the load-bearing invariant
        # the audit gate verifies.
        if is_on_chain(self.storage_location):
            if self.erasure_supported:
                raise ValueError(
                    f"RetentionPolicy for {self.category.value} on "
                    f"{self.storage_location.value} declares "
                    f"erasure_supported=True, but on-chain data is "
                    f"structurally non-erasable"
                )
            if self.max_retention_seconds is not None:
                raise ValueError(
                    f"RetentionPolicy for {self.category.value} on "
                    f"{self.storage_location.value} declares a finite "
                    f"retention ceiling, but on-chain data is "
                    f"structurally indefinite"
                )
        else:
            if not self.erasure_supported and self.category not in (
                DataCategory.REFUSAL_LOG,
            ):
                raise ValueError(
                    f"RetentionPolicy for {self.category.value} on "
                    f"{self.storage_location.value} declares "
                    f"erasure_supported=False, but off-chain data "
                    f"must be erasable (unless explicitly carved "
                    f"out — only REFUSAL_LOG is carved out today)"
                )
            if self.max_retention_seconds is None:
                raise ValueError(
                    f"RetentionPolicy for {self.category.value} on "
                    f"{self.storage_location.value} declares "
                    f"indefinite retention, but off-chain data must "
                    f"have a finite ceiling"
                )
            if self.max_retention_seconds <= 0:
                raise ValueError(
                    f"RetentionPolicy max_retention_seconds must be "
                    f"positive, got {self.max_retention_seconds}"
                )
        if not self.description or not self.description.strip():
            raise ValueError(
                "RetentionPolicy.description must be non-empty — the "
                "privacy notice surfaces this line verbatim"
            )


# =============================================================================
# The pinned policies. ONE record per (category, storage_location).
# =============================================================================

RETENTION_POLICIES: Mapping[
    tuple[DataCategory, StorageLocation], RetentionPolicy
] = {
    # TRANSACTION_HISTORY — TimescaleDB hypertable
    (DataCategory.TRANSACTION_HISTORY, StorageLocation.OFF_CHAIN_TIMESCALE):
        RetentionPolicy(
            category=DataCategory.TRANSACTION_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            max_retention_seconds=TIMESCALE_TRANSACTION_RETENTION_SECONDS,
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=True,
            description=(
                "Raw per-agent Solana transaction time-series used as "
                "feature inputs. Hypertable retention 180 days; "
                "automatically dropped beyond."
            ),
        ),
    # TRANSACTION_HISTORY — Kafka topic
    (DataCategory.TRANSACTION_HISTORY, StorageLocation.OFF_CHAIN_KAFKA):
        RetentionPolicy(
            category=DataCategory.TRANSACTION_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_KAFKA,
            max_retention_seconds=KAFKA_TRANSACTIONS_RETENTION_SECONDS,
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=True,
            description=(
                "Streaming transaction events on agent.transactions. "
                "Kafka topic retention 7 days; rotates beyond."
            ),
        ),
    # SCORE_HISTORY — TimescaleDB
    (DataCategory.SCORE_HISTORY, StorageLocation.OFF_CHAIN_TIMESCALE):
        RetentionPolicy(
            category=DataCategory.SCORE_HISTORY,
            storage_location=StorageLocation.OFF_CHAIN_TIMESCALE,
            max_retention_seconds=TIMESCALE_SCORE_RETENTION_SECONDS,
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=True,
            description=(
                "Append-only scoring history used to detect velocity "
                "and drift anomalies. Policy ceiling 180 days from "
                "last activity; erasure available on request."
            ),
        ),
    # CERT_HISTORY — on-chain
    (DataCategory.CERT_HISTORY, StorageLocation.ON_CHAIN_SOLANA):
        RetentionPolicy(
            category=DataCategory.CERT_HISTORY,
            storage_location=StorageLocation.ON_CHAIN_SOLANA,
            max_retention_seconds=INDEFINITE,
            lawful_basis=LawfulBasis.LEGAL_OBLIGATION_AUDIT_TRAIL,
            erasure_supported=False,
            description=(
                "HealthCertificate PDAs — one per (agent, epoch). "
                "Pseudonymous (wallet pubkey only) and minimal "
                "(tier / score / signer set). Immutable; disclosed "
                "as a documented technical constraint of using a "
                "public ledger."
            ),
        ),
    # REGISTRATION_METADATA — on-chain
    (DataCategory.REGISTRATION_METADATA, StorageLocation.ON_CHAIN_SOLANA):
        RetentionPolicy(
            category=DataCategory.REGISTRATION_METADATA,
            storage_location=StorageLocation.ON_CHAIN_SOLANA,
            max_retention_seconds=INDEFINITE,
            lawful_basis=LawfulBasis.CONTRACT_CONSUMER_INTEGRATION,
            erasure_supported=False,
            description=(
                "AgentRegistration PDA — pubkey, owner, baseline "
                "hash, registration timestamp. The on-chain "
                "registration is the contractual basis for issuing "
                "certs at all."
            ),
        ),
    # REFUSAL_LOG — Kafka topic (OFAC-1 transparency carve-out)
    (DataCategory.REFUSAL_LOG, StorageLocation.OFF_CHAIN_KAFKA):
        RetentionPolicy(
            category=DataCategory.REFUSAL_LOG,
            storage_location=StorageLocation.OFF_CHAIN_KAFKA,
            max_retention_seconds=KAFKA_REFUSAL_RETENTION_SECONDS,
            lawful_basis=LawfulBasis.LEGAL_OBLIGATION_SANCTIONS,
            erasure_supported=False,
            description=(
                "OFAC-1 silent-delist transparency stream on "
                "Topic.CERT_REFUSED. Each event records a refusal "
                "with attributable reason codes. Carved out of "
                "erasure because erasing a refusal record would "
                "defeat the silent-delist transparency invariant; "
                "the legal-obligation basis is the operator-side "
                "transparency duty."
            ),
        ),
    # CHALLENGE_HISTORY — on-chain
    (DataCategory.CHALLENGE_HISTORY, StorageLocation.ON_CHAIN_SOLANA):
        RetentionPolicy(
            category=DataCategory.CHALLENGE_HISTORY,
            storage_location=StorageLocation.ON_CHAIN_SOLANA,
            max_retention_seconds=INDEFINITE,
            lawful_basis=LawfulBasis.LEGAL_OBLIGATION_AUDIT_TRAIL,
            erasure_supported=False,
            description=(
                "ChallengeRecord PDA — one per challenged cert. "
                "Records the challenger, the disputed cert, and "
                "the attester quorum outcome. Immutable audit "
                "trail."
            ),
        ),
    # OPERATIONAL_TELEMETRY — Prometheus
    (DataCategory.OPERATIONAL_TELEMETRY, StorageLocation.OFF_CHAIN_PROMETHEUS):
        RetentionPolicy(
            category=DataCategory.OPERATIONAL_TELEMETRY,
            storage_location=StorageLocation.OFF_CHAIN_PROMETHEUS,
            max_retention_seconds=PROMETHEUS_RETENTION_SECONDS,
            lawful_basis=LawfulBasis.LEGITIMATE_INTEREST_FRAUD_PREVENTION,
            erasure_supported=True,
            description=(
                "Operational metrics. Today the production config "
                "does not emit per-agent labels; the category is "
                "reserved for future telemetry that does. TSDB "
                "retention 30 days."
            ),
        ),
}


# =============================================================================
# Errors
# =============================================================================

class DataProtectionError(Exception):
    """Raised when a policy lookup is invalid or a constraint fails."""


# =============================================================================
# Lookup helpers
# =============================================================================

def get_policy(
    category: DataCategory,
    storage_location: StorageLocation,
) -> RetentionPolicy:
    """
    Return the pinned policy for one (category, storage_location)
    pair. Raises `DataProtectionError` if no policy exists — the
    audit gate uses this to flag stores whose category was added to
    the enum but never wired into `RETENTION_POLICIES`.
    """
    key = (category, storage_location)
    if key not in RETENTION_POLICIES:
        raise DataProtectionError(
            f"no RetentionPolicy declared for {category.value} on "
            f"{storage_location.value}"
        )
    return RETENTION_POLICIES[key]


def erasable_policies() -> tuple[RetentionPolicy, ...]:
    """Return every policy where erasure is supported, in pinned order."""
    return tuple(
        p for p in RETENTION_POLICIES.values() if p.erasure_supported
    )


def non_erasable_policies() -> tuple[RetentionPolicy, ...]:
    """
    Return every policy where erasure is NOT supported. The privacy
    notice's on-chain carve-out lists these verbatim.
    """
    return tuple(
        p for p in RETENTION_POLICIES.values() if not p.erasure_supported
    )


# =============================================================================
# Public surface
# =============================================================================

__all__ = [
    # Enums
    "DataCategory",
    "LawfulBasis",
    "StorageLocation",
    # Policy record + table
    "RetentionPolicy",
    "RETENTION_POLICIES",
    # Pinned retention constants (audit-grepped)
    "TIMESCALE_TRANSACTION_RETENTION_SECONDS",
    "TIMESCALE_SCORE_RETENTION_SECONDS",
    "PROMETHEUS_RETENTION_SECONDS",
    "KAFKA_TRANSACTIONS_RETENTION_SECONDS",
    "KAFKA_REFUSAL_RETENTION_SECONDS",
    "INDEFINITE",
    # Helpers
    "is_on_chain",
    "get_policy",
    "erasable_policies",
    "non_erasable_policies",
    # Errors
    "DataProtectionError",
]
