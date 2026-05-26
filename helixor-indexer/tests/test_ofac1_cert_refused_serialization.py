"""
tests/test_ofac1_cert_refused_serialization.py — wire-format pins for
the OFAC-1 silent-delist transparency topic.

The substrate is `helixor-oracle/oracle/cert_refusal_log.py`; this
test file pins the indexer-side serialiser for
`Topic.CERT_REFUSED = "agent.cert_events.refused"`.

Pins:
  - Round-trip is byte-identical (canonical JSON, sorted keys).
  - The serialiser rejects empty wallet, negative epoch, empty
    reasons, naive (tz-unaware) datetime.
  - The deserialiser rejects wire-version mismatch and missing fields.
  - `Topic.CERT_REFUSED` is wired with the canonical topic name.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from eventbus.serialization import (
    CERT_REFUSED_WIRE_VERSION,
    SerializationError,
    deserialize_cert_refused,
    serialize_cert_refused,
)
from eventbus.types import Topic


UTC_NOW = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------------------------
# Topic registration
# ----------------------------------------------------------------------------

def test_topic_cert_refused_canonical_name():
    """Topic.CERT_REFUSED must carry the canonical topic string —
    producers and consumers depend on this exact value."""
    assert Topic.CERT_REFUSED.value == "agent.cert_events.refused"


# ----------------------------------------------------------------------------
# Round-trip
# ----------------------------------------------------------------------------

def test_round_trip_byte_identical():
    """A record serialised, deserialised, and re-serialised must be
    byte-identical. The indexer's idempotent dedup uses the bytes as a
    stable fingerprint."""
    raw = serialize_cert_refused(
        agent_wallet="agent-1",
        epoch=42,
        requested_tier="GREEN",
        gate="NSS-3",
        reasons=("AGENT_SECONDS_TOO_YOUNG", "AGENT_EPOCHS_TOO_YOUNG"),
        detected_at=UTC_NOW,
    )
    decoded = deserialize_cert_refused(raw)
    assert decoded["agent_wallet"] == "agent-1"
    assert decoded["epoch"] == 42
    assert decoded["requested_tier"] == "GREEN"
    assert decoded["gate"] == "NSS-3"
    assert decoded["reasons"] == [
        "AGENT_SECONDS_TOO_YOUNG", "AGENT_EPOCHS_TOO_YOUNG",
    ]
    assert decoded["wire_version"] == CERT_REFUSED_WIRE_VERSION

    # Re-serialise with the SAME inputs → identical bytes.
    raw2 = serialize_cert_refused(
        agent_wallet=decoded["agent_wallet"],
        epoch=decoded["epoch"],
        requested_tier=decoded["requested_tier"],
        gate=decoded["gate"],
        reasons=tuple(decoded["reasons"]),
        detected_at=datetime.fromisoformat(decoded["detected_at"]),
    )
    assert raw == raw2


def test_canonical_json_sorted_keys():
    """The wire format MUST sort keys — a consumer that hashes the
    bytes for dedup depends on the JSON key order being canonical."""
    raw = serialize_cert_refused(
        agent_wallet="agent-1",
        epoch=42,
        requested_tier="GREEN",
        gate="NSS-3",
        reasons=("AGENT_SECONDS_TOO_YOUNG",),
        detected_at=UTC_NOW,
    )
    payload = json.loads(raw.decode("utf-8"))
    # Re-encode WITHOUT sort_keys — if the raw output was canonical,
    # the round-trip-canonical version equals it.
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    assert raw == canonical


def test_detected_at_normalised_to_utc():
    """A non-UTC tz-aware datetime is normalised to UTC on the wire."""
    sgt = timezone(timedelta(hours=8))
    sgt_now = UTC_NOW.astimezone(sgt)
    raw = serialize_cert_refused(
        agent_wallet="agent-1",
        epoch=42,
        requested_tier="GREEN",
        gate="NSS-3",
        reasons=("AGENT_SECONDS_TOO_YOUNG",),
        detected_at=sgt_now,
    )
    decoded = deserialize_cert_refused(raw)
    # The wire carries UTC.
    parsed = datetime.fromisoformat(decoded["detected_at"])
    assert parsed == UTC_NOW
    assert parsed.utcoffset() == timedelta(0)


# ----------------------------------------------------------------------------
# Serialiser input validation
# ----------------------------------------------------------------------------

def test_serialise_rejects_empty_wallet():
    with pytest.raises(SerializationError, match="agent_wallet must be non-empty"):
        serialize_cert_refused(
            agent_wallet="",
            epoch=42,
            requested_tier="GREEN",
            gate="NSS-3",
            reasons=("AGENT_SECONDS_TOO_YOUNG",),
            detected_at=UTC_NOW,
        )


def test_serialise_rejects_negative_epoch():
    with pytest.raises(SerializationError, match="epoch must be >= 0"):
        serialize_cert_refused(
            agent_wallet="agent-1",
            epoch=-1,
            requested_tier="GREEN",
            gate="NSS-3",
            reasons=("AGENT_SECONDS_TOO_YOUNG",),
            detected_at=UTC_NOW,
        )


def test_serialise_rejects_empty_reasons():
    """A refusal with no reason codes is structurally suspect — the
    silent-censorship case OFAC-1 is designed to surface."""
    with pytest.raises(SerializationError, match="reasons must be non-empty"):
        serialize_cert_refused(
            agent_wallet="agent-1",
            epoch=42,
            requested_tier="GREEN",
            gate="NSS-3",
            reasons=(),
            detected_at=UTC_NOW,
        )


def test_serialise_rejects_naive_datetime():
    naive = datetime(2026, 5, 27, 12, 0, 0)  # no tzinfo
    with pytest.raises(SerializationError, match="must be tz-aware"):
        serialize_cert_refused(
            agent_wallet="agent-1",
            epoch=42,
            requested_tier="GREEN",
            gate="NSS-3",
            reasons=("AGENT_SECONDS_TOO_YOUNG",),
            detected_at=naive,
        )


# ----------------------------------------------------------------------------
# Deserialiser robustness
# ----------------------------------------------------------------------------

def test_deserialise_rejects_invalid_json():
    with pytest.raises(SerializationError, match="not valid JSON"):
        deserialize_cert_refused(b"not-json")


def test_deserialise_rejects_non_object_payload():
    with pytest.raises(SerializationError, match="not a JSON object"):
        deserialize_cert_refused(b"[1, 2, 3]")


def test_deserialise_rejects_wire_version_mismatch():
    payload = {
        "wire_version":   CERT_REFUSED_WIRE_VERSION + 99,
        "agent_wallet":   "agent-1",
        "epoch":          42,
        "requested_tier": "GREEN",
        "gate":           "NSS-3",
        "reasons":        ["AGENT_SECONDS_TOO_YOUNG"],
        "detected_at":    UTC_NOW.isoformat(),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(SerializationError, match="wire version mismatch"):
        deserialize_cert_refused(raw)


def test_deserialise_rejects_missing_field():
    payload = {
        "wire_version":   CERT_REFUSED_WIRE_VERSION,
        "agent_wallet":   "agent-1",
        "epoch":          42,
        "requested_tier": "GREEN",
        "gate":           "NSS-3",
        # "reasons" missing — poison message.
        "detected_at":    UTC_NOW.isoformat(),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(SerializationError, match="missing required field 'reasons'"):
        deserialize_cert_refused(raw)
