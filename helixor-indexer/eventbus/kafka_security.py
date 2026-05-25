"""
eventbus/kafka_security.py — VULN-17 MITIGATION.

THE AUDIT FINDING
-----------------
HIGH. Default Kafka and Redis installations have no authentication. If
the broker is reachable beyond localhost (and even when it isn't — a
compromised neighbour, a misconfigured network policy, a leaked
internal address), any producer can publish to any topic. Helixor
already mitigates per-message spoofing via VULN-07's Ed25519 payload
signatures, BUT:

  * an attacker who can produce arbitrary records can still flood a
    topic, racing the legitimate producer and burning consumer budget;
  * an attacker who can consume can read every detection event before
    the certificate is on chain — a leak of pre-publish state;
  * a topic with no broker ACL is one `kafka-topics --delete` away
    from a partition wipe.

VULN-07's payload signing authenticates the BYTES that arrived. It
does NOT authenticate the CONNECTION that delivered them. Both layers
are needed.

THE GUARD
---------
A tiny env-var-driven decision module: given the configured Kafka
security knobs (KAFKA_SECURITY_PROTOCOL + the SASL/SSL settings
appropriate to it), this module decides whether the resulting client
config is acceptable for the current HELIXOR_NETWORK.

The rules:

  * PRODUCTION (mainnet-beta) — REFUSE plaintext. The protocol must
    be one of {SSL, SASL_SSL}, OR the operator must set
    HELIXOR_KAFKA_PLAINTEXT_OK=1 to make the decision conscious and
    grep-able in service logs.

  * NON-PRODUCTION (localnet/devnet/testnet) — plaintext is permitted
    but a WARNING is logged so the operator never forgets. SASL_PLAINTEXT
    is the recommended dev mode: still warns about the missing TLS,
    but proves the SASL handshake works end-to-end.

  * SASL_SSL / SSL — accepted everywhere. The SASL knobs (mechanism,
    username, password) are validated to be present when the protocol
    name includes SASL.

WHY ENV-VARS, NOT A SECRETS FILE
--------------------------------
The deployment plane is a 12-factor process: env vars are how the
systemd unit, the docker-compose service, and the K8s Pod spec all
pass secrets. The SASL password is sourced from a sealed file by the
orchestrator and exported into the env at process start.

WHY THIS MODULE (NOT A QUIET DEFAULT)
-------------------------------------
A "default to PLAINTEXT" client silently works against an
unauthenticated broker. A "default to refuse" client REQUIRES the
operator to make a decision — either supply SASL/SSL settings, or set
the explicit opt-in. The audit's "default config is unauthenticated"
fault model is what this module exists to refuse.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger("helixor.eventbus.kafka_security")


# =============================================================================
# Supported Kafka security protocols (the canonical librdkafka names).
# =============================================================================

PROTO_PLAINTEXT      = "PLAINTEXT"
PROTO_SSL            = "SSL"
PROTO_SASL_PLAINTEXT = "SASL_PLAINTEXT"
PROTO_SASL_SSL       = "SASL_SSL"

SUPPORTED_PROTOCOLS = frozenset({
    PROTO_PLAINTEXT, PROTO_SSL, PROTO_SASL_PLAINTEXT, PROTO_SASL_SSL,
})

# Protocols that ENCRYPT in transit (TLS underneath).
ENCRYPTED_PROTOCOLS = frozenset({PROTO_SSL, PROTO_SASL_SSL})

# Protocols that AUTHENTICATE the client (SASL handshake).
SASL_PROTOCOLS      = frozenset({PROTO_SASL_PLAINTEXT, PROTO_SASL_SSL})

# Protocols accepted in production without an opt-in.
PRODUCTION_SAFE_PROTOCOLS = frozenset({PROTO_SASL_SSL, PROTO_SSL})


# =============================================================================
# Supported SASL mechanisms — pinned to the rdkafka-known set. PLAIN is
# accepted but is only safe under SASL_SSL (the password travels in clear
# text otherwise). SCRAM is preferred.
# =============================================================================

SASL_MECH_PLAIN         = "PLAIN"
SASL_MECH_SCRAM_SHA_256 = "SCRAM-SHA-256"
SASL_MECH_SCRAM_SHA_512 = "SCRAM-SHA-512"
SASL_MECH_GSSAPI        = "GSSAPI"
SASL_MECH_OAUTHBEARER   = "OAUTHBEARER"

SUPPORTED_SASL_MECHANISMS = frozenset({
    SASL_MECH_PLAIN, SASL_MECH_SCRAM_SHA_256, SASL_MECH_SCRAM_SHA_512,
    SASL_MECH_GSSAPI, SASL_MECH_OAUTHBEARER,
})


# =============================================================================
# Env-var surface — the full set this module consults.
# =============================================================================

ENV_PROTOCOL          = "KAFKA_SECURITY_PROTOCOL"
ENV_SASL_MECHANISM    = "KAFKA_SASL_MECHANISM"
ENV_SASL_USERNAME     = "KAFKA_SASL_USERNAME"
ENV_SASL_PASSWORD     = "KAFKA_SASL_PASSWORD"   # never logged
ENV_SSL_CA_LOCATION   = "KAFKA_SSL_CA_LOCATION"
ENV_SSL_CERT_LOCATION = "KAFKA_SSL_CERTIFICATE_LOCATION"
ENV_SSL_KEY_LOCATION  = "KAFKA_SSL_KEY_LOCATION"

# The escape hatch — only honoured when set to exactly "1". Logged loudly.
ENV_PLAINTEXT_OK      = "HELIXOR_KAFKA_PLAINTEXT_OK"


# =============================================================================
# Exceptions
# =============================================================================

class KafkaSecurityRefused(RuntimeError):
    """Production refuses a plaintext / un-authenticated Kafka client."""


class UnsupportedKafkaSecurity(RuntimeError):
    """A supplied env var has an unrecognised value."""


class MissingKafkaCredentials(RuntimeError):
    """SASL was requested but no credentials were provided."""


# =============================================================================
# Verdict
# =============================================================================

@dataclass(frozen=True, slots=True)
class KafkaSecurityVerdict:
    """The decision the guard arrived at — exposed so callers can inspect it."""
    protocol:        str
    sasl_mechanism:  str | None
    sasl_username:   str | None
    has_password:    bool          # never expose the password itself
    ssl_ca:          str | None
    ssl_cert:        str | None
    ssl_key:         str | None
    network:         str
    plaintext_opt_in: bool

    @property
    def is_encrypted(self) -> bool:
        return self.protocol in ENCRYPTED_PROTOCOLS

    @property
    def is_authenticated(self) -> bool:
        return self.protocol in SASL_PROTOCOLS

    def to_rdkafka_config(self) -> dict[str, Any]:
        """
        Render the verdict as a librdkafka config dict — the exact keys
        confluent-kafka consumes. SAFE TO LOG: the password is excluded.
        Use `with_password_for_rdkafka` to attach the password just-in-time
        when constructing the real client.
        """
        out: dict[str, Any] = {"security.protocol": self.protocol}
        if self.sasl_mechanism is not None:
            out["sasl.mechanism"] = self.sasl_mechanism
        if self.sasl_username is not None:
            out["sasl.username"] = self.sasl_username
        if self.ssl_ca is not None:
            out["ssl.ca.location"] = self.ssl_ca
        if self.ssl_cert is not None:
            out["ssl.certificate.location"] = self.ssl_cert
        if self.ssl_key is not None:
            out["ssl.key.location"] = self.ssl_key
        return out

    def with_password_for_rdkafka(self, password: str | None) -> dict[str, Any]:
        """
        Same as `to_rdkafka_config`, plus `sasl.password`. NEVER LOG the
        returned dict — call this only when handing config to the client.
        """
        out = self.to_rdkafka_config()
        if password is not None and self.is_authenticated:
            out["sasl.password"] = password
        return out


# =============================================================================
# Public API
# =============================================================================

def _strip(value: str | None) -> str | None:
    """Return None for missing / empty strings; trim whitespace otherwise."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def evaluate(env: dict[str, str] | None = None) -> KafkaSecurityVerdict:
    """
    Compute the current verdict. Pure — does not raise on unsafe configs;
    raises only on UNRECOGNISED / MALFORMED inputs. `enforce_kafka_security`
    is the gate that turns "unsafe but well-formed" into a refusal.

    `env` overrides os.environ for tests.
    """
    env = dict(env) if env is not None else dict(os.environ)

    protocol = _strip(env.get(ENV_PROTOCOL)) or PROTO_PLAINTEXT
    protocol_uc = protocol.upper()
    if protocol_uc not in SUPPORTED_PROTOCOLS:
        raise UnsupportedKafkaSecurity(
            f"{ENV_PROTOCOL}={protocol!r} is not one of "
            f"{sorted(SUPPORTED_PROTOCOLS)}"
        )

    mechanism = _strip(env.get(ENV_SASL_MECHANISM))
    if mechanism is not None:
        mechanism = mechanism.upper()
        if mechanism not in SUPPORTED_SASL_MECHANISMS:
            raise UnsupportedKafkaSecurity(
                f"{ENV_SASL_MECHANISM}={mechanism!r} is not one of "
                f"{sorted(SUPPORTED_SASL_MECHANISMS)}"
            )

    # SASL requires a mechanism. If the user picked a SASL protocol but
    # forgot the mechanism, refuse before we hand a broken config to the
    # client — librdkafka's error here is opaque.
    if protocol_uc in SASL_PROTOCOLS and mechanism is None:
        raise UnsupportedKafkaSecurity(
            f"{ENV_PROTOCOL}={protocol_uc} requires {ENV_SASL_MECHANISM} "
            f"to be set (one of {sorted(SUPPORTED_SASL_MECHANISMS)})"
        )

    username = _strip(env.get(ENV_SASL_USERNAME))
    password = _strip(env.get(ENV_SASL_PASSWORD))
    if protocol_uc in SASL_PROTOCOLS:
        if username is None or password is None:
            raise MissingKafkaCredentials(
                f"{ENV_PROTOCOL}={protocol_uc} requires both "
                f"{ENV_SASL_USERNAME} and {ENV_SASL_PASSWORD} to be set"
            )

    # Network identity — imported lazily so this module does not pull
    # the oracle package into the indexer's import graph at top level.
    network = _strip(env.get("HELIXOR_NETWORK")) or "localnet"

    plaintext_opt_in = _strip(env.get(ENV_PLAINTEXT_OK)) == "1"

    return KafkaSecurityVerdict(
        protocol=protocol_uc,
        sasl_mechanism=mechanism,
        sasl_username=username,
        has_password=password is not None,
        ssl_ca=_strip(env.get(ENV_SSL_CA_LOCATION)),
        ssl_cert=_strip(env.get(ENV_SSL_CERT_LOCATION)),
        ssl_key=_strip(env.get(ENV_SSL_KEY_LOCATION)),
        network=network,
        plaintext_opt_in=plaintext_opt_in,
    )


def is_production_network(network: str) -> bool:
    """The set of networks that MUST refuse plaintext without opt-in."""
    return network.strip().lower() == "mainnet-beta"


def enforce_kafka_security(
    *,
    service: str | None = None,
    env: dict[str, str] | None = None,
) -> KafkaSecurityVerdict:
    """
    Enforce the Kafka security guard. Returns the verdict on success;
    raises `KafkaSecurityRefused` if production has no encrypted/authenticated
    protocol and no explicit opt-in.

    `service` names the calling entrypoint, only used for the log line.
    `env` overrides os.environ for tests.
    """
    verdict = evaluate(env)
    label = service or "<unspecified>"

    in_production = is_production_network(verdict.network)

    if in_production and verdict.protocol not in PRODUCTION_SAFE_PROTOCOLS:
        if not verdict.plaintext_opt_in:
            msg = (
                f"kafka_security: REFUSING to start service {label!r} against "
                f"network {verdict.network!r} with Kafka "
                f"protocol={verdict.protocol!r}. Production must use one of "
                f"{sorted(PRODUCTION_SAFE_PROTOCOLS)} (set "
                f"{ENV_PROTOCOL}=SASL_SSL + the {ENV_SASL_USERNAME}/"
                f"{ENV_SASL_PASSWORD} pair, or set {ENV_PLAINTEXT_OK}=1 "
                f"to make this conscious — see launch/RUNBOOK.md)."
            )
            logger.error(msg)
            raise KafkaSecurityRefused(msg)
        logger.error(
            "kafka_security: PRODUCTION service %s starting with INSECURE "
            "Kafka protocol %r — operator set %s=1. This is auditable.",
            label, verdict.protocol, ENV_PLAINTEXT_OK,
        )
        return verdict

    if not verdict.is_encrypted:
        # Non-production with plaintext / SASL_PLAINTEXT — allowed but log.
        logger.warning(
            "kafka_security: service %s starting with UN-ENCRYPTED Kafka "
            "protocol %r on network %r — acceptable for dev, NEVER for "
            "production",
            label, verdict.protocol, verdict.network,
        )
    else:
        logger.info(
            "kafka_security: service %s starting with %r"
            "%s on network %r",
            label, verdict.protocol,
            f" + SASL/{verdict.sasl_mechanism}"
              if verdict.is_authenticated else "",
            verdict.network,
        )
    return verdict


# =============================================================================
# Test helper — flip the env for a block of code
# =============================================================================

@contextmanager
def override_kafka_security(**env: str | None):
    """
    Temporarily override the kafka-security env vars for a test. Restores
    the previous values on exit, even on exception. A `None` value
    *removes* the variable.

    Usage:
        with override_kafka_security(
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME="svc-indexer",
            KAFKA_SASL_PASSWORD="hunter2",
            HELIXOR_NETWORK="mainnet-beta",
        ):
            v = enforce_kafka_security(service="ut")
    """
    prev: dict[str, str | None] = {k: os.environ.get(k) for k in env}
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def password_from_env(env: dict[str, str] | None = None) -> str | None:
    """
    Read the SASL password out-of-band. Kept separate from `evaluate`
    so the verdict struct never needs to carry the secret.
    """
    env = dict(env) if env is not None else dict(os.environ)
    return _strip(env.get(ENV_SASL_PASSWORD))
