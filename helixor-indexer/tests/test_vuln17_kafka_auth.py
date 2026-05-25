"""
tests/test_vuln17_kafka_auth.py — VULN-17 mitigation invariants.

THE AUDIT FINDING
-----------------
VULN-17 (HIGH) — Default Kafka and Redis installations have no
authentication. A network-adjacent attacker (a leaked internal
address, a misconfigured VPC, a compromised neighbour) can publish
arbitrary records to any topic, read every detection event before the
certificate is on chain, or wipe partitions outright. VULN-07 made
each MESSAGE self-authenticating with an Ed25519 signature; it did
NOT authenticate the CONNECTION. Both layers are needed.

WHAT THIS FILE PINS
-------------------
The decisions the `eventbus/kafka_security` guard makes:

  1. PRODUCTION (HELIXOR_NETWORK=mainnet-beta) REFUSES Kafka clients
     that don't use SASL_SSL/SSL — and the refusal is observable as a
     `KafkaSecurityRefused` exception at config-build time, NOT some
     opaque librdkafka error after the client is already running.

  2. The escape hatch is EXPLICIT: HELIXOR_KAFKA_PLAINTEXT_OK=1 — and
     when used, the start logs an ERROR so the conscious decision is
     auditable in service logs.

  3. SASL requires BOTH a mechanism and credentials. A misconfigured
     SASL_SSL with no username/password is rejected up-front, not
     after the first failed handshake.

  4. Non-production networks accept plaintext but log a warning — so
     a developer never forgets that the prod path is different.

  5. The verdict's rendered rdkafka config dict carries the right keys
     (security.protocol, sasl.mechanism, sasl.username, sasl.password,
     ssl.*) — i.e., the from-env factory's output is the dict
     confluent-kafka actually consumes.

  6. The password NEVER appears in the verdict object's logged
     representation — it is only attached at client-construction time
     via `with_password_for_rdkafka`. (A regression that surfaces the
     secret in the verdict would re-introduce the audit risk.)

Each test class targets one trust surface. Failure of any of these
is the difference between "audit-clean" and "an attacker on the wire
producing into agent.transactions".
"""

from __future__ import annotations

import logging

import pytest

from eventbus.confluent_adapter import ConfluentKafkaConfig
from eventbus.kafka_security import (
    ENV_PLAINTEXT_OK,
    ENV_PROTOCOL,
    ENV_SASL_MECHANISM,
    ENV_SASL_PASSWORD,
    ENV_SASL_USERNAME,
    KafkaSecurityRefused,
    KafkaSecurityVerdict,
    MissingKafkaCredentials,
    PRODUCTION_SAFE_PROTOCOLS,
    PROTO_PLAINTEXT,
    PROTO_SASL_PLAINTEXT,
    PROTO_SASL_SSL,
    PROTO_SSL,
    UnsupportedKafkaSecurity,
    enforce_kafka_security,
    evaluate,
    is_production_network,
    override_kafka_security,
)


# =============================================================================
# (1) Production refuses plaintext / un-authenticated protocols.
# =============================================================================

class TestProductionRefusesPlaintext:
    """The CORE VULN-17 invariant: mainnet without auth must not start."""

    def test_mainnet_plaintext_refused(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
        ):
            with pytest.raises(KafkaSecurityRefused) as exc:
                enforce_kafka_security(service="ut")
            # Operator-actionable error message.
            assert "PLAINTEXT" in str(exc.value)
            assert "mainnet-beta" in str(exc.value)

    def test_mainnet_default_protocol_refused(self):
        # No KAFKA_SECURITY_PROTOCOL set at all — defaults to PLAINTEXT,
        # and production must refuse that exactly the same way as an
        # explicit "PLAINTEXT". This pins the "default is unauthenticated"
        # attack the audit calls out.
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL=None,
        ):
            with pytest.raises(KafkaSecurityRefused):
                enforce_kafka_security(service="ut")

    def test_mainnet_sasl_plaintext_refused(self):
        # SASL_PLAINTEXT authenticates but sends the password and every
        # message in clear text. Production must refuse this too.
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_PLAINTEXT",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME="svc-indexer",
            KAFKA_SASL_PASSWORD="hunter2",
        ):
            with pytest.raises(KafkaSecurityRefused):
                enforce_kafka_security(service="ut")


# =============================================================================
# (2) Production accepts encrypted + authenticated configurations.
# =============================================================================

class TestProductionAcceptsSaslSsl:
    """SASL_SSL is the default acceptable production protocol."""

    def test_mainnet_sasl_ssl_with_scram_accepted(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME="svc-indexer",
            KAFKA_SASL_PASSWORD="hunter2",
        ):
            v = enforce_kafka_security(service="ut")
        assert v.protocol == PROTO_SASL_SSL
        assert v.sasl_mechanism == "SCRAM-SHA-256"
        assert v.sasl_username == "svc-indexer"
        assert v.is_encrypted is True
        assert v.is_authenticated is True

    def test_mainnet_plain_mtls_ssl_accepted(self):
        # SSL (mutual TLS, no SASL) is also a valid production protocol —
        # the client cert IS the credential.
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SSL",
            KAFKA_SSL_CA_LOCATION="/etc/helixor/kafka/ca.crt",
            KAFKA_SSL_CERTIFICATE_LOCATION="/etc/helixor/kafka/client.crt",
            KAFKA_SSL_KEY_LOCATION="/etc/helixor/kafka/client.key",
        ):
            v = enforce_kafka_security(service="ut")
        assert v.protocol == PROTO_SSL
        assert v.is_encrypted is True
        assert v.is_authenticated is False  # mTLS, no SASL handshake
        assert v.ssl_ca == "/etc/helixor/kafka/ca.crt"

    def test_production_safe_set_is_intentional(self):
        # Pin the set of protocols deemed safe for production. Adding
        # PLAINTEXT or SASL_PLAINTEXT to this set would silently
        # re-introduce VULN-17 — a test failure here forces the change
        # to be discussed.
        assert PRODUCTION_SAFE_PROTOCOLS == {PROTO_SASL_SSL, PROTO_SSL}


# =============================================================================
# (3) The escape hatch is explicit, audited, and required to be exact "1".
# =============================================================================

class TestPlaintextOptIn:
    """HELIXOR_KAFKA_PLAINTEXT_OK=1 — a conscious, auditable opt-in."""

    def test_opt_in_allows_plaintext_in_production(self, caplog):
        # An operator who genuinely wants plaintext on mainnet (e.g.,
        # a private-link broker behind a service mesh that already
        # authenticates) sets the explicit opt-in. Allowed — but logged
        # at ERROR severity so the decision is auditable forever in logs.
        caplog.set_level(logging.DEBUG, logger="helixor.eventbus.kafka_security")
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
            HELIXOR_KAFKA_PLAINTEXT_OK="1",
        ):
            v = enforce_kafka_security(service="ut")
        assert v.protocol == PROTO_PLAINTEXT
        assert v.plaintext_opt_in is True
        # The auditable log line.
        record_levels = {r.levelname for r in caplog.records
                         if r.name == "helixor.eventbus.kafka_security"}
        assert "ERROR" in record_levels

    def test_opt_in_value_other_than_1_is_not_honoured(self):
        # The flag must be exactly "1" (whitespace-trimmed, matching
        # the project-wide HELIXOR_MAINNET_OK convention). "true",
        # "yes", "TRUE", "0", and empty values all leave production in
        # the refused state. This pins the "did you set the env var to
        # a truthy-looking string" gotcha.
        for bad in ("true", "yes", "TRUE", "0", "", "  ", "10", "01"):
            with override_kafka_security(
                HELIXOR_NETWORK="mainnet-beta",
                KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
                HELIXOR_KAFKA_PLAINTEXT_OK=bad,
            ):
                with pytest.raises(KafkaSecurityRefused):
                    enforce_kafka_security(service="ut")

    def test_opt_in_does_not_affect_non_production(self):
        # The opt-in is a production concept. In dev it's a no-op
        # because plaintext is already permitted.
        with override_kafka_security(
            HELIXOR_NETWORK="devnet",
            KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
            HELIXOR_KAFKA_PLAINTEXT_OK="1",
        ):
            v = enforce_kafka_security(service="ut")
        assert v.protocol == PROTO_PLAINTEXT
        assert v.network == "devnet"


# =============================================================================
# (4) SASL completeness — partial configs must fail BEFORE the client tries.
# =============================================================================

class TestSaslCredentialCompleteness:
    """Misconfigured SASL is rejected at evaluate() time."""

    def test_sasl_protocol_without_mechanism_rejected(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM=None,
            KAFKA_SASL_USERNAME="u",
            KAFKA_SASL_PASSWORD="p",
        ):
            with pytest.raises(UnsupportedKafkaSecurity) as exc:
                evaluate()
            assert "KAFKA_SASL_MECHANISM" in str(exc.value)

    def test_sasl_protocol_without_username_rejected(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME=None,
            KAFKA_SASL_PASSWORD="p",
        ):
            with pytest.raises(MissingKafkaCredentials):
                evaluate()

    def test_sasl_protocol_without_password_rejected(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME="u",
            KAFKA_SASL_PASSWORD=None,
        ):
            with pytest.raises(MissingKafkaCredentials):
                evaluate()

    def test_unknown_protocol_value_rejected(self):
        with override_kafka_security(
            KAFKA_SECURITY_PROTOCOL="SASL_TLS",   # not a real protocol
        ):
            with pytest.raises(UnsupportedKafkaSecurity):
                evaluate()

    def test_unknown_sasl_mechanism_value_rejected(self):
        with override_kafka_security(
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-1024",  # not real
            KAFKA_SASL_USERNAME="u",
            KAFKA_SASL_PASSWORD="p",
        ):
            with pytest.raises(UnsupportedKafkaSecurity):
                evaluate()


# =============================================================================
# (5) Non-production accepts plaintext (with a warning).
# =============================================================================

class TestDevPermitsPlaintext:
    """Plaintext in dev is loud but allowed — never silently."""

    def test_devnet_plaintext_allowed(self, caplog):
        caplog.set_level(logging.DEBUG, logger="helixor.eventbus.kafka_security")
        with override_kafka_security(
            HELIXOR_NETWORK="devnet",
            KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
        ):
            v = enforce_kafka_security(service="ut")
        assert v.protocol == PROTO_PLAINTEXT
        # A WARNING log so the developer can't claim they didn't know.
        warn = [r for r in caplog.records
                if r.name == "helixor.eventbus.kafka_security"
                and r.levelname == "WARNING"]
        assert warn, "expected a WARNING log for plaintext on devnet"

    def test_localnet_sasl_plaintext_allowed(self):
        # SASL_PLAINTEXT in dev — the recommended dev mode: proves the
        # SASL handshake works end-to-end without needing real certs.
        with override_kafka_security(
            HELIXOR_NETWORK="localnet",
            KAFKA_SECURITY_PROTOCOL="SASL_PLAINTEXT",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME="dev",
            KAFKA_SASL_PASSWORD="dev",
        ):
            v = enforce_kafka_security(service="ut")
        assert v.protocol == PROTO_SASL_PLAINTEXT
        assert v.is_authenticated is True
        assert v.is_encrypted is False

    def test_unset_network_defaults_to_localnet(self):
        # The guard must not silently treat an unset HELIXOR_NETWORK as
        # production. (A missing var defaults to "localnet".)
        with override_kafka_security(
            HELIXOR_NETWORK=None,
            KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
        ):
            v = enforce_kafka_security(service="ut")
        assert v.network == "localnet"
        assert not is_production_network(v.network)


# =============================================================================
# (6) rdkafka rendering — verdict → librdkafka config keys.
# =============================================================================

class TestRdkafkaConfigRendering:
    """The verdict's dict has the exact keys confluent-kafka consumes."""

    def test_sasl_ssl_renders_full_config(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-512",
            KAFKA_SASL_USERNAME="svc-indexer",
            KAFKA_SASL_PASSWORD="hunter2",
            KAFKA_SSL_CA_LOCATION="/etc/ssl/ca.crt",
        ):
            v = enforce_kafka_security(service="ut")
        cfg = v.with_password_for_rdkafka("hunter2")
        assert cfg["security.protocol"]  == "SASL_SSL"
        assert cfg["sasl.mechanism"]     == "SCRAM-SHA-512"
        assert cfg["sasl.username"]      == "svc-indexer"
        assert cfg["sasl.password"]      == "hunter2"
        assert cfg["ssl.ca.location"]    == "/etc/ssl/ca.crt"

    def test_logged_dict_omits_password(self):
        # to_rdkafka_config() is the "safe to log" rendering — the
        # password must NEVER appear. A regression here would leak
        # credentials into structured logs / metrics / DLQ payloads.
        v = KafkaSecurityVerdict(
            protocol="SASL_SSL",
            sasl_mechanism="SCRAM-SHA-256",
            sasl_username="svc",
            has_password=True,
            ssl_ca=None, ssl_cert=None, ssl_key=None,
            network="mainnet-beta",
            plaintext_opt_in=False,
        )
        cfg = v.to_rdkafka_config()
        assert "sasl.password" not in cfg
        # And the verdict's repr doesn't carry it either (has_password is
        # a bool, not the secret).
        assert "hunter2" not in repr(v)


# =============================================================================
# (7) ConfluentKafkaConfig.from_env — the integration seam.
# =============================================================================

class TestConfluentKafkaConfigFromEnv:
    """The from-env factory threads the guard into the producer config."""

    def test_from_env_attaches_security_settings_to_producer(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME="svc-indexer",
            KAFKA_SASL_PASSWORD="hunter2",
        ):
            cfg = ConfluentKafkaConfig.from_env(
                bootstrap_servers="kafka-0:9093,kafka-1:9093",
                service="ut",
            )
        prod = cfg.producer_config()
        assert prod["security.protocol"]  == "SASL_SSL"
        assert prod["sasl.mechanism"]     == "SCRAM-SHA-256"
        assert prod["sasl.username"]      == "svc-indexer"
        assert prod["sasl.password"]      == "hunter2"
        # Existing producer guarantees still in force.
        assert prod["acks"] == "all"
        assert prod["enable.idempotence"] is True

    def test_from_env_attaches_security_settings_to_consumer(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="SASL_SSL",
            KAFKA_SASL_MECHANISM="SCRAM-SHA-256",
            KAFKA_SASL_USERNAME="svc-indexer",
            KAFKA_SASL_PASSWORD="hunter2",
        ):
            cfg = ConfluentKafkaConfig.from_env(
                bootstrap_servers="kafka-0:9093",
                service="ut",
            )
        cons = cfg.consumer_config("oracle-cluster")
        assert cons["security.protocol"] == "SASL_SSL"
        assert cons["sasl.password"]     == "hunter2"
        assert cons["group.id"]          == "oracle-cluster"
        # Manual commit is the at-least-once guarantee — must remain.
        assert cons["enable.auto.commit"] is False

    def test_from_env_in_production_refuses_plaintext(self):
        with override_kafka_security(
            HELIXOR_NETWORK="mainnet-beta",
            KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
        ):
            with pytest.raises(KafkaSecurityRefused):
                ConfluentKafkaConfig.from_env(
                    bootstrap_servers="kafka:9092", service="ut",
                )

    def test_from_env_requires_bootstrap_servers(self):
        with override_kafka_security(
            HELIXOR_NETWORK="devnet",
            KAFKA_SECURITY_PROTOCOL="PLAINTEXT",
        ):
            # Neither KAFKA_BOOTSTRAP env nor the kwarg is provided.
            with pytest.raises(RuntimeError) as exc:
                ConfluentKafkaConfig.from_env(env={}, service="ut")
            assert "KAFKA_BOOTSTRAP" in str(exc.value)

    def test_legacy_constructor_unchanged(self):
        # The pre-VULN-17 constructor (used by tests that hand-curate
        # the `extra` dict) still works. The guard fires only when the
        # entrypoint chooses the from-env factory.
        cfg = ConfluentKafkaConfig(
            bootstrap_servers="kafka:9092",
            client_id="x",
            extra={"some.knob": "value"},
        )
        assert cfg.producer_config()["some.knob"] == "value"
        assert cfg.security_verdict is None


# =============================================================================
# (8) Env-var name stability — off-chain tooling and ops dashboards
# match on these strings; they must not be silently renamed.
# =============================================================================

class TestEnvVarStability:
    """The env-var names are the operator-facing API of this module."""

    def test_env_var_names_are_pinned(self):
        assert ENV_PROTOCOL          == "KAFKA_SECURITY_PROTOCOL"
        assert ENV_SASL_MECHANISM    == "KAFKA_SASL_MECHANISM"
        assert ENV_SASL_USERNAME     == "KAFKA_SASL_USERNAME"
        assert ENV_SASL_PASSWORD     == "KAFKA_SASL_PASSWORD"
        assert ENV_PLAINTEXT_OK      == "HELIXOR_KAFKA_PLAINTEXT_OK"
