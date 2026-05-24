"""
api/metrics.py — Prometheus instrumentation.

The names here are the names the alert rules
(launch/monitoring/alerts.yml) and runbooks (launch/runbooks/api_slow.md,
mainnet_refusal_triggered.md) curl for. Renaming a metric is a wire
break — the alert breaks silently. Treat the names below as the contract.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram,
    generate_latest,
)


# Use a dedicated registry rather than the global one so test code can
# create a fresh API instance per test without metric duplication errors.
def make_registry() -> CollectorRegistry:
    return CollectorRegistry()


# =============================================================================
# Standard buckets for latency histograms
# =============================================================================
#
# Production target: API p95 < 500ms (runbook api_slow.md). Buckets are
# chosen to give resolution around that threshold.

LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
)


# =============================================================================
# The metric set — created per registry
# =============================================================================

class ApiMetrics:
    """The full metric set the API records. One instance per registry."""

    def __init__(self, registry: CollectorRegistry) -> None:
        self.requests_total = Counter(
            "helixor_api_requests_total",
            "Total API requests, by method + route + status",
            labelnames=("method", "route", "status"),
            registry=registry,
        )
        self.request_seconds = Histogram(
            "helixor_api_request_seconds",
            "API request latency, by method + route",
            labelnames=("method", "route"),
            buckets=LATENCY_BUCKETS,
            registry=registry,
        )
        # Counter exposed to launch/monitoring/alerts.yml ::
        # ProductionRefusalTriggered. Incremented when the network guard
        # would have refused but the API was launched anyway with the
        # opt-in. Steady-state value should be 0; > 0 means a service was
        # CONFIGURED to point at production.
        self.production_refusal_total = Counter(
            "helixor_production_refusal_total",
            "Times the network guard refused a production start",
            labelnames=("service",),
            registry=registry,
        )
        # Indicator gauge — 1 if the current process is running against
        # mainnet (with explicit opt-in), 0 otherwise.
        self.is_production = Gauge(
            "helixor_api_is_production",
            "1 if the API is running against a production network",
            registry=registry,
        )
        # Schema version exposed as a gauge so a dashboard can pin which
        # release is live.
        self.schema_version = Gauge(
            "helixor_api_schema_version",
            "The wire-schema version this API serves",
            registry=registry,
        )


def render_metrics(registry: CollectorRegistry) -> tuple[bytes, str]:
    """Render the registry to Prometheus text format."""
    return generate_latest(registry), CONTENT_TYPE_LATEST
