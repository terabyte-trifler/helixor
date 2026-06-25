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
            "phylanx_api_requests_total",
            "Total API requests, by method + route + status",
            labelnames=("method", "route", "status"),
            registry=registry,
        )
        self.request_seconds = Histogram(
            "phylanx_api_request_seconds",
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
            "phylanx_production_refusal_total",
            "Times the network guard refused a production start",
            labelnames=("service",),
            registry=registry,
        )
        # Indicator gauge — 1 if the current process is running against
        # mainnet (with explicit opt-in), 0 otherwise.
        self.is_production = Gauge(
            "phylanx_api_is_production",
            "1 if the API is running against a production network",
            registry=registry,
        )
        # Schema version exposed as a gauge so a dashboard can pin which
        # release is live.
        self.schema_version = Gauge(
            "phylanx_api_schema_version",
            "The wire-schema version this API serves",
            registry=registry,
        )
        # VULN-09: rate-limit observability. A spike in rejections is
        # either a real DDoS or a misconfigured client; either way the
        # operator wants to see it.
        self.rate_limit_rejections_total = Counter(
            "phylanx_api_rate_limit_rejections_total",
            "Requests rejected by the sliding-window rate limiter",
            labelnames=("bucket_type",),   # "ip" | "key"
            registry=registry,
        )
        # VULN-09: auth observability. 401s on operational endpoints
        # should be rare in steady state; sustained 401s mean a client
        # is probing.
        self.auth_rejections_total = Counter(
            "phylanx_api_auth_rejections_total",
            "401s raised by the API-key gate on operational endpoints",
            labelnames=("route",),
            registry=registry,
        )
        # DBP-4: per-partner safe-reader share.
        #
        # Every score-read call from a Verified-Integrator key (a key
        # carrying a `partner_wallet`) is bucketed by `surface`:
        #   - "safe" — the partner called `/agents/{wallet}/safe_score`,
        #              the VULN-23 guard-railed endpoint.
        #   - "raw"  — the partner called `/agents/{wallet}/health`,
        #              `/agents/{wallet}/health/{epoch}`, or
        #              `/agents/{wallet}/history` directly — no
        #              freshness / velocity guard at the API layer.
        #
        # The leaderboard endpoint (DBP-4c) reads these counters and
        # computes safe_share = safe / (safe + raw) per partner_wallet.
        # The metric carries the partner_wallet pubkey directly because
        # that is the on-chain identity the leaderboard ranks — the
        # cardinality is bounded by the number of Verified Integrators
        # (≪ # of agents, so this is safe).
        self.safe_reader_share_total = Counter(
            "phylanx_api_safe_reader_share_total",
            "Score-read calls by a Verified-Integrator key, "
            "bucketed by surface (safe vs raw). DBP-4 telemetry.",
            labelnames=("partner_wallet", "surface"),
            registry=registry,
        )


def render_metrics(registry: CollectorRegistry) -> tuple[bytes, str]:
    """Render the registry to Prometheus text format."""
    return generate_latest(registry), CONTENT_TYPE_LATEST
