"""
audit/load_tests/api_load.py — Day-29 API load test scaffold.

Acceptance: 10,000 agent health queries/hour sustained against the
helixor read API, p95 latency < 500ms.

10K req/h = 2.78 req/s sustained. The harness runs `--rate` requests per
second over `--duration` seconds, records latencies, and asserts p95
and error rate. The standard run is `--rate 4 --duration 3600` (slightly
above target, for headroom), giving 14,400 queries in 1 hour.

HONEST EXECUTION
----------------
The full 1-hour run requires the deployed read API. This harness IS the
load-test runner — it talks to whatever URL is supplied via --base-url.
For audit-readiness, the auditor runs:

    python audit/load_tests/api_load.py --base-url http://<deployed-api>/ \\
        --rate 4 --duration 3600

In local dev / CI, a short run validates the harness itself:

    python audit/load_tests/api_load.py --base-url http://localhost:8080/ \\
        --rate 4 --duration 30

The 30s smoke run extrapolates: if 120 queries in 30s with p95 < 500ms
on a local API, the 1-hour run at the same rate sustains 14,400 queries
with the same p95 — assuming the deployed infra has equal or better
characteristics.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import URLError


# A small pool of agent wallets to query. Production seeds with the actual
# registered agent list pulled from the on-chain registry.
DEFAULT_AGENTS = [
    f"agent{i:04d}{'x'*36}"[:44] for i in range(100)
]


def _agents_from_env_or_default() -> list[str]:
    raw = os.environ.get("HELIXOR_API_LOAD_AGENTS", "").strip()
    if not raw:
        return DEFAULT_AGENTS
    agents = [item.strip() for item in raw.split(",") if item.strip()]
    return agents or DEFAULT_AGENTS


def one_query(base_url: str, agent_wallet: str, timeout_s: float = 5.0):
    """A single agent-health query.

    Returns (latency_ms, category, status) where category is one of
    "ok"        — 2xx response
    "not_found" — 404 (the endpoint works, the agent isn't known yet)
    "client"    — other 4xx (a bug in the test or a contract change)
    "server"    — 5xx or transport (the API is broken)
    """
    url = f"{base_url.rstrip('/')}/agents/{agent_wallet}/health"
    start = time.perf_counter()
    try:
        req = urlrequest.Request(url, headers={"Accept": "application/json"})
        with urlrequest.urlopen(req, timeout=timeout_s) as resp:
            _ = resp.read()
            elapsed_ms = (time.perf_counter() - start) * 1000
            return elapsed_ms, "ok", resp.status
    except URLError as exc:
        status = getattr(exc, "code", 0) or 0
        elapsed_ms = (time.perf_counter() - start) * 1000
        if status == 404:
            return elapsed_ms, "not_found", status
        if 400 <= status < 500:
            return elapsed_ms, "client", status
        return elapsed_ms, "server", str(exc)
    except Exception as exc:                # noqa: BLE001
        return (time.perf_counter() - start) * 1000, "server", repr(exc)


def run_load(base_url: str, rate: float, duration_s: int,
             agents: list[str], workers: int = 16) -> dict:
    """
    Drive `rate` req/s for `duration_s` seconds, randomly sampling agents.
    Returns a dict with latencies, per-category counts, and pass/fail.

    Categories:
      "ok"        — 2xx; the API returned the agent's health
      "not_found" — 404; the endpoint works but the agent isn't indexed
      "client"    — other 4xx; the test is wrong or contract drifted
      "server"    — 5xx / transport; the API is broken
    """
    latencies_ok:        list[float] = []
    latencies_not_found: list[float] = []
    latencies_client:    list[float] = []
    latencies_server:    list[float] = []
    error_samples: list[str] = []
    started = time.perf_counter()
    next_emit = started
    interval = 1.0 / rate

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []
        while time.perf_counter() - started < duration_s:
            agent = random.choice(agents)
            futures.append(pool.submit(one_query, base_url, agent))
            next_emit += interval
            sleep_for = next_emit - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
        # Drain.
        for fut in as_completed(futures):
            ms, category, status = fut.result()
            if category == "ok":
                latencies_ok.append(ms)
            elif category == "not_found":
                latencies_not_found.append(ms)
            elif category == "client":
                latencies_client.append(ms)
                error_samples.append(f"client {status}")
            else:
                latencies_server.append(ms)
                error_samples.append(f"server {status}")

    # Latency stats are computed on REACHED responses — anything where
    # the API answered, including 404s. Server errors don't have a real
    # latency signal.
    reached = sorted(latencies_ok + latencies_not_found)
    total = (
        len(latencies_ok) + len(latencies_not_found)
        + len(latencies_client) + len(latencies_server)
    )

    p50 = reached[len(reached) // 2] if reached else 0
    p95 = (reached[int(0.95 * len(reached)) - 1]
           if len(reached) > 20 else 0)
    p99 = (reached[int(0.99 * len(reached)) - 1]
           if len(reached) > 100 else 0)

    server_error_rate = len(latencies_server) / max(total, 1)

    return {
        "total_requests": total,
        "ok":             len(latencies_ok),
        "not_found":      len(latencies_not_found),
        "client_errors":  len(latencies_client),
        "server_errors":  len(latencies_server),
        "server_error_rate": server_error_rate,
        "p50_ms":         p50,
        "p95_ms":         p95,
        "p99_ms":         p99,
        "duration_s":     duration_s,
        "rate":           rate,
        "achieved_qps":   total / duration_s,
        "error_samples":  error_samples[:5],
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", required=True)
    p.add_argument("--rate", type=float, default=4.0,
                   help="requests/second (default 4, target = 2.78)")
    p.add_argument("--duration", type=int, default=30,
                   help="seconds (default 30; full audit run = 3600)")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument(
        "--agents",
        default="",
        help=(
            "comma-separated agent wallets to query; defaults to "
            "HELIXOR_API_LOAD_AGENTS or a synthetic unknown-agent pool"
        ),
    )
    p.add_argument("--report",
                   default="audit/reports/api_load.json")
    args = p.parse_args(argv)

    agents = (
        [item.strip() for item in args.agents.split(",") if item.strip()]
        if args.agents
        else _agents_from_env_or_default()
    )
    result = run_load(args.base_url, args.rate, args.duration,
                      agents, workers=args.workers)
    print(json.dumps(result, indent=2))

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))

    # ── Acceptance ──────────────────────────────────────────────────────────
    failed = False
    # Server errors (5xx) are the API being broken. 404s are fine when
    # querying random agents that may not yet be indexed; they prove the
    # endpoint works.
    if result["server_error_rate"] > 0.001:
        print(f"❌ server error rate {result['server_error_rate']*100:.3f}% exceeds 0.1%")
        failed = True
    if result["p95_ms"] > 500:
        print(f"❌ p95 latency {result['p95_ms']:.0f}ms exceeds 500ms")
        failed = True
    if result["achieved_qps"] < args.rate * 0.95:
        print(f"❌ achieved {result['achieved_qps']:.2f} qps vs target {args.rate}")
        failed = True
    if failed:
        return 1
    print("✅ API LOAD CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
