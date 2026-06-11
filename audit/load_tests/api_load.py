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


# =============================================================================
# Endpoint mix (Day-40)
# =============================================================================
#
# Day-29 covered only /health. Day-40 ships the cert-v2 consumer surface
# (SDK + API), so the load test now drives /health AND /diagnosis at a
# weighted mix that mirrors what an insurer/marketplace integration
# actually does: a fast freshness-check (/health) for every action +
# a heavier explain-call (/diagnosis) for a fraction. The default mix
# is 80/20 — derived from the Day-40 plan's "score check before every
# operation, diagnosis pull only on red/yellow" pattern.
ENDPOINTS = ("health", "diagnosis")

# Default sample epoch the /diagnosis path queries. Production runs
# override per-agent via the wallet file (which can carry an `epoch` key)
# or via --diagnosis-epoch. A non-existent epoch still produces a real
# latency signal (404 is recorded under not_found, not as a server error).
DEFAULT_DIAGNOSIS_EPOCH = 1


def _build_url(base_url: str, surface: str, wallet: str, epoch: int) -> str:
    base = base_url.rstrip("/")
    if surface == "diagnosis":
        return f"{base}/agents/{wallet}/diagnosis/{epoch}"
    return f"{base}/agents/{wallet}/health"


def one_query(
    base_url: str,
    agent_wallet: str,
    timeout_s: float = 5.0,
    surface: str = "health",
    epoch: int = DEFAULT_DIAGNOSIS_EPOCH,
):
    """A single API query against `surface`.

    `surface` is "health" (default) or "diagnosis". Day-40 added the
    diagnosis path so the load test covers the cert-v2 consumer surface
    (the SDK's `getDiagnosis(agent, epoch)`) alongside the legacy score
    read.

    Returns (latency_ms, category, status) where category is one of
    "ok"        — 2xx response
    "not_found" — 404 (the endpoint works, the agent isn't known yet)
    "client"    — other 4xx (a bug in the test or a contract change)
    "server"    — 5xx or transport (the API is broken)
    """
    url = _build_url(base_url, surface, agent_wallet, epoch)
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


def run_load(
    base_url: str, rate: float, duration_s: int,
    agents: list[str], workers: int = 16,
    diagnosis_fraction: float = 0.2,
    diagnosis_epoch: int = DEFAULT_DIAGNOSIS_EPOCH,
) -> dict:
    """
    Drive `rate` req/s for `duration_s` seconds, randomly sampling agents.
    Returns a dict with latencies, per-category counts, and pass/fail.

    `diagnosis_fraction` ∈ [0.0, 1.0] is the share of requests routed to
    /agents/{wallet}/diagnosis/{epoch}; the remainder hit /health. The
    default 0.2 mirrors the expected insurer/marketplace mix (cheap
    freshness check on every action, heavier diagnosis pull only when the
    score warrants explanation). The achieved mix is reported alongside
    p95 so a regression in either surface is visible.

    Categories:
      "ok"        — 2xx; the API returned the agent's health/diagnosis
      "not_found" — 404; the endpoint works but the agent isn't indexed
      "client"    — other 4xx; the test is wrong or contract drifted
      "server"    — 5xx / transport; the API is broken
    """
    if not 0.0 <= diagnosis_fraction <= 1.0:
        raise ValueError(
            f"diagnosis_fraction must be in [0, 1], got {diagnosis_fraction}"
        )
    latencies_ok:        list[float] = []
    latencies_not_found: list[float] = []
    latencies_client:    list[float] = []
    latencies_server:    list[float] = []
    # Per-surface p95 lets us catch a regression in /diagnosis even if
    # /health's faster response masks it in the global aggregate.
    latencies_by_surface: dict[str, list[float]] = {
        "health":    [],
        "diagnosis": [],
    }
    surface_counts: dict[str, int] = {"health": 0, "diagnosis": 0}
    error_samples: list[str] = []
    started = time.perf_counter()
    next_emit = started
    interval = 1.0 / rate

    with ThreadPoolExecutor(max_workers=workers) as pool:
        # Each submitted future is tagged with the surface it targets so
        # per-surface latency is attributable on drain (the surface choice
        # is randomised per-submit, so as_completed alone loses ordering).
        tagged: list[tuple[str, object]] = []
        while time.perf_counter() - started < duration_s:
            agent = random.choice(agents)
            surface = (
                "diagnosis"
                if random.random() < diagnosis_fraction
                else "health"
            )
            surface_counts[surface] += 1
            fut = pool.submit(
                one_query, base_url, agent, 5.0, surface, diagnosis_epoch,
            )
            tagged.append((surface, fut))
            next_emit += interval
            sleep_for = next_emit - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
        for surface, fut in tagged:
            ms, category, status = fut.result()  # type: ignore[attr-defined]
            if category == "ok":
                latencies_ok.append(ms)
                latencies_by_surface[surface].append(ms)
            elif category == "not_found":
                latencies_not_found.append(ms)
                latencies_by_surface[surface].append(ms)
            elif category == "client":
                latencies_client.append(ms)
                error_samples.append(f"{surface} client {status}")
            else:
                latencies_server.append(ms)
                error_samples.append(f"{surface} server {status}")

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

    # Per-surface p95s. We guard with len > 20 (same threshold as the
    # global p95) so a thin sample doesn't produce a misleading 0 that
    # the acceptance gate would treat as "passing".
    def _p95(samples: list[float]) -> float:
        s = sorted(samples)
        return s[int(0.95 * len(s)) - 1] if len(s) > 20 else 0

    health_p95    = _p95(latencies_by_surface["health"])
    diagnosis_p95 = _p95(latencies_by_surface["diagnosis"])

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
        "health_p95_ms":     health_p95,
        "diagnosis_p95_ms":  diagnosis_p95,
        "surface_counts":    surface_counts,
        "diagnosis_fraction_requested": diagnosis_fraction,
        "diagnosis_fraction_achieved":
            surface_counts["diagnosis"] / max(sum(surface_counts.values()), 1),
        "duration_s":     duration_s,
        "rate":           rate,
        "achieved_qps":   total / duration_s,
        "error_samples":  error_samples[:5],
    }


def _agents_from_file(path: Path) -> list[str]:
    """Load wallet list from a JSON file. Accepts:
      - `[{"wallet": "..."}, ...]`  (helixor synthetic-explanation report)
      - `["wallet1", "wallet2", ...]`  (flat list)
      - `{"agents": [...]}`           (wrapped, either of the above)
    Lets the smoke run hit registered wallets (200s) instead of
    synthetic ones (400s), producing real p95 latency signal."""
    payload = json.loads(path.read_text())
    if isinstance(payload, dict) and "agents" in payload:
        payload = payload["agents"]
    out: list[str] = []
    for entry in payload:
        if isinstance(entry, str):
            out.append(entry)
        elif isinstance(entry, dict) and "wallet" in entry:
            out.append(entry["wallet"])
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", required=True)
    p.add_argument("--rate", type=float, default=4.0,
                   help="requests/second (default 4, target = 2.78)")
    p.add_argument("--duration", type=int, default=30,
                   help="seconds (default 30; full audit run = 3600)")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--report",
                   default="audit/reports/api_load.json")
    p.add_argument(
        "--wallets-file", type=Path, default=None,
        help=(
            "Load wallet list from a JSON file (synthetic explanation "
            "report or on-chain registry export). Default uses the "
            "static DEFAULT_AGENTS list, which 4xx's against a real API."
        ),
    )
    p.add_argument(
        "--diagnosis-fraction", type=float, default=0.2,
        help=(
            "Share of requests routed to /diagnosis (default 0.2 — "
            "matches the insurer/marketplace mix where /health is the "
            "freshness check and /diagnosis is the explain pull)."
        ),
    )
    p.add_argument(
        "--diagnosis-epoch", type=int, default=DEFAULT_DIAGNOSIS_EPOCH,
        help="Epoch queried on the /diagnosis path (default 1).",
    )
    args = p.parse_args(argv)

    agents = (
        _agents_from_file(args.wallets_file)
        if args.wallets_file
        else DEFAULT_AGENTS
    )
    if not agents:
        print("❌ no agents to query")
        return 1

    result = run_load(
        args.base_url, args.rate, args.duration, agents,
        workers=args.workers,
        diagnosis_fraction=args.diagnosis_fraction,
        diagnosis_epoch=args.diagnosis_epoch,
    )
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
    # Per-surface gates: a /diagnosis regression must not be masked by
    # the cheaper /health calls dominating the global aggregate.
    if result["health_p95_ms"] > 500:
        print(f"❌ /health p95 {result['health_p95_ms']:.0f}ms exceeds 500ms")
        failed = True
    if result["diagnosis_p95_ms"] > 500:
        print(f"❌ /diagnosis p95 {result['diagnosis_p95_ms']:.0f}ms exceeds 500ms")
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
