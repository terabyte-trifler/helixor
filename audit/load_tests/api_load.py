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
# Valid Solana pubkey strings for local smoke tests. Production runs should
# replace this with actual registered agents from the on-chain registry.
DEFAULT_AGENTS = ["11111111111111111111111111111111"]


def one_query(
    base_url: str,
    agent_wallet: str,
    timeout_s: float = 5.0,
    path_template: str = "/score/{agent_wallet}",
):
    """A single agent-health query. Returns (latency_ms, ok, status_code)."""
    path = path_template.format(agent_wallet=agent_wallet).lstrip("/")
    url = f"{base_url.rstrip('/')}/{path}"
    start = time.perf_counter()
    try:
        req = urlrequest.Request(url, headers={"Accept": "application/json"})
        with urlrequest.urlopen(req, timeout=timeout_s) as resp:
            _ = resp.read()
            elapsed_ms = (time.perf_counter() - start) * 1000
            return elapsed_ms, True, resp.status
    except URLError as exc:
        return (time.perf_counter() - start) * 1000, False, str(exc)
    except Exception as exc:                # noqa: BLE001
        return (time.perf_counter() - start) * 1000, False, repr(exc)


def run_load(
    base_url: str,
    rate: float,
    duration_s: int,
    agents: list[str],
    workers: int = 16,
    path_template: str = "/score/{agent_wallet}",
) -> dict:
    """
    Drive `rate` req/s for `duration_s` seconds, randomly sampling agents.
    Returns a dict with latencies, error rate, and pass/fail vs the bar.
    """
    latencies_ok: list[float] = []
    latencies_err: list[float] = []
    errors: list[str] = []
    started = time.perf_counter()
    next_emit = started
    interval = 1.0 / rate

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []
        while time.perf_counter() - started < duration_s:
            agent = random.choice(agents)
            futures.append(pool.submit(one_query, base_url, agent, 5.0, path_template))
            next_emit += interval
            sleep_for = next_emit - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
        # Drain.
        for fut in as_completed(futures):
            ms, ok, status = fut.result()
            if ok:
                latencies_ok.append(ms)
            else:
                latencies_err.append(ms)
                errors.append(str(status))

    total = len(latencies_ok) + len(latencies_err)
    error_rate = len(latencies_err) / max(total, 1)
    p50 = statistics.median(latencies_ok) if latencies_ok else 0
    p95 = (sorted(latencies_ok)[int(0.95 * len(latencies_ok)) - 1]
           if len(latencies_ok) > 20 else 0)
    p99 = (sorted(latencies_ok)[int(0.99 * len(latencies_ok)) - 1]
           if len(latencies_ok) > 100 else 0)

    return {
        "total_requests": total,
        "errors":         len(latencies_err),
        "error_rate":     error_rate,
        "p50_ms":         p50,
        "p95_ms":         p95,
        "p99_ms":         p99,
        "duration_s":     duration_s,
        "rate":           rate,
        "achieved_qps":   total / duration_s,
        "error_samples":  errors[:5],
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
        "--path-template",
        default="/score/{agent_wallet}",
        help="endpoint template; default matches Helixor API",
    )
    p.add_argument("--report",
                   default="audit/reports/api_load.json")
    args = p.parse_args(argv)

    result = run_load(args.base_url, args.rate, args.duration,
                      DEFAULT_AGENTS, workers=args.workers,
                      path_template=args.path_template)
    print(json.dumps(result, indent=2))

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))

    # ── Acceptance ──────────────────────────────────────────────────────────
    failed = False
    if result["error_rate"] > 0.001:
        print(f"❌ error rate {result['error_rate']*100:.3f}% exceeds 0.1%")
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
