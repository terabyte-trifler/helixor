#!/usr/bin/env python3
"""
scripts/seed_baseline_test_data.py — populate test data for Day 5 verification.

Creates one registered_agent + N transactions across multiple days so you
can manually run compute_baseline.py and see a real baseline result.

Usage:
    python -m scripts.seed_baseline_test_data \
        --wallet TESTAGENTwalletXXXXXXXXXXXXXXXXXXXXXXXXX \
        --tx-count 100 --active-days 7 --success-rate 0.95
"""

from __future__ import annotations

import argparse
import asyncio
import random
import sys
from datetime import datetime, timedelta, timezone

import structlog

from indexer import db

log = structlog.get_logger()


async def seed(
    wallet:        str,
    tx_count:      int,
    active_days:   int,
    success_rate:  float,
    sol_volatility: float,
) -> None:
    structlog.configure(
        processors=[structlog.processors.TimeStamper(fmt="iso"),
                    structlog.dev.ConsoleRenderer()],
    )

    await db.init_pool()
    pool = await db.get_pool()
    rng  = random.Random(42)  # deterministic

    try:
        async with pool.acquire() as conn:
            now = datetime.now(tz=timezone.utc)

            # Ensure registered_agent exists
            await conn.execute(
                """
                INSERT INTO registered_agents
                    (agent_wallet, owner_wallet, name, registration_pda,
                     registered_at, onchain_signature, active)
                VALUES ($1, $2, $3, $4, $5, $6, TRUE)
                ON CONFLICT (agent_wallet) DO NOTHING
                """,
                wallet,
                "OWNER" + "x" * 39,
                "seed-test-agent",
                "REGPDA" + "y" * 38,
                now - timedelta(days=active_days + 5),
                f"SEEDSIG_{wallet[:8]}",
            )

            # Distribute tx_count across active_days
            txs_per_day = tx_count // active_days
            remainder   = tx_count - txs_per_day * active_days

            log.info("seeding_transactions",
                     wallet=wallet[:12] + "...",
                     total=tx_count, active_days=active_days,
                     per_day=txs_per_day)

            tx_idx = 0
            for day in range(active_days):
                count = txs_per_day + (1 if day < remainder else 0)
                day_base_time = now - timedelta(days=day)

                # Daily SOL flow varies per day to produce realistic volatility
                base_flow = 1_000_000  # 0.001 SOL nominal per tx
                day_multiplier = 1.0 + rng.gauss(0, sol_volatility)
                day_multiplier = max(0.1, day_multiplier)

                for _ in range(count):
                    tx_idx += 1
                    block_time = day_base_time - timedelta(
                        seconds=rng.randint(0, 3600 * 23),
                    )
                    success = rng.random() < success_rate
                    sol_change = int(base_flow * day_multiplier
                                     * rng.choice([-1, 1])
                                     * (1 + rng.random()))

                    await conn.execute(
                        """
                        INSERT INTO agent_transactions
                            (agent_wallet, tx_signature, slot, block_time, success,
                             program_ids, sol_change, fee, raw_meta, source)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, 'webhook')
                        ON CONFLICT (tx_signature) DO NOTHING
                        """,
                        wallet,
                        f"SEEDED_{wallet[:8]}_{tx_idx:06d}_{rng.randint(0, 10**9)}",
                        100_000_000 + tx_idx,
                        block_time,
                        success,
                        ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
                        sol_change,
                        5000,
                    )

            log.info("seeding_complete", wallet=wallet[:12] + "...")
            print(f"\n  ✓ Seeded {tx_count} txs for agent {wallet}\n"
                  f"  Now run:\n"
                  f"    python -m scripts.compute_baseline {wallet}\n")

    finally:
        await db.close_pool()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--wallet", required=True, help="Agent wallet pubkey to seed")
    p.add_argument("--tx-count",       type=int,   default=100)
    p.add_argument("--active-days",    type=int,   default=10)
    p.add_argument("--success-rate",   type=float, default=0.95)
    p.add_argument("--sol-volatility", type=float, default=0.3,
                   help="Stddev of daily multiplier (0.0=constant, 0.5=very volatile)")
    args = p.parse_args()

    asyncio.run(seed(
        wallet         = args.wallet,
        tx_count       = args.tx_count,
        active_days    = args.active_days,
        success_rate   = args.success_rate,
        sol_volatility = args.sol_volatility,
    ))


if __name__ == "__main__":
    main()
