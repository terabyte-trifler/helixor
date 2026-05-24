#!/usr/bin/env python3
"""Submit current DB scores through the deployed MVP update_score path.

This is a devnet bridge for the e2e harness. V2 certificate publishing uses
certificate_issuer epoch-keyed certs, but the current devnet singleton config
still needs its Day-27 realloc migration before threshold cert writes can land.
Until that migration is deployed, this script exercises the live on-chain score
write that the existing e2e reader expects.
"""

from __future__ import annotations

import argparse
import asyncio
from types import SimpleNamespace

from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey

from indexer import db
from indexer.config import settings
from oracle.network_guard import enforce_network_guard
from oracle.submit import (
    load_oracle_keypair,
    submit_score_update,
)


async def main(limit: int) -> int:
    enforce_network_guard(service="submit-legacy-scores")
    await db.init_pool()
    pool = await db.get_pool()
    oracle_kp = load_oracle_keypair()
    program_id = Pubkey.from_string(settings.health_oracle_program_id)
    submitted = 0

    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT *
                FROM agent_scores s
                JOIN registered_agents r USING (agent_wallet)
                WHERE s.written_onchain_at IS NULL
                  AND r.active = TRUE
                ORDER BY s.computed_at DESC
                LIMIT $1
                """,
                limit,
            )

            async with AsyncClient(settings.solana_rpc_url) as rpc:
                for row in rows:
                    result = SimpleNamespace(
                        score=int(row["score"]),
                        alert=str(row["alert"]),
                        baseline_stats_hash=row["baseline_stats_hash"] or row["baseline_hash"],
                        baseline_hash=row["baseline_hash"],
                        window_success_rate=float(row["window_success_rate"] or 0),
                        window_tx_count=int(row["window_tx_count"] or 0),
                        anomaly_flag=bool(row["anomaly_flag"]),
                        scoring_algo_version=int(row["scoring_algo_version"] or 1),
                        scoring_weights_version=int(row["weights_version"] or 1),
                    )
                    out = await submit_score_update(
                        rpc,
                        program_id,
                        oracle_kp,
                        row["agent_wallet"],
                        result,
                    )
                    await conn.execute(
                        """
                        UPDATE agent_scores
                        SET written_onchain_at = NOW()
                        WHERE agent_wallet = $1
                        """,
                        row["agent_wallet"],
                    )
                    submitted += 1
                    print(f"submitted {row['agent_wallet']} cert={out.cert_pda} tx={out.tx_signature}")
    finally:
        await db.close_pool()

    print(f"submitted_count={submitted}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=25)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.limit)))
