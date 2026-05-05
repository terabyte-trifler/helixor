# Webhook Queue + Batch Workers

Goal: keep Helius webhook acknowledgements fast while moving database writes to
dedicated workers that can batch insert transactions.

## Runtime Shape

```
Helius
  -> POST /webhook
  -> parse + replay-age filter
  -> Redis list queue
  -> webhook_worker
  -> batched INSERT into Postgres
```

The receiver no longer needs to hold the Helius HTTP request open while
Postgres inserts complete. If Redis is unavailable, the receiver returns `500`
so Helius retries instead of silently dropping data.

## Settings

```bash
WEBHOOK_QUEUE_ENABLED=true
WEBHOOK_QUEUE_NAME=webhook_batches
WEBHOOK_WORKER_BATCH_SIZE=500
WEBHOOK_WORKER_POLL_TIMEOUT_SECONDS=5
```

Local tests keep queueing disabled by default so they can exercise the inline
fallback. Docker and production examples enable the queue.

## Worker

Run one or more workers:

```bash
python -m indexer.webhook_worker
```

Scaling workers increases queue drain throughput. PgBouncer protects the
managed database from connection fan-out.

## Database Write Path

`repo.insert_transactions_batch` uses one set-based `INSERT ... SELECT FROM
unnest(...) ON CONFLICT DO NOTHING` call per batch. That removes the old
one-INSERT-per-transaction bottleneck.

Skipped transactions include:
- parse failures filtered by the receiver
- replay-age rejects
- unknown/deactivated agents
- duplicate transaction signatures

## Operations

Watch:
- Redis queue length for `helixor:webhook_batches`
- worker logs for `webhook_batches_processed`
- `/metrics` for recent webhook insert/skipped/error counts
- Postgres write latency and PgBouncer pool saturation

Alerts:
- queue length rising for more than 5 minutes
- worker restarts
- Helius retry spikes
- webhook events with non-null `error`
