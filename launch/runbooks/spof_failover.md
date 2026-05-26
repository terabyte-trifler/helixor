# Runbook — SPOF failover

**Severity:** Page (any production replica down) → Critical (quorum
loss in Kafka or DB primary down).
**Triggers:**
- `KafkaBrokerDown` (one broker offline)
- `KafkaUnderReplicatedPartitions` (any topic ISR < min.insync.replicas)
- `TimescalePrimaryDown` (primary unreachable for > 30s)
- `TimescaleStandbyLag` (replication lag > 60s)
- `APIReplicaDown` (one of api-1/-2/-3 failing `/health`)
- `GeyserConsensusConflictRate` (`ConflictReport`s > 0 over 5 min)
- `GeyserConsensusDroppedNoQuorum` (drops > 0.1% of consumed signatures)

## What's happening

A production substrate component has failed or is degraded. The
mitigations in `launch/design/spof_resolution.md` are designed for
exactly this — the protocol survives one-component loss in every
substrate. This runbook is the playbook for **observing** that the
mitigation engaged AND for **executing** the manual steps (DB
promotion) the automatic mitigation does not cover.

---

## Kafka broker down (SPOF-#5)

### Triage (60s)

```bash
# 1. Which broker is down?
docker compose -f launch/deploy/docker-compose.indexer.yml \
               -f launch/deploy/docker-compose.kafka-ha.yml ps kafka-1 kafka-2 kafka-3

# 2. Are partitions under-replicated?
docker compose exec kafka-1 \
  kafka-topics --bootstrap-server kafka-1:9092 \
               --command-config /etc/kafka/secrets/client.properties \
               --describe --under-replicated-partitions

# 3. Indexer producer health — is it still publishing?
curl -s http://localhost:9090/metrics | grep kafka_producer
```

### Decision tree

- **One broker down, partitions still in-sync (ISR=2):** the cluster
  is operating at the audit-mandated floor. The dead broker will rejoin
  on `docker compose start kafka-N`. NO operator action required for
  protocol safety; production stays writable. Investigate root cause
  (disk full, OOM, segfault) before declaring the incident closed.

- **One broker down, partitions UNDER-replicated (ISR=1):** the dead
  broker held a replica that has not been re-replicated. `min.insync=2`
  means producers with `acks=all` will start blocking once they need
  to write to a partition where only one replica is in sync. Restart
  the broker FAST. If the broker's disk is unrecoverable, follow the
  "lost a broker permanently" section below.

- **Two brokers down:** writes are halted (min.insync=2 cannot be
  satisfied with one live broker). This is by design — the
  alternative is losing acknowledged writes. Restore at least one
  failed broker before writes resume. The indexer's outbox keeps
  pending writes until the cluster recovers; no data is lost.

### Lost a broker permanently

If a broker's storage is gone, the easiest path is to bring up a
replacement with the SAME `KAFKA_NODE_ID` and an empty data volume.
The KRaft quorum will re-replicate the partitions onto the new broker.
This takes minutes-to-hours depending on partition size.

---

## TimescaleDB primary down (SPOF-#6)

### Triage (60s)

```bash
# 1. Confirm primary is down (not just unreachable from one host).
docker compose -f launch/deploy/docker-compose.indexer.yml \
               -f launch/deploy/docker-compose.timescale-ha.yml \
               exec timescale-standby \
  psql -U helixor_replicator -h timescale-primary -d helixor -c "SELECT 1"

# 2. Confirm standby is in hot-standby mode.
docker compose exec timescale-standby \
  psql -U helixor_replicator -d helixor -c "SELECT pg_is_in_recovery();"
# Expect: t

# 3. Replication lag.
docker compose exec timescale-standby \
  psql -U helixor_replicator -d helixor -c "
    SELECT now() - pg_last_xact_replay_timestamp() AS lag;"
```

### Promote the standby (RTO target ≤ 60s)

```bash
# 1. Promote the standby. After this it accepts writes.
docker compose exec timescale-standby \
  psql -U helixor_replicator -d helixor -c "SELECT pg_promote();"

# 2. Repoint indexer + API at the new primary. Two options:
#    a) Quick — edit the .env file's DATABASE_URL/READ_DATABASE_URL
#       to point both at the (now-primary) timescale-standby host,
#       then `docker compose up -d indexer api-1 api-2 api-3`.
#    b) Proper — replace the dead primary with a fresh container
#       seeded by `pg_basebackup` from the new primary; the
#       compose service name keeps the indexer connection string
#       stable.
```

### After promotion

- The old primary's volume MUST be wiped before it rejoins (its WAL
  diverged from the new primary's the moment the promotion ran).
  `docker volume rm tsdb_primary_data` and let `pg_basebackup` re-seed.
- The WAL archive (`wal_archive` volume) continued ticking during the
  outage — PITR back to before the failure is still possible if the
  promotion turned out to be premature.

---

## API replica down (SPOF-#7)

### Triage (15s)

```bash
# 1. Which replica is failing /health?
for r in api-1 api-2 api-3; do
  docker compose exec $r wget -qO- http://localhost:8080/health && \
    echo "$r ok" || echo "$r FAIL"
done

# 2. Confirm nginx removed it from the pool.
curl -s http://localhost:8080/lb-health    # the LB itself
curl -s http://localhost:8080/health       # routed through LB
```

### Decision tree

- **One replica failing health, LB still serves 200:** nginx
  `max_fails=3` removed it. Production is unaffected; the dashboard
  is unaware. Investigate the failing replica's logs:
  `docker compose logs --since 10m api-2`. Common causes: stuck on a
  slow DB query, OOM, runtime exception.

- **Two replicas failing:** the LB is down to one. Investigate
  immediately — a third failure 502s the dashboard. Look for a shared
  cause (the standby has lagged, a slow query on a hot table, a bad
  release).

- **All three replicas failing:** the LB's `/lb-health` still returns
  200 but every dashboard request 502s. This is almost always a
  shared upstream problem (DB primary down → see Timescale section;
  Kafka unreachable → see Kafka section; bad release rolled to all
  three → roll back).

---

## Geyser consensus alerts (SPOF-#8)

### Triage (60s)

```bash
# 1. Conflict reports — two endpoints disagreed on canonical bytes.
curl -s http://localhost:9090/metrics | grep geyser_consensus_conflicts
# A NON-zero rate is the smoking gun for an endpoint compromise OR a
# fork-of-one between two providers.

# 2. Dropped-no-quorum rate — proposals that aged out before reaching K.
curl -s http://localhost:9090/metrics | grep geyser_consensus_dropped
# A sustained rate means endpoints are systematically out of sync.
```

### Decision tree

- **Spike in `conflicts`:** investigate which endpoint dissented.
  `ConflictReport.dissenting_source` names it (the indexer's
  structured-log line carries the source label). If it persists,
  REMOVE the dissenter from `HELIXOR_GEYSER_ENDPOINTS` and restart
  the indexer with N-1 endpoints. The mainnet floor of N=3 still
  holds; below 3, the indexer refuses to start.

- **`dropped_no_quorum` > 0.1% sustained:** something is making
  one of the three endpoints chronically slow. Check provider
  status pages; rotate to a backup endpoint if one is misbehaving.

- **`SinglePointGeyserError` at indexer boot:** the operator
  configured fewer than 3 endpoints for mainnet. This is the gate
  doing its job — set `HELIXOR_GEYSER_ENDPOINTS` to at least three
  independent providers. Do NOT add a workaround to bypass the
  refusal.

---

## When to escalate

- Two or more SPOF substrates are simultaneously degraded (e.g. Kafka
  + DB) — page the on-call protocol engineer; this is correlated
  failure, not independent component loss.
- The SPOF audit gate (`audit/spof_check.py`) goes red in CI mid-
  incident — a refactor undid a mitigation. Block the offending merge
  before any further deploys.
- `SinglePointGeyserError` fires on a healthy 3-endpoint config —
  the gate has a bug, file an issue. Do NOT relax `MAINNET_MIN_ENDPOINTS`
  to unblock.
