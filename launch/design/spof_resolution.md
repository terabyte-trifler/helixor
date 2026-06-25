# SPOF Resolution — the nine single points of failure

**Status:** IMPLEMENTED.
**Audit findings:** the 9-entry SPOF inventory from the launch-readiness review.
**Owners:** protocol engineering (#1–#4), platform engineering (#5–#9).
**Related code / config:**
- `programs/slash-authority/src/state/pending_authority_rotation.rs` (#2)
- `programs/slash-authority/src/instructions/{propose,attest,enact,cancel}_authority_rotation.rs` (#2)
- `programs/slash-authority/src/instructions/update_authorities.rs` (#2 — refusal handler)
- `launch/deploy/deploy_programs.sh` (#3 — Squads upgrade authority)
- `phylanx-indexer/indexer/production_config.py` (#8)
- `phylanx-indexer/indexer/consensus.py` (#8 — already present)
- `launch/deploy/docker-compose.kafka-ha.yml` (#5)
- `launch/deploy/docker-compose.timescale-ha.yml` (#6)
- `launch/deploy/docker-compose.api-ha.yml` (#7+#9)
- `launch/deploy/nginx/api_upstream.conf` (#7+#9)
- `audit/spof_check.py` + `audit/test_spof_check.py` (mechanical regression gate)
- `launch/runbooks/spof_failover.md`

---

## Why a unified SPOF closure

The launch-readiness review enumerated nine distinct single points of
failure. They span four substrates — Solana programs, the indexer, the
event bus, the data store — and three risk shapes — single-key
authority, single-instance services, single-network-path dependencies.
The right mitigation is different for each, but the discipline is the
same: NO production component may be a one-of-one whose failure halts
or compromises the protocol.

This doc is the single source of truth for which mitigation closes
which SPOF and where the regression gate lives. The audit gate at
`audit/spof_check.py` is the mechanical proof; this doc is the
narrative for an external reviewer.

---

## The SPOF inventory

| # | SPOF                       | Risk shape                  | Mitigation                                                                              | Gate           |
|---|----------------------------|-----------------------------|-----------------------------------------------------------------------------------------|----------------|
| 1 | `advance_authority`        | single-key authority        | AW-02 threshold-attested advance (M-of-N cluster sigs in the same tx).                  | AW-02 tests    |
| 2 | `slash_authority`          | single-key authority        | Time-locked 2-of-3-attested rotation ceremony; single-admin handler refuses.            | SPOF gate #2   |
| 3 | upgrade authority          | single-key authority        | Squads multisig owns the program upgrade authority post-`deploy_programs.sh`.           | SPOF gate #3   |
| 4 | oracle key per node        | single-key authority        | 3-of-5 cluster threshold signatures (already shipped).                                  | cluster tests  |
| 5 | Kafka                      | single-instance service     | 3-broker KRaft cluster, RF=3, min.insync.replicas=2, unclean leader election OFF.       | SPOF gate #5   |
| 6 | TimescaleDB                | single-instance service     | Primary + hot standby + `pg_receivewal` WAL archive for PITR.                            | SPOF gate #6   |
| 7 | API server                 | single-instance service     | Three identical replicas (`api-1`, `api-2`, `api-3`).                                   | SPOF gate #7+9 |
| 8 | Geyser endpoint            | single-network-path         | Mainnet floor of 3 endpoints, 2-of-3 `ConsensusStream` quorum. `SinglePointGeyserError` refuses single-endpoint mainnet at boot. | SPOF gate #8   |
| 9 | API redundancy / LB        | single-network-path         | nginx least-conn LB with `proxy_next_upstream` and >= 3 upstreams.                       | SPOF gate #7+9 |

---

## How each fix works

### SPOF-#2 — slash-authority rotation ceremony

Single-admin rotation of the executor/resolver/pauser keys collapsed
the VULN-04 separated-authority guarantee back to a single-key risk.
The fix mirrors the VULN-13 oracle-key ceremony:

1. `propose_authority_rotation` opens the singleton
   `PendingAuthorityRotation` PDA. Admin OR any current role key may
   propose; role-key proposers auto-attest, admin does not. Minimum
   timelock is 48h.
2. `attest_authority_rotation` adds a current role-key attestation.
   Admin attestations are refused (separation by design).
3. `enact_authority_rotation` applies the rotation once
   `now >= enact_after` AND `attestations >= 2` (strict majority of
   the three role keys). Anyone may enact.
4. `cancel_authority_rotation` lets admin OR any current role key veto
   the open proposal during the window — a single honest role key
   stops a hostile rotation.

`update_authorities` (the pre-mitigation single-admin instruction) is
retained for IDL compatibility but ALWAYS returns
`SingleAdminUpdateRemoved`. The constants
(`MIN_TIMELOCK_SECONDS = 48 * 60 * 60`, `CONSENSUS_THRESHOLD = 2`,
`ROLE_KEY_COUNT = 3`) are pinned by `spof02_authority_rotation.rs`.

### SPOF-#8 — Geyser multi-endpoint mainnet floor

`indexer/consensus.py` had a K-of-N gate but no production wiring.
`indexer/production_config.py` is the only sanctioned construction
site for a mainnet indexer; it:

- Parses `PHYLANX_GEYSER_ENDPOINTS` (`name=url[|TOKEN_ENV],...`).
- When `PHYLANX_SOLANA_CLUSTER` is mainnet, requires
  `len(endpoints) >= 3`. Single-endpoint mainnet raises
  `SinglePointGeyserError` at startup — the indexer does not boot.
- Defaults `consensus_threshold` to strict majority of N
  (`floor(N/2)+1`), floor 2.

The enforcement is LOAD-TIME, not runtime — a misconfigured indexer
fails before opening any subscription.

### SPOF-#5 — Kafka 3-broker HA

`docker-compose.kafka-ha.yml` replaces the single-broker dev compose's
broker with three brokers in a KRaft quorum. The HA flags:

- `KAFKA_DEFAULT_REPLICATION_FACTOR=3` — three replicas of every
  partition.
- `KAFKA_MIN_INSYNC_REPLICAS=2` — producers with `acks=all` only see a
  successful write when two replicas have it. One broker can fail
  without losing acknowledged writes; two-broker loss halts writes
  (a deliberate CAP-consistent choice — we do not lose acknowledged
  events to recover write availability).
- `KAFKA_UNCLEAN_LEADER_ELECTION_ENABLE=false` — an out-of-sync
  replica must never become leader.

A `kafka-init` one-shot creates the `agent.transactions` topic with
the HA settings explicit on the topic config so a broker default
drift cannot silently downgrade durability.

### SPOF-#6 — TimescaleDB primary + standby + WAL archive

`docker-compose.timescale-ha.yml` declares:

- `timescale-primary` — accepts writes; `wal_level=replica`,
  `archive_mode=on`, `archive_command` ships closed segments to the
  shared `wal_archive` volume.
- `timescale-standby` — `pg_basebackup`'d from the primary on first
  boot, then runs in hot-standby mode. Serves read-only queries via
  `READ_DATABASE_URL`. RPO is bounded by the streaming-replication
  lag (seconds in practice); RTO is bounded by the failover-runbook
  steps (≤ 60s).
- `wal-archive` — runs `pg_receivewal` against a replication slot so
  the WAL is shipped off-primary as soon as it is generated. This is
  the PITR substrate: a `DELETE` typo can be undone by replaying up
  to the LSN before the bad command.

### SPOF-#7+#9 — API multi-replica behind nginx LB

`docker-compose.api-ha.yml` declares `api-1`/`api-2`/`api-3` (three
identical replicas) and `api-lb` (nginx). The LB config at
`launch/deploy/nginx/api_upstream.conf`:

- `least_conn` balances new requests across replicas — better than
  round-robin under the mixed-latency workload the dashboard creates.
- `proxy_next_upstream error timeout http_502 http_503 http_504` —
  idempotent GETs that hit a failing replica retry against the next
  one. POST/PUT/DELETE are not retried (at-most-once on writes).
- `max_fails=3 fail_timeout=15s` per upstream — three failures within
  15s remove the replica for 15s. Less flappy than the default.
- `/lb-health` — the LB's own probe, distinct from the replicas'
  `/health`. The runbook uses it to distinguish "the LB is up" from
  "a replica is up".

---

## Regression gate

`audit/spof_check.py` runs in CI as part of `audit/run_all.sh` section
1k. It scans the listed files for the marker strings and exits
non-zero on any HARD finding. `audit/test_spof_check.py` exercises the
gate against the live tree and asserts:

1. Every SPOF family is covered (the report's `checked` list contains
   #2, #3, #5, #6, #7+#9, #8 — SPOF-#1 and SPOF-#4 are covered by the
   AW-02 / cluster-threshold gates respectively).
2. The repo is currently GREEN (no hard findings).

A regression that removes any mitigation lights this gate red before
the change reaches mainnet.

---

## Out of scope (for this doc)

SPOF-#1 and SPOF-#4 are mentioned in the table but their resolutions
are NOT re-described here — they are covered, with full design notes,
by `aw02_distributed_epoch_advancement.md` and the cluster
threshold-signing design respectively. The SPOF gate references them
by audit-family marker; it does not re-implement the checks.
