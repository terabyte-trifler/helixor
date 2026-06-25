# Runbook — Epoch Advance Stalled / Fallback Fired (AW-02)

**Owner:** on-call cluster engineer
**Severity:** P0 on fallback fired or no advance within 1.5× duration
            P1 on quorum trending down (attester_count → threshold)
**SLO:** epoch advances every 24h ± 1h in steady state

---

## What this runbook covers

The Tier-1 normal-path advance (AW-02 fix) requires `M-of-N` cluster
Ed25519 attestations over the canonical advance digest. If the cluster
cannot assemble quorum, the protocol enters one of three states:

1. **Quorum trending down** — `EpochAdvancedByThreshold.attester_count`
   slipping toward the threshold (e.g. 5/5 → 4/5 → 3/5) but still
   passing. Early-warning P1: a node is silently dropping out of the
   daily ceremony.
2. **Quorum lost, fallback fires** — no `EpochAdvancedByThreshold`,
   one `EpochAdvancedByFallback` event after the 2× duration window
   opened. P0: the cluster operationally degraded for ≥ 1 epoch.
3. **Quorum lost AND fallback unavailable** — no advance at all,
   `EpochState.current_epoch` not ticking. P0: no fresh certs being
   issued for any agent. This is the catastrophic failure mode
   AW-02's Tier 2 was designed to prevent — investigate immediately.

---

## Symptom triage

### Symptom A — daily review surfaces declining `attester_count`

Quorum is still being made, but the margin is shrinking.

```sql
-- in the indexer, against the EpochAdvancedByThreshold event stream
SELECT advanced_at::date AS day, MIN(attester_count) AS min_attesters
  FROM epoch_advanced_by_threshold
 WHERE advanced_at > now() - interval '14 days'
 GROUP BY 1
 ORDER BY 1;
```

If the min trend is moving toward `consensus_threshold(cluster)`:

1. Identify the missing node(s). Cross-reference the precompile
   signers in the advance tx with `OracleConfig.oracle_keys`. A node
   that did NOT contribute on this tick is in the gap.
2. SSH to the missing-signer host. Check `journalctl -u phylanx-oracle`
   for the daily advance-ceremony participation log line. Common
   causes: clock drift, KMS/HSM auth expiry, signer daemon crashed,
   network partition between the signer and the tx submitter.
3. Restore participation before the trend hits `threshold - 1` — at
   that point a single additional dropout breaks quorum.

### Symptom B — `EpochAdvancedByFallback` event seen on chain

The cluster failed to assemble M-of-N AND the Tier-2 liveness window
opened. The protocol advanced, but operationally degraded.

1. **Page immediately.** This is a P0 — every additional advance
   without restored quorum is another data point that the cluster's
   normal ceremony is broken.
2. Read the `EpochAdvancedByFallback.cluster_key` field — that is
   the cluster member who pushed the fallback tick through. They
   were available; the OTHERS were not.
3. Identify every cluster key that should have attested. For each
   one that didn't, run the Symptom-A diagnostic above.
4. Investigate the ROOT cause across multiple nodes simultaneously
   — if 2 of 3 nodes were silent, look for a common dependency
   (shared KMS region down, indexer outage breaking the digest
   computation pipeline, time-sync issue blocking `may_advance`).
5. Once at least `consensus_threshold(cluster)` nodes are healthy,
   verify quorum at the NEXT epoch boundary by inspecting the
   chain explorer — expect `EpochAdvancedByThreshold` with full
   attester count, no further fallback events.

### Symptom C — no advance event at all, `current_epoch` stuck

The cluster is below quorum AND no single node is healthy enough
to trigger the Tier-2 fallback. This is the worst case AW-02 is
designed to make rare.

1. **Page everyone.** Cluster is down for cert issuance.
2. Establish what the on-chain `EpochState` reads:
   ```sh
   solana account <epoch_state_pda> --output json
   ```
   Read `current_epoch` and `last_advanced_at`. If `now -
   last_advanced_at >= 2 * epoch_duration_seconds`, the Tier-2
   window IS open — investigate why no cluster member is pushing
   through (any single member can advance solo at this point).
3. If even one cluster member can SSH in, run the manual fallback:
   on that host, run `phylanx-ops advance-epoch --fallback` (the
   ops tool wraps a direct call to `health_oracle.advance_epoch`
   with the single cluster signer). The fallback path only needs
   ONE cluster signer's tx — no Ed25519 precompile attestations
   required, just the signer's keypair as the tx fee payer with
   their pubkey in `OracleConfig.oracle_keys`.
4. If no cluster member can be brought online inside 4 hours, escalate
   to admin (`oracle_config.authority` — Squads multisig) and consider
   `rotate_advance_authority` to a fresh recovery key. Note this only
   updates the legacy HINT field; it does NOT bypass the M-of-N gate.
   The actual recovery path is to bring a cluster key online, NOT to
   rotate the hint.

---

## Diagnostic queries

```sql
-- Last 7 days of advance events — quick visual check
SELECT
  e.advanced_at,
  e.from_epoch || '→' || e.to_epoch    AS tick,
  CASE
    WHEN t.attester_count IS NOT NULL
      THEN 'threshold:' || t.attester_count
    WHEN f.cluster_key IS NOT NULL
      THEN 'FALLBACK:'  || f.cluster_key
    ELSE 'unknown'
  END                                  AS path
FROM epoch_advanced e
LEFT JOIN epoch_advanced_by_threshold t USING (to_epoch)
LEFT JOIN epoch_advanced_by_fallback  f USING (to_epoch)
WHERE e.advanced_at > now() - interval '7 days'
ORDER BY e.advanced_at;
```

```sh
# Live: who signed the most recent advance tx?
solana transaction <signature> --output json \
  | jq '.transaction.message.instructions[]
        | select(.programIdIndex == <ed25519_program_index>)
        | .data' \
  | base58_decode | hexdump -C
```

The pubkey bytes are at offset 16 (after the precompile header) and
length 32. Match against `OracleConfig.oracle_keys` to confirm cluster
membership.

---

## Recovery checklist

- [ ] Identified the missing cluster nodes by name
- [ ] Confirmed root cause (KMS, clock, daemon, network, ...)
- [ ] Brought ≥ `consensus_threshold(cluster)` nodes back online
- [ ] Confirmed a fresh `EpochAdvancedByThreshold` event at the next
      boundary with `attester_count >= consensus_threshold(cluster)`
- [ ] **No new `EpochAdvancedByFallback` event in the subsequent 24h
      window** — if a fallback fires again, the underlying cause was
      not fully addressed
- [ ] Postmortem filed in `incidents/` if any P0 was raised

---

## Why this matters

AW-02 closed the audit gap that epoch advancement was the ONLY
consensus-critical op in the protocol not protected by the cluster's
M-of-N threshold mechanism. The runbook above is the operational
counterpart: the on-chain code refuses to advance without quorum,
and the operator's job is to keep quorum reachable. A persistent
state where quorum is unreachable means the cluster is operationally
broken — every additional fallback tick is a degraded-state cert
generation event, and the system's threat model assumes that path
is rare and time-bounded, not the steady state.

See `launch/design/aw02_distributed_epoch_advancement.md` for the
full design rationale and threat model.
