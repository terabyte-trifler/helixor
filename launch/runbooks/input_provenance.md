# Runbook — AW-01 input-provenance divergence

**Severity:** Page (sustained mismatch) → P0 (cert with mismatched commitment shipped to consumers).
**Trigger:** Prometheus `InputCommitmentDivergence` alert (FlagBit 7 on aggregated score) OR SDK consumer reports `verifyInputProvenance` → `Mismatch`.

## What's happening

The cluster's oracle nodes are supposed to compute the SAME 32-byte
`input_commitment` for each agent. AW-01 wires that commitment into the
cert-payload digest, so the on-chain Ed25519 signature attests not just
to a score but to **the inputs the cluster scored over**.

A divergence means at least one node computed a different commitment.
The cross-node agreement check in `run_byzantine_epoch` surfaces this
two ways:

* `ByzantineAgentResult.input_divergent_nodes` — the dissenting node IDs.
* `FlagBit.INPUT_DIVERGENCE` (bit 7) is OR'd into the aggregated
  `flags`, which on-chain consumers see in the cert.

If no AW-01 quorum was reached, `input_commitment is None` and the cert
pipeline refuses to issue a cert for that agent in that epoch — the
architectural fix in action: no input majority, no certificate.

## Why it happens (most → least common)

1. **One node is reading a different upstream.** The Geyser plugin
   bound a different RPC, the Kafka consumer is on a different topic,
   or the indexer was restored from a different DB snapshot. This is
   the dominant cause in practice.
2. **Time-window skew.** A node's clock or window-computation logic
   computed `current_window` 1 second wider than peers — the
   commitment covers `current_window.start/end` so even a 1µs
   difference changes the digest.
3. **Pre-AW-01 software running on one node.** The node compiled
   against an old `oracle.cluster.input_commitment` schema (version 1
   vs a hypothetical version 2) — surfaced via `INPUT_COMMITMENT_VERSION`
   bytes folded into the digest.
4. **Poisoned indexer / Kafka pipeline.** An attacker fed false
   transactions to one node. This is exactly the threat AW-01 closes;
   the divergence flag is the system catching it.

## Triage (5 min)

```bash
# 1. Which agent, which epoch, which nodes diverged?
curl -s http://api/byzantine/recent | jq '
  .results[] | select(.input_divergent_nodes | length > 0) |
  {epoch, agent: .agent_wallet, divergent: .input_divergent_nodes,
   commitment: .input_commitment}'

# 2. Pull each node's per-agent input commitment for that epoch.
#    Honest nodes on the same input MUST produce IDENTICAL bytes.
for n in oracle-node-0 oracle-node-1 oracle-node-2 oracle-node-3 oracle-node-4; do
  ssh "$n" -- "helixor-oracle commitment-for --epoch $EPOCH --agent $AGENT"
done | sort -u

# 3. Compare the upstream pipeline configuration each node reads from.
for n in oracle-node-{0..4}; do
  ssh "$n" -- 'env | grep -E "GEYSER|KAFKA|INDEXER|RPC_URL" | sort'
done
```

## Decision tree

- **A single node diverges, its upstream config differs from peers** →
  fix the config, restart the node. The cluster continues with 4; the
  divergent node will recompute correctly on the next epoch.

- **A single node diverges, configs match, but the node reads from a
  different physical RPC/indexer instance** → that instance is the
  problem. Cut the node over to a peer's known-good upstream while the
  bad upstream is investigated.

- **Multiple nodes diverge into two groups** → systemic upstream
  partition. Likely a Kafka topic split or a Geyser fleet running two
  versions. Do NOT push code. Halt advances of any cert that lacks
  AW-01 quorum (the pipeline already refuses) and page upstream owners.

- **Every node computed a different commitment** → likely a
  determinism regression in `compute_input_commitment` itself
  (someone changed canonical encoding). Rollback the most recent
  oracle deploy.

- **`input_commitment is None` for a given epoch** → no cert was
  issued. The downstream SDK consumer will see no current-epoch cert
  and SHOULD reject. If consumers are still accepting somehow,
  investigate the consumer's `SafeCertReader` configuration.

## SDK consumer impact

DeFi protocols that wired `verifyInputProvenance(cert, inputs)` are
the first line of defence. If they report `Mismatch`:

- The cert was signed against inputs the consumer cannot reproduce.
- The consumer is correctly REFUSING the score. Do NOT pressure them
  to relax the check — that defeats AW-01.
- If `ProvenanceRejection.PreV3Cert`, the cert is older than the AW-01
  upgrade. Document the rollover epoch in the integration partner's
  policy.
- If `ProvenanceRejection.PreV4Cert` or `MissingSlotAnchor`, the cert
  is older than the AW-01-EXT (slot-anchor) upgrade or was issued
  with a zero-sentinel anchor. Same handling as PreV3Cert — pin the
  cutover epoch in partner policy, don't bypass the check.

## AW-01-EXT — slot-anchor divergence (third source of truth)

A separate failure surface exists for the Solana slot anchor that
AW-01-EXT (v4 certs) added on top of AW-01. The cluster pins a
`(slot, block_hash)` at scoring time and folds it into both the
input-provenance commitment AND the cert-payload digest. The
certificate-issuer's `verify_slot_anchor` checks it against the
SlotHashes sysvar at WRITE time; the SDK's `verifyAgainstSolanaLedger`
re-checks it at READ time (within the ~512-slot / ~3.4-min window).

The SDK can return four distinct rejections for the slot anchor:

| Rejection                | Meaning                                                           | Op-side action                                                                 |
|--------------------------|-------------------------------------------------------------------|--------------------------------------------------------------------------------|
| `PreV4Cert`              | Cert was issued before AW-01-EXT rolled out.                      | Pin the v4 cutover epoch; document in partner policy. Not an alert.            |
| `MissingSlotAnchor`      | Cert was written with the zero-sentinel anchor.                   | P0. The cert pipeline must NEVER write a zero anchor in production — it would have failed the on-chain `verify_slot_anchor` write-time check. Investigate writer.|
| `AnchorTooOld`           | Slot is outside the SlotHashes sysvar window — only verifiable off-chain. | Expected for any cert older than ~3.4 min. SDK consumers SHOULD treat as "best-effort verified at write time" and rely on the write-time check + (eventually) the `challenge_certificate` ix. |
| `AnchorHashMismatch`     | The cluster's `slot_anchor_hash` differs from what Solana actually recorded for that slot. | **P0 — page immediately.** This is the AW-01-EXT smoking gun: a coordinated upstream poisoning where the cluster's RPC fleet returned a fake block hash for the slot. See "SOURCE_DISAGREEMENT triage" below. |

### SOURCE_DISAGREEMENT triage (AW-01-EXT P0 path)

Trigger: SDK consumer reports `AnchorHashMismatch` OR Prometheus
`SourceDisagreement` alert fires (consumer-side metric — the cluster
itself cannot detect this; the whole point is that the cluster's RPC
fleet IS the poisoned source).

```bash
# 1. Pull the disputed cert + its slot anchor.
CERT_PDA=...   # from the consumer's bug report
helixor-cli cert-show "$CERT_PDA" --field slot_anchor_slot,slot_anchor_hash

# 2. Independently re-fetch the block hash for that slot from a
#    REFERENCE validator we trust (not in the cluster's RPC fleet).
SLOT=$(...)
solana --url $REFERENCE_RPC block "$SLOT" --output json |
  jq -r .blockhash
# Compare bytes-for-bytes. If they differ, the cluster's anchor is
# lying — confirm with a SECOND independent reference RPC before
# escalating.

# 3. Snapshot each cluster node's upstream-RPC config — at least one
#    poisoned RPC should be common to ALL nodes that signed this cert.
for n in oracle-node-{0..4}; do
  ssh "$n" -- 'env | grep -E "SOLANA_RPC|GEYSER" | sort'
done | sort -u
```

Decision tree:

- **Single reference RPC says cluster lied, second reference RPC
  agrees with cluster** → reference RPC is the wrong one. Reject the
  report.
- **Two independent reference RPCs both say cluster lied** → confirmed
  AW-01-EXT poisoning. Page the lead. Halt cert issuance immediately
  (`helixor-cli pause cert-writes`). The cluster's upstream RPC fleet
  is compromised.
- **Reference RPCs agree with cluster** → SDK consumer's
  `verifyAgainstSolanaLedger` may have a bug. Capture the consumer's
  reproduction case before closing.

### SlotAnchorMismatch (write-time rejection)

If the on-chain `verify_slot_anchor` rejects a cert write with
`SlotAnchorHashMismatch` (error code `12073`), that is the cluster
catching its OWN poisoning before the cert lands — the slot was
still in the sysvar window so the chain itself rebutted. This is the
write-time analogue of the post-fact `AnchorHashMismatch` above and
warrants the SAME triage: an `SlotAnchorHashMismatch` write-time
rejection means at least one cluster RPC is poisoned RIGHT NOW.

### SlotAnchorTooOld (write-time rejection)

`SlotAnchorTooOld` (`12072`) at write time means the cluster pinned a
slot older than the SlotHashes window before submitting the cert —
i.e. scoring + sig assembly + submission took longer than ~3.4 min.
Almost always a latency regression, not a poisoning event. Triage
via `launch/runbooks/latency_regression.md`. If repeated, raise the
SlotHashes-fetch cadence in `oracle/cluster/slot_anchor.py`.

### CertificateRepudiated (post-window challenge upheld)

`AW-01-EXT.6` — when a cert is more than ~3.4 min old (outside the
SlotHashes window), the write-time `verify_slot_anchor` check is no
longer queryable. The on-chain `challenge_certificate` ix is the
post-window dispute path:

1. A third-party attester cluster (DISJOINT from the cert-signing
   cluster) fetches `cert.slot_anchor_slot` from an INDEPENDENT
   source (their own archive node, etc.).
2. They M-of-N-sign the canonical challenge digest
   (`sha256("helixor-aw01-ext-challenge" || cert_pubkey ||
   true_block_hash)`).
3. A challenger submits the signatures via `challenge_certificate`.
4. If `true_block_hash != cert.slot_anchor_hash`, the handler flips
   `cert.challenge_state` to `Upheld` and emits
   `CertificateRepudiated`.

**Any `CertificateRepudiated` event is a P0** — the cert is now
provably wrong at the slot-anchor layer; downstream consumers MUST
treat it as invalid. The off-chain slash-authority plumbing reads
the event and triggers the cluster-side slashing flow. Follow-up:

- Postmortem under `incidents/<YYYY-MM-DD>-aw01ext6-<short-tag>.md`.
- Audit the cluster's upstream RPC fleet for the slot in question.
- Rotate compromised RPCs out before resuming cert writes.

A `ChallengeRejected` event (the challenger's `true_block_hash`
matched the cert's anchor) is NOT a P0 — the challenge was
frivolous and the challenger's rent was consumed as the anti-spam
cost. But a SUSTAINED rate of rejections from the same challenger
pubkey may indicate a DOS attempt or a misconfigured attester
operator — investigate the attester cluster.

Two further error codes can surface from `challenge_certificate`:

- `NoAttesterCluster` (`12080`) — the operator left
  `challenge_attester_keys` empty and `challenge_threshold` zero
  at `initialize_config` time, leaving the ix deliberately
  disabled. Wire the attester cluster (or accept that the
  write-time check is the only AW-01-EXT defence).
- `ChallengeExpired` (`12083`) — the cert is older than 90 days
  (`CHALLENGE_WINDOW_SECONDS`). The cert state is final; the
  dispute path is fully off chain at this point.

## Strike attribution

Nodes named in `input_divergent_nodes` accumulate strikes on the
watchdog's `INPUT_DIVERGENCE` track (separate from
`ConflictingScores`). Watch the strikes endpoint:

```bash
curl -s http://api/byzantine/strikes | jq '.[] |
  select(.input_divergence_strikes > 0)'
```

## When to wake the lead

- Same node diverges 3 epochs in a row → strike-3 challenge pending.
- ANY epoch with `input_commitment is None` (no quorum) → P0 — the
  cluster failed to agree on what it saw.
- A DeFi consumer reports `Mismatch` against a live cert → P0.

## Postmortem (mandatory for any P0)

File under `incidents/<YYYY-MM-DD>-aw01-<short-tag>.md`. Mandatory
fields:
- Divergence timeline (epoch → divergent nodes → resolution).
- Was the cluster outvoted, or did the pipeline refuse the cert?
- The upstream root cause (Geyser? Kafka? indexer? clock?).
- Whether a consumer caught the divergence via `verifyInputProvenance`.
- Recovery action (config fix / rollback / replace node).
