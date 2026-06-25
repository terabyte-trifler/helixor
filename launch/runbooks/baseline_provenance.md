# Runbook — AW-03 baseline-provenance divergence

**Severity:** P0 (a `HashMismatch` from any partner SDK consumer) → Page (sustained `AccountNotFound` or `AccountUnreadable` from any partner).
**Trigger:** SDK consumer reports `verifyBaselineProvenance` → non-`ok` result, OR Prometheus `BaselineNonceRegression` alert (rejected on-chain write), OR daily-review job finds a `BaselineCommitted` event without a matching `BaselineDataAccount` PDA.

## What's happening

`baseline_hash` on the `AgentRegistration` is a 32-byte SHA-256
commitment over the cluster's behavioural baseline statistics for an
agent. AW-03 added the BYTES BEHIND THE HASH on chain via the
`BaselineDataAccount` PDA at:

```
seeds = ["baseline_data", agent_wallet, commit_nonce.to_le_bytes()]
```

`commit_baseline` enforces `sha256(payload) == baseline_hash` at write
time, and the account is immutable thereafter (`init` constraint, no
upgrade path). `HealthCertificate` carries `baseline_commit_nonce: u64`
(layout v6) which the threshold-signed `cert_payload_digest` folds in
as 8 BE bytes. SDK consumers call
`verifyBaselineProvenance(connection, healthOracleProgram, cert)` to
re-derive the hash from the on-chain payload.

A divergence means one of:

* `HashMismatch` — `sha256(account.payload) !== cert.baselineHash`. By
  construction this should be IMPOSSIBLE (the program enforces equality
  at write time and the account is immutable). If it happens it is the
  AW-03 smoking gun.
* `AccountNotFound` — the PDA derived from `(agent, baselineCommitNonce)`
  has no on-chain account. The cluster issued a cert naming a baseline
  that does not exist on chain.
* `AccountUnreadable` — bytes deserialise-fail. Either truncation, a
  wrong discriminator, or a deploy mismatch between cluster code and
  on-chain state.
* `AgentMismatch` / `NonceMismatch` — the fetched account belongs to a
  different agent or rotation than the cert claims. Unreachable for a
  well-formed PDA derivation but defended.
* `NoDataAccount` — `cert.baselineCommitNonce === 0n`. Either a
  pre-AW-03 (legacy) cert or a cluster regression that dropped the
  binding.

## Why it happens (most → least common)

1. **Pre-AW-03 cert presented to a post-AW-03 consumer.** The cert was
   issued before the v6 rollover and has `baselineCommitNonce === 0n`.
   `NoDataAccount` is the expected result; the partner should pin the
   v6 cutover epoch in their integration policy.
2. **RPC freshness lag.** The partner is reading a still-pending
   `BaselineDataAccount` write that has not yet finalized. Retry at
   `commitment: finalized` resolves it.
3. **Chain reorg.** A reorg dropped a `BaselineCommitted` tx. The
   cluster will re-emit on the next epoch; `AccountNotFound` should
   self-heal within ~30s.
4. **Wrong PDA derivation in the partner's SDK fork.** If the partner
   pinned an old `@phylanx/sdk` minor that predates the
   `baselineDataPda` helper, their PDA derivation can diverge from the
   on-chain seed scheme. Pin them to current SDK.
5. **Real AW-03 break.** The cluster issued a cert binding a
   `baseline_commit_nonce` whose on-chain account either doesn't exist
   or has divergent bytes. This is the threat AW-03 is supposed to
   make impossible — investigate as P0.

## Triage (5 min)

```bash
# 1. What's the cert claiming?
CERT_PDA=...   # from the consumer's bug report
phylanx-cli cert-show "$CERT_PDA" --field \
  agent,layout_version,baseline_hash,baseline_commit_nonce

# 2. Does the on-chain BaselineDataAccount exist at that nonce?
AGENT=$(...)
NONCE=$(...)
phylanx-cli baseline-data-show \
  --agent "$AGENT" --nonce "$NONCE" \
  --field commit_nonce,baseline_hash,payload_len

# 3. Re-derive the hash from the on-chain payload.
phylanx-cli baseline-data-show --agent "$AGENT" --nonce "$NONCE" \
  --field payload --raw | sha256sum
# Compare bytes-for-bytes with the cert's baseline_hash.

# 4. Pull the cluster's view of the agent's current baseline.
curl -s "http://api/agents/$AGENT/baseline" | jq '
  {commit_nonce, baseline_hash, baseline_algo_version, committed_at}'
# This MUST match the on-chain BaselineDataAccount that the
# AgentRegistration.baseline_data_pointer names.
```

## Decision tree

- **`cert.baselineCommitNonce === 0n` AND `cert.layoutVersion < 6`** →
  this is a pre-AW-03 cert. Expected. Pin the v6 cutover epoch in
  partner policy; do NOT relax the partner's check.

- **`cert.baselineCommitNonce === 0n` AND `cert.layoutVersion === 6`**
  → P0. A v6 cert MUST carry a non-zero nonce. Investigate the writer:
  was the AW-03 audit sweep run before the deploy that issued this
  cert? Re-run `python3 audit/baseline_provenance_check.py` and look
  for a regression that landed without the sweep being re-run.

- **`AccountNotFound` and the cert is < 30s old** → RPC lag. Retry at
  `commitment: finalized`. If the account still does not exist after
  60s, treat as P0 — the cluster issued a cert against a
  nonexistent baseline. Inspect the cluster's `commit_baseline`
  pipeline.

- **`AccountNotFound` and the cert is > 30s old** → P0. The cluster's
  on-chain baseline state diverges from what the cert claims.
  Halt cert issuance (`phylanx-cli pause cert-writes`), investigate.

- **`AccountUnreadable`** → P0 with a different shape. The bytes are
  there but deserialise fails. Almost always a program-version /
  client-version mismatch. Confirm the partner's
  `phylanx-sdk` IDL hash matches the deployed program's IDL hash.

- **`HashMismatch`** → CRITICAL P0. This is by-construction
  impossible: the on-chain `commit_baseline` handler enforces
  `sha256(payload) == baseline_hash` at write time, and the account
  is immutable. If it happens, exactly one of these is true:
    1. The on-chain program was upgraded to a buggy version that
       skipped the equality check. Diff
       `programs/health-oracle/src/instructions/commit_baseline.rs`
       against the deployed `.so` via
       `audit/artifact_verification/verify_so_match.ts`.
    2. The Anchor IDL hash on the partner's SDK is out of sync with
       the deployed program — they're deserialising the wrong bytes
       into the `payload` field.
    3. A reorg or a transient RPC corruption is feeding the partner
       a stale or corrupted account. Retry against a second
       independent RPC.
  Halt cert issuance immediately; do not resume until the cause is
  identified and the audit `verify_so_match.ts` job passes against a
  fresh build.

- **`AgentMismatch` / `NonceMismatch`** → SDK fork bug. The partner's
  PDA derivation diverged from the canonical seeds. Pin them to the
  current `@phylanx/sdk`.

## On-chain rejections to watch

The cluster's own writers can be rejected at `commit_baseline` /
`record_baseline` time. These are the cluster catching its OWN
regressions before chain state diverges:

| Error code | Symbol                          | Meaning                                                                                                                                              |
|------------|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| (see `errors.rs`) | `BaselineNonceRegression` | The writer tried to commit `new_nonce <= current_nonce`. Replay or rollback attempt. Investigate the writer immediately; this should be impossible from honest cluster code. |
| (see `errors.rs`) | `BaselineHashPayloadMismatch` | `sha256(payload) != baseline_hash`. The off-chain canonical serializer diverged from `baseline.hashing.build_hash_payload`. Pin the serializer version; do NOT bypass. |
| (see `errors.rs`) | `BaselinePayloadTooLarge` | Payload > 8 KB. Means the off-chain serializer is producing a non-canonical form. Same triage as `BaselineHashPayloadMismatch`. |
| (see `errors.rs`) | `BaselinePayloadEmpty` | Payload is zero-length. Pipeline bug — the serializer failed silently somewhere upstream. |

Any non-zero rate on the Prometheus
`phylanx_baseline_writetime_rejections_total{kind="*"}` counter is a P1
in steady state — the cluster's serializer + writer should be
self-consistent; a rejection means a deploy landed without the audit
sweep catching the regression.

## SDK consumer impact

DeFi protocols that wired `verifyBaselineProvenance(...)` are the first
line of defence against silent baseline substitution. If they report a
non-`NoDataAccount` rejection:

- The cert was signed against a baseline the consumer cannot reproduce
  from on-chain bytes.
- The consumer is correctly REFUSING the score. Do NOT pressure them
  to relax the check — that defeats AW-03.
- If `NoDataAccount` and the cert is v6, treat as a cluster regression
  (P0). If the cert is v5 or earlier, document the cutover and accept
  hash-only verification for legacy certs.

## When to wake the lead

- ANY `HashMismatch` from a partner → P0 (this is by-construction
  impossible from honest cluster code).
- ANY `AccountNotFound` against a cert > 30s old → P0 (the cluster
  issued a cert against a nonexistent baseline).
- A `BaselineNonceRegression` on-chain rejection → P0 (an honest
  writer should never regress; either a key is compromised or the
  writer is running stale code).
- Any sustained rate (> 1/hour) of `AccountUnreadable` from any
  partner → P1 (IDL drift between deployed program and consumer SDK).

## Postmortem (mandatory for any P0)

File under `incidents/<YYYY-MM-DD>-aw03-<short-tag>.md`. Mandatory
fields:
- The cert involved (`agent`, `epoch`, `baseline_commit_nonce`,
  `baseline_hash`).
- The specific rejection (`HashMismatch` / `AccountNotFound` / ...).
- What the on-chain bytes actually were vs what the cert named.
- Root cause: program-version drift / SDK-version drift / writer
  regression / RPC corruption.
- Whether the AW-03 audit sweep was run against the deploy that
  issued the bad cert. If yes, why didn't it catch the regression
  — the sweep is the architectural guarantee; if it lies, fix the
  sweep first.
- Recovery action: program rollback / writer rollback / partner SDK
  pin update.
- Was a partner the one who detected this, or did internal
  monitoring catch it first? A partner catching it means the
  cluster's own daily-review job missed a divergence — review the
  job's freshness assumptions.
