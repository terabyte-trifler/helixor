# Runbook — AW-04 scoring-provenance divergence

**Severity:** P0 (a `HashMismatch`, `ScoreReplayMismatch`, or
`CodeHashMismatch` from any partner SDK consumer) → Page (sustained
`AccountNotFound` or `AccountUnreadable` for `ScoreComponentsAccount`
from any partner).
**Trigger:** SDK consumer reports `verifyScoreComputation` →
non-`ok` result, OR `verifyScoringCodeHash` → non-`Ok` for a v7 cert,
OR Prometheus `ScoreComponentsWritetimeRejections` alert (rejected
on-chain write), OR daily-review job finds a `CertificateIssued`
event without a matching `ScoreComponentsAccount` PDA.

## What's happening

A v7 `HealthCertificate` carries two AW-04 commitments:

* `scoring_code_hash: [u8; 32]` — folded into the threshold-signed
  `cert_payload_digest` as 32 BE bytes appended after the AW-03
  `baseline_commit_nonce`. By construction every v7 cert names a
  SPECIFIC scoring kernel version.
* `score_components_hash: [u8; 32]` — derived ON CHAIN at write
  time from the payload bytes stored in the paired
  `ScoreComponentsAccount` PDA. Folded into the digest as 32 BE
  bytes appended after `scoring_code_hash`.

The components PDA sits at:

```
seeds = ["score_components", agent_wallet, epoch.to_le_bytes()]
```

`issue_certificate` enforces `sha256(payload) == components_hash` at
init time and the account is immutable thereafter (`init` constraint).
SDK consumers call `verifyScoreComputation(connection,
certificateIssuer, cert)` to re-derive the hash from the on-chain
payload and replay the score arithmetic.

A divergence means one of:

* `HashMismatch` — `sha256(account.payload) !== cert.scoreComponentsHash`.
  By construction this should be IMPOSSIBLE (the program computes
  the hash from the bytes it stored, and the account is immutable).
  If it happens it is the AW-04 smoking gun.
* `AccountNotFound` — the PDA derived from `(agent, epoch)` has no
  on-chain account. The cluster issued a v7 cert whose paired
  components account does not exist on chain.
* `AccountUnreadable` — bytes deserialise-fail. Either truncation,
  a wrong discriminator, or a deploy mismatch between cluster code
  and on-chain state.
* `AgentMismatch` / `EpochMismatch` — the fetched account belongs
  to a different agent or epoch than the cert claims. Unreachable
  for a well-formed PDA derivation but defended.
* `PayloadMalformed` — the canonical-JSON payload fails the SDK's
  schema pin (`v === 1`, all required keys present, types correct).
  Either a cluster-side serializer regression or a schema-version
  mismatch.
* `ScoreReplayMismatch` — the SDK's re-derivation of the headline
  score from the per-dimension contribs disagrees with
  `cert.score`. Either the cluster's composite function diverges
  from the documented algorithm (kernel swap), or the components
  account was written with arithmetically inconsistent contribs.
* `CodeHashMismatch` — `cert.scoringCodeHash !== expectedHash` for
  a v7 cert. Partner pinned a kernel hash that the cluster is no
  longer running.
* `PreV7Cert` — `cert.layoutVersion < 7` or zero `scoring_code_hash`.
  Either a pre-AW-04 (legacy) cert or a cluster regression that
  dropped the binding.
* `NoComponentsAccount` — `cert.layoutVersion < 7` AND no
  components account; expected for legacy certs only.

## Why it happens (most → least common)

1. **Pre-AW-04 cert presented to a post-AW-04 consumer.** The cert
   was issued before the v7 rollover and has zero
   `scoring_code_hash` / no paired components account. `PreV7Cert`
   / `NoComponentsAccount` is the expected result; the partner
   should pin the v7 cutover epoch in their integration policy.
2. **RPC freshness lag.** The partner is reading a still-pending
   `ScoreComponentsAccount` write that has not yet finalized.
   Retry at `commitment: finalized` resolves it.
3. **Chain reorg.** A reorg dropped the components init alongside
   the cert. The cluster will re-emit on the next epoch;
   `AccountNotFound` should self-heal within ~30s.
4. **Wrong PDA derivation in the partner's SDK fork.** If the
   partner pinned an old `@helixor/sdk` minor that predates the
   `scoreComponentsPda` helper, their PDA derivation can diverge
   from the on-chain seed scheme. Pin them to current SDK.
5. **Pinned kernel hash drifted.** The partner pinned
   `EXPECTED_SCORING_CODE_HASH = <vN>` and the cluster has since
   deployed `<vN+1>` (e.g. a documented kernel refresh, weights
   bump, or audit-driven kernel patch). `CodeHashMismatch` is
   correct behaviour for an UN-audited new kernel — the partner
   must re-audit the new kernel and update the pin.
6. **Real AW-04 break.** The cluster issued a v7 cert binding a
   `scoring_code_hash` or `score_components_hash` whose on-chain
   account either doesn't exist, has divergent bytes, or whose
   payload's score-replay arithmetic disagrees with the headline
   score. This is the threat AW-04 is supposed to make impossible
   — investigate as P0.

## Triage (5 min)

```bash
# 1. What's the cert claiming?
CERT_PDA=...   # from the consumer's bug report
helixor-cli cert-show "$CERT_PDA" --field \
  agent,layout_version,epoch,score,scoring_code_hash,score_components_hash

# 2. Does the on-chain ScoreComponentsAccount exist at that epoch?
AGENT=$(...)
EPOCH=$(...)
helixor-cli score-components-show \
  --agent "$AGENT" --epoch "$EPOCH" \
  --field epoch,agent,components_hash,payload_len

# 3. Re-derive the hash from the on-chain payload.
helixor-cli score-components-show --agent "$AGENT" --epoch "$EPOCH" \
  --field payload --raw | sha256sum
# Compare bytes-for-bytes with the cert's score_components_hash.

# 4. Re-derive the score from the payload contribs.
helixor-cli score-components-show --agent "$AGENT" --epoch "$EPOCH" \
  --field payload --raw | jq '
    {claimed_score: .score,
     replay: ([.dims[].contrib] | add | (if . > 1000 then 1000 elif . < 0 then 0 else . end))}'
# These MUST match (modulo delta_guard_rail clamp).

# 5. Pull the cluster's view of the deployed kernel hash.
helixor-cli oracle-config-show --field scoring_code_hash
# Confirm matches the cert's scoring_code_hash AND the partner's
# pinned EXPECTED_SCORING_CODE_HASH.
```

## Decision tree

- **`cert.layoutVersion < 7` (any rejection)** → this is a pre-AW-04
  cert. Expected for `PreV7Cert` / `NoComponentsAccount`. Pin the
  v7 cutover epoch in partner policy; do NOT relax the partner's
  check.

- **`cert.layoutVersion === 7` AND `cert.scoringCodeHash` is all
  zero** → P0. A v7 cert MUST carry a non-zero hash. The on-chain
  handler rejects this with `MissingScoringCodeHash`, so the cert
  could not have been issued by a correct deploy. Either: (a) the
  deployed `.so` was upgraded to a buggy version that skipped the
  zero-hash check (verify via
  `audit/artifact_verification/verify_so_match.ts`), or (b) the
  on-chain bytes are corrupted. Halt cert issuance.

- **`AccountNotFound` and the cert is < 30s old** → RPC lag. Retry
  at `commitment: finalized`. If the account still does not exist
  after 60s, treat as P0 — the cluster issued a cert against a
  nonexistent components account. Inspect the cluster's
  `submit_score` → `issue_certificate` CPI pipeline.

- **`AccountNotFound` and the cert is > 30s old** → P0. The cluster's
  on-chain components state diverges from what the cert claims.
  Halt cert issuance (`helixor-cli pause cert-writes`), investigate.
  This is by-construction impossible if the CPI handler ran
  correctly: `issue_certificate` initialises BOTH the cert PDA AND
  the components PDA atomically. A cert without its components is
  a partial CPI write, which the runtime should have reverted.

- **`AccountUnreadable`** → P0 with a different shape. The bytes
  are there but deserialise fails. Almost always a program-version /
  client-version mismatch. Confirm the partner's `helixor-sdk` IDL
  hash matches the deployed program's IDL hash. Run
  `audit/artifact_verification/verify_so_match.ts`.

- **`HashMismatch`** → CRITICAL P0. This is by-construction
  impossible: the on-chain `issue_certificate` handler computes the
  hash from the bytes it stores, and the account is immutable. If
  it happens, exactly one of these is true:
    1. The on-chain program was upgraded to a buggy version that
       trusted a caller-supplied hash. Diff
       `programs/certificate-issuer/src/instructions/issue_certificate.rs`
       against the deployed `.so` via
       `audit/artifact_verification/verify_so_match.ts`.
    2. The Anchor IDL hash on the partner's SDK is out of sync with
       the deployed program — they're deserialising the wrong bytes
       into the `payload` field of `ScoreComponentsAccount`.
    3. A reorg or transient RPC corruption is feeding the partner
       a stale or corrupted account. Retry against a second
       independent RPC.
  Halt cert issuance immediately; do not resume until the cause is
  identified and the audit `verify_so_match.ts` job passes against
  a fresh build.

- **`PayloadMalformed`** → P1, escalate to P0 if sustained. Either
  (a) the cluster's `oracle/score_components.py` canonical-JSON
  serializer regressed (likely if the rejection is a missing key
  or a non-canonical numeric serialisation), or (b) the SDK schema
  pin needs widening for a new schema version. The fix is on the
  cluster side: re-run `audit/scoring_provenance_check.py` and
  diff the serializer output against
  `tests/oracle/test_aw04_score_components.py`.

- **`ScoreReplayMismatch`** → CRITICAL P0. The cluster signed a
  cert whose headline `score` disagrees with the sum of the per-
  dimension contribs in its OWN components account. The signature
  attests to the inconsistency, which means the cluster's scoring
  kernel is computing a final score by some path other than
  "sum the contribs and clamp". Exactly one of:
    1. A kernel swap: `scoring/composite.py` has been replaced
       with a version that does NOT sum the dim contribs. Re-run
       `python3 audit/scoring_provenance_check.py` and pull the
       deployed `scoring_code_hash` — compare against the audit
       baseline.
    2. The components account was written with fabricated /
       arithmetically inconsistent contribs (cluster regression).
  Halt cert issuance. Cross-check the cluster's deployed kernel
  bundle hash against the audited reference.

- **`CodeHashMismatch`** → P1 (NOT P0 by default). This is the
  CORRECT consumer behaviour for an UN-audited kernel deployment.
  Either:
    1. The cluster shipped a new kernel version and the partner
       hasn't refreshed their pin. The cluster's release process
       should have announced the hash change in advance —
       confirm the announcement landed in the partner channel.
    2. The cluster shipped a kernel WITHOUT a release
       announcement → P0. The cluster's deploy discipline is the
       issue, not the cert. Investigate the cluster operator who
       pushed the deploy.
  Resolution: update partner's `EXPECTED_SCORING_CODE_HASH`
  AFTER they re-audit the new kernel against
  `audit/reports/aw04_scoring_provenance.json`.

- **`AgentMismatch` / `EpochMismatch`** → SDK fork bug. The
  partner's PDA derivation diverged from the canonical seeds. Pin
  them to the current `@helixor/sdk`.

## On-chain rejections to watch

The cluster's own writers can be rejected at `issue_certificate`
time. These are the cluster catching its OWN regressions before
chain state diverges:

| Error code | Symbol                          | Meaning                                                                                                                                              |
|------------|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| (see `errors.rs`) | `MissingScoringCodeHash`        | The writer tried to issue a v7 cert with a zero `scoring_code_hash`. Pipeline bug — the bundle-hash computation failed silently. Investigate the writer; this should be impossible from honest cluster code that ran `compute_scoring_bundle_hash()`. |
| (see `errors.rs`) | `ScoreComponentsPayloadEmpty`   | Components payload is zero-length. Pipeline bug — the canonical-JSON serializer failed silently somewhere upstream. |
| (see `errors.rs`) | `ScoreComponentsPayloadTooLarge` | Components payload > 4 KB. Means the off-chain canonical serializer is producing a non-canonical (or non-pruned) form. Pin the serializer version; do NOT bypass. |
| (see `errors.rs`) | `MissingScoreComponentsHash`    | Derived components hash is all-zero (sha256 of empty input). This should be caught by `ScoreComponentsPayloadEmpty` first — if it fires alone, the on-chain hash function is broken (impossible by construction; treat as catastrophic). |

Any non-zero rate on the Prometheus
`helixor_score_components_writetime_rejections_total{kind="*"}`
counter is a P1 in steady state — the cluster's serializer + writer
should be self-consistent; a rejection means a deploy landed without
the audit sweep catching the regression.

## SDK consumer impact

DeFi protocols that wired `verifyScoreComputation(...)` are the
first line of defence against silent scoring-kernel swaps. If they
report a non-`PreV7Cert`/`NoComponentsAccount` rejection:

- The cert was signed against a score the consumer cannot reproduce
  from on-chain bytes.
- The consumer is correctly REFUSING the score. Do NOT pressure them
  to relax the check — that defeats AW-04.
- If `PreV7Cert` / `NoComponentsAccount` and the cert is v6 or
  earlier, document the cutover and accept hash-only verification
  for legacy certs.

A consumer that also wires `verifyScoringCodeHash(cert,
expectedHash)` has the second line of defence: even if the
components replay passes, a kernel swap (different `composite.py` /
`weights.py` / etc.) flips the bundle hash and the partner's pin
catches the swap. Encourage partners to wire BOTH.

## When to wake the lead

- ANY `HashMismatch` from a partner → P0 (this is by-construction
  impossible from honest cluster code).
- ANY `ScoreReplayMismatch` from a partner → P0 (the cluster
  signed an arithmetically inconsistent score).
- ANY `AccountNotFound` against a v7 cert > 30s old → P0 (the
  cluster issued a cert against a nonexistent components account;
  the CPI write was not atomic).
- ANY zero `scoring_code_hash` on a v7 cert → P0 (the on-chain
  handler rejects this, so it can only happen via a broken deploy).
- A `MissingScoringCodeHash` or `ScoreComponentsPayloadEmpty`
  on-chain rejection → P0 (an honest writer should never produce
  these).
- Any sustained rate (> 1/hour) of `AccountUnreadable` from any
  partner → P1 (IDL drift between deployed program and consumer
  SDK).
- A `CodeHashMismatch` from a partner WITHOUT a prior cluster
  release announcement → P0 (deploy-discipline regression at the
  cluster operator level).

## Postmortem (mandatory for any P0)

File under `incidents/<YYYY-MM-DD>-aw04-<short-tag>.md`. Mandatory
fields:
- The cert involved (`agent`, `epoch`, `score`, `scoring_code_hash`,
  `score_components_hash`).
- The specific rejection (`HashMismatch` / `ScoreReplayMismatch` /
  `AccountNotFound` / `CodeHashMismatch` / ...).
- What the on-chain bytes actually were vs what the cert named
  (raw payload, derived hash, sum of dim contribs, claimed score).
- Root cause: program-version drift / SDK-version drift / kernel
  swap / writer regression / RPC corruption / un-announced kernel
  deploy.
- Whether the AW-04 audit sweep was run against the deploy that
  issued the bad cert. If yes, why didn't it catch the regression
  — the sweep is the architectural guarantee; if it lies, fix the
  sweep first.
- Recovery action: program rollback / writer rollback / kernel
  rollback / partner SDK pin update / partner kernel-hash pin
  update.
- Was a partner the one who detected this, or did internal
  monitoring catch it first? A partner catching it means the
  cluster's own daily-review job missed a divergence — review the
  job's freshness assumptions.
