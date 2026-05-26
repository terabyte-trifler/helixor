# Runbook — Score Manipulation Detected incident response

**Severity:** High. A cert (or a window of certs across one or more
epochs) is believed to carry a manipulated score — either via
upstream-data poisoning (red-team Path 2 "Inflate Legitimate Score"),
Byzantine slow-drift (VULN-03), or active collusion among a subset of
oracle nodes.

**Triggers:**
- ILS-1 / ILS-2 / ILS-3 audit gate (`audit/inflate_score_check.py`)
  red.
- PDS-2 score-velocity guard (`helixor-oracle/oracle/score_velocity.py`)
  raises `ScoreVelocityViolation` for an agent.
- An off-protocol observer files a `challenge_certificate` ix
  (AW-01-EXT.6) and the threshold attester quorum upholds it.
- Cluster-internal Byzantine watchdog (`byzantine_repo`) reports
  `recent_flags()` exceeding the 3-strike threshold for one or more
  nodes within a short window.
- External report from a DeFi integrator that the published score
  does not match independently re-derived inputs.

## What's happening

A score-manipulation event is the runtime sibling of red-team Path 2.
The attack surface has three sub-leaves, each closed by orthogonal
mitigations:

  2a. VULN-06 baseline overwrite                [LOW EFFORT]    — ILS-1
  2b. VULN-07 feature poisoning                 [MEDIUM EFFORT] — ILS-2
  2c. VULN-03 Byzantine slow drift              [HIGH EFFORT]   — ILS-3

The defences are preventative: they refuse cert issuance when the
cluster sees the manipulation pattern in real time. But a sufficiently
patient adversary can fly under those floors, or the mitigations can
have a regression that lands in mainnet between audit-gate runs. When
that happens, the audit's 4-step incident response is:

  1. Flag the affected-epoch certs as disputed on-chain.
  2. Issue an emergency YELLOW alert for affected agents.
  3. Notify DeFi protocols to pause lending against disputed certs.
  4. Begin forensic analysis of the Kafka / database trail.

Every move below uses existing primitives. The new code surface is
zero; this runbook is the *order* and the *anchors*.

---

## Step 1 — Flag affected-epoch certs as disputed on-chain

**Substrate:** the AW-01-EXT.6 challenge flow — `challenge_certificate`
on `certificate-issuer`. The challenge is an immutable PDA (one-per-
cert) carrying the challenger's evidence digest and the cluster's
attester-quorum verdict.

  - `helixor-programs/programs/certificate-issuer/src/instructions/challenge_certificate.rs`
  - `helixor-programs/programs/certificate-issuer/src/state/challenge_record.rs`
    (`ChallengeRecord` PDA with `state ∈ {None=0, Upheld=1, Rejected=2}`,
    layout-pinned, never closes)
  - `helixor-programs/programs/certificate-issuer/src/state/health_certificate.rs:70-103`
    (the `ChallengeState` discriminator the cert itself carries)

**Procedure (operator-of-record, signed Squads tx — one per affected
cert):**

```text
For each (agent, epoch) flagged as manipulated:

A. CANONICALISE the dispute evidence — the inputs / commitments /
   raw transactions the challenger asserts contradict the cert's
   declared score. The digest goes into the challenge's
   `evidence_hash` field; the off-chain payload is published to the
   audit-trail repo (audit/reports/score_manipulation_<UTC>.md).

B. FILE the challenge:

     challenge_certificate(
         agent_wallet      = <pubkey>,
         epoch             = <u64>,
         evidence_hash     = <32 bytes>,
         attester_signers  = challenge_attester_keys[...],
     )

   The ix verifies a strict-majority attester quorum (a SEPARATE
   threshold set from the cluster_keys — `challenge_attester_keys` +
   `challenge_threshold` on `IssuerConfig`) before flipping the
   cert's `challenge_state` to `Upheld`.

C. CONFIRM the on-chain state flipped:

     anchor account HealthCertificate --address <CERT_PDA>
     # Verify cert.challenge_state == 1 (Upheld)

   And the `ChallengeRecord` PDA derived from
   `["challenge", agent, epoch_le]` exists with `state == Upheld`.

D. REPEAT for every cert in the disputed window. The challenge ix
   is per-(agent, epoch); a multi-epoch manipulation window means N
   challenge ixs, one per cert.
```

**Why the on-chain flag is sufficient:**

Verified Integrators that do direct on-chain reads (the recommended
DBP-3 pattern) decode the cert's `challenge_state` field. A cert with
`challenge_state == Upheld` is REPUDIATED — the protocol's own read
logic refuses to honour it. No API call, no webhook subscription,
no SDK update is needed; the substrate IS the flag.

**Do NOT:**
- Try to mutate or close the `HealthCertificate` PDA. Certs are
  layout-pinned and overwritten only by the next `issue_certificate`
  call; the `challenge_state` field is the dispute marker, not the
  cert's existence.
- Lower `challenge_threshold` to push a marginal dispute through.
  The attester quorum is the on-chain audit gate against frivolous
  challenges; weakening it defeats the AW-01-EXT.6 mechanism.

**Test pins:**
- `programs/certificate-issuer/src/instructions/challenge_certificate.rs:432-630`
  (digest determinism, domain-tag separation, attester filtering,
  cross-cert replay defence, 90-day challenge window).

---

## Step 2 — Issue emergency YELLOW alert for affected agents

**Substrate:** the cluster's normal `issue_certificate` flow accepts
`alert_tier` as an input parameter (`AlertTier::{Green=0, Yellow=1,
Red=2}` in `programs/certificate-issuer/src/state/health_certificate.rs:64`),
and that input is folded into the signed digest. Operators-of-record
can force YELLOW for affected agents by directing the cluster's next
cert-issuance cycle to emit `alert_tier = 1`.

**Procedure (cluster operators, coordinated out-of-band):**

```text
A. AGREE on the YELLOW-list — the set of agents whose certs were
   manipulated or whose dependent inputs are tainted. The list goes
   into a cluster-coordinator config flag
   (HELIXOR_FORCE_YELLOW_AGENTS) that the scoring kernel reads at
   issuance time.

B. The cluster's next epoch tick produces certs for every active
   agent. For agents on the YELLOW-list, the scoring kernel emits
   alert_tier = 1 REGARDLESS of the computed score. The score
   itself is still the cluster's honest re-computation — only the
   tier is forced.

C. FRP-3 (`MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600`) guarantees
   every active agent's cert is replaced within 4h, so the YELLOW
   alert reaches every Verified Integrator's SafeCertReader on
   their next poll.

D. After the forensic analysis (step 4) closes and the audit
   confirms the agent's inputs are clean, REMOVE the agent from
   HELIXOR_FORCE_YELLOW_AGENTS. The next cluster reissue (≤ 4h)
   produces GREEN again.
```

**Why YELLOW (not RED):**

`alert_tier = 2 (RED)` is the audit-mandated state for an agent
whose score is known-corrupted. YELLOW is the state for "the score
may be unreliable — proceed with caution." A score-manipulation
incident in the *detection* phase is YELLOW; an upheld challenge
(step 1) plus a forensic-confirmed manipulation (step 4) escalates
the cluster's next reissue to RED.

**Anchor pins:**
- `helixor-programs/programs/certificate-issuer/src/state/health_certificate.rs:64`
  (`AlertTier::Yellow = 1`).
- `helixor-programs/programs/certificate-issuer/src/instructions/issue_certificate.rs:53`
  (`alert_tier: u8` accepted as input, folded into the signed digest).
- `helixor-oracle/oracle/cert_reissue_cadence.py:102`
  (`MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600` cadence guarantee).

---

## Step 3 — Notify DeFi protocols to pause lending against disputed certs

**Substrate:** the DBP-4 cert-degrading webhook + SOL-3 per-operation
freshness floors. The IR strategy is "pause lending against disputed
certs"; the existing primitives compose to exactly that outcome.

**Three layers, fired together:**

**3a. On-chain reads — automatic.** Verified Integrators reading
`HealthCertificate` directly (the DBP-3 canonical pattern) see
`challenge_state == Upheld` from step 1 and refuse the read in their
own on-chain logic. No notification needed; the flag IS the pause.

**3b. SDK-side reads — via freshness cascade after YELLOW reissue.**
After step 2 forces YELLOW, the cluster reissues affected agents'
certs. SafeCertReader returns the YELLOW tier verbatim; partners
whose policy refuses YELLOW for high-stakes operations
(`example_safe_partner/reader.ts:64-74` LOAN_ISSUE refuses against
YELLOW or higher) automatically halt those operations. If operators
instead choose to *suspend* signing for an affected agent (no new
certs at all), the freshness floors fire in cascade — within 4h for
LOAN_ISSUE callers, within 12h for LIQUIDATION_CHECK callers, within
48h for STATUS_READ callers. See the timeline in
`launch/runbooks/oracle_key_compromise_response.md` step 4 for the
exact per-operation cutoffs.

**3c. Courtesy notification — DBP-4 cert.degrading + email.** If the
cluster has suspended signing for the affected agents, the existing
`cert.degrading` webhook fires at the 36h mark (DBP-4d
`DEGRADING_THRESHOLD_FRACTION = 0.75` in `helixor-api/api/webhooks.py`)
to every Insured-tier subscriber. The webhook is the proactive
signal; combined with an out-of-band incident notice to the
Verified Integrator channel (`launch/integrations/example_safe_partner.json`
points partners at the contact list maintained alongside
`HELIXOR_WEBHOOKS`), partners hear it from two independent surfaces.

**Procedure (responder):**

1. Post the incident notice to the Verified Integrator channel.
   Reference this runbook section and the affected (agent, epoch)
   list from step 1.
2. Confirm the DBP-4 webhook fired (or, for an agent-by-agent
   suspension, will fire within 36h). Inspect the dispatcher's
   delivery log; failed deliveries are tracked per-partner.
3. Track partner-side acknowledgements out-of-band; the safe-reader
   refusal is the binding mechanism, the ACK is courtesy.

**Anchor pins:**
- `helixor-api/api/webhooks.py:DEGRADING_THRESHOLD_FRACTION = 0.75`,
  `EVENT_CERT_DEGRADING = "cert.degrading"`, `SIGNATURE_HEADER =
  "X-Helixor-Webhook-Signature"`.
- `launch/integrations/example_safe_partner/reader.ts:58-74`
  (per-operation freshness floors + tier-refusal policy).
- `helixor-sdk/src/safe_reader.ts` (SafeCertReader's reject reasons).

**Test pins:**
- `helixor-api/tests/test_dbp4_webhooks.py` (webhook trigger + dedupe).
- `helixor-sdk/test/safe_reader.test.ts` (reject-reason coverage).

**Roadmap note:** a dedicated `cert.repudiated` webhook event +
`SafeCertReader.RejectReason.CertRepudiated` are additive surface,
not replacement. The existing on-chain `challenge_state` flag is the
durable signal; the new event/reason are sugar for partners that
prefer push delivery to direct on-chain reads. They are tracked as a
future PR; this runbook does NOT depend on them.

---

## Step 4 — Begin forensic analysis of Kafka / database data

**Substrate:** the existing audit scripts + the indexer's Kafka log
+ the TimescaleDB tables. The forensic question is "what produced
the manipulated score, and when did the manipulation start?"

**The trail (newest evidence first):**

```text
ON-CHAIN
  HealthCertificate  ─ epoch, score, alert_tier, baseline_hash,
                       input_commitment (AW-01),
                       slot_anchor_(slot,hash) (AW-01-EXT),
                       scoring_code_hash + score_components_hash (AW-04)
  ChallengeRecord    ─ (from step 1) evidence_hash, attester verdict
  ScoreComponentsAccount ─ per-dimension breakdown (AW-04)
  BaselineDataAccount    ─ the canonical baseline payload (AW-03)

INDEXED (TimescaleDB)
  agent_score_history   ─ one row per cert the indexer mirrored
  byzantine_flags       ─ one row per watchdog flag event
  oracle_heartbeats     ─ last-seen per node

CLUSTER (Kafka)
  topic: scores.raw        ─ per-node raw score votes per epoch
  topic: commits           ─ commit-reveal commit phase records
  topic: reveals           ─ commit-reveal reveal phase records
  topic: input_commitments ─ per-cluster input commitment events
```

**Forensic queries (canonical):**

```bash
# Q1. Pull every cert for the affected agent in the disputed window:
psql -c "
  SELECT epoch, score, alert_tier, baseline_hash, input_commitment,
         scoring_code_hash, score_components_hash
    FROM agent_score_history
   WHERE agent_wallet = '<wallet>'
     AND epoch BETWEEN <start> AND <end>
   ORDER BY epoch;
"

# Q2. Pull every Byzantine flag in the same window:
psql -c "
  SELECT filed_at, accused_node, proof_type, subject_epoch,
         subject_agent, accused_score, cluster_median, evidence_hash
    FROM byzantine_flags
   WHERE subject_agent = '<wallet>'
     AND subject_epoch BETWEEN <start> AND <end>
   ORDER BY filed_at;
"

# Q3. Replay the affected epoch's raw vote stream from Kafka:
helixor-indexer-cli kafka-replay \
  --topic scores.raw \
  --filter "agent=<wallet>" \
  --from-epoch <start> --to-epoch <end> \
  > /tmp/raw_votes_<wallet>.jsonl

# Q4. Re-run the audit gates against the snapshot the cluster used:
python3 audit/inflate_score_check.py --json /tmp/ils.json
python3 audit/scoring_provenance_check.py --json /tmp/aw04.json
python3 audit/baseline_provenance_check.py --json /tmp/aw03.json
# Any HARD finding identifies the exact mitigation that should have
# refused the manipulated cert.
```

**What to look for:**

1. **Per-node vote divergence.** Q3's per-node votes should cluster
   tightly around the cert's declared score; outliers identify the
   nodes that may have been manipulated or compromised. Cross-
   reference Q2 to see if those nodes were already flagged.
2. **Baseline rotation drift.** Q1's `baseline_hash` should change
   only on the cadence ILS-1 enforces. A baseline that rotated
   mid-window without a co-attestation is the signature of VULN-06.
3. **Score-components replay.** Decode the `ScoreComponentsAccount`
   for each affected epoch and re-run `verifyScoreComputation`
   (helixor-sdk). A replay disagreement is AW-04's catch — either
   the cluster shipped patched scoring code (caught by
   `scoring_code_hash`) or fabricated the components
   (caught by `score_components_hash` matching neither
   `sum(contrib) -> clamp` nor the committed breakdown).
4. **Input commitment drift.** The cert's `input_commitment` (AW-01)
   should re-derive from independently observable on-chain
   transactions in the slot window declared by
   `slot_anchor_(slot, hash)` (AW-01-EXT). A drift here is the
   signature of an upstream-data poison (Geyser / Kafka / indexer)
   — and the same cross-validator in
   `helixor-indexer/indexer/cross_verify.py:SamplingCrossVerifier`
   would have refused the data on ingest if it had been sampled.
5. **Velocity.** PDS-2 (`MAX_SCORE_DELTA_PER_EPOCH = 200`) refuses
   intra-epoch deltas exceeding 200 points. A manipulation that
   stayed under 200 per epoch but accumulated drift is VULN-03's
   slow-drift attack — ILS-3 cumulative ceiling should have caught
   it.

**Retention floor:**

- **Kafka:** indexer topics retain per the
  `launch/deploy/docker-compose.kafka-ha.yml` config; ops policy
  is "≥ 30 days for `scores.*`, `commits`, `reveals`,
  `input_commitments`" (audit-mandated, raise an issue if violated).
- **TimescaleDB:** `agent_score_history` and `byzantine_flags` are
  retained indefinitely; `oracle_heartbeats` is windowed at 90
  days. Audit-relevant rows for an open challenge MUST be flagged
  `hold = true` to exempt them from any future compaction.
- **Prometheus:** 30d retention
  (`launch/deploy/docker-compose.indexer.yml:183`); use this to
  trace alert / rate-limit anomalies during the window.
- **PITR:** 7-day point-in-time recovery
  (`launch/deploy/docker-compose.timescale-ha.yml:36`); useful only
  if the manipulation was detected within a week.

**Procedure:**

1. Snapshot Q1–Q3 into `audit/reports/score_manipulation_<UTC>.md`
   alongside the dispute evidence digest from step 1.
2. Run Q4 to identify which mitigation should have refused the
   cert and why it didn't. If a HARD finding regression is the
   answer, the FIX is to restore the mitigation anchor — NOT to
   weaken the gate.
3. Cross-reference with the operator-of-record HSM audit logs for
   the affected window. If a node's signing pattern shows manual
   override or anomalous frequency, that node enters the suspect
   set for the next rotation (re-use the oracle-key-compromise
   runbook).
4. Write the post-mortem to `incidents/<UTC>_score_manipulation.md`
   with the four sections: timeline, root cause, mitigation gap,
   forward fixes.

**Do NOT:**
- Delete or compact any Kafka topic, TimescaleDB row, or oracle
  heartbeat within the dispute window. Retention floors are
  audit-mandated; compaction is a destructive operation that
  destroys the forensic trail.
- Restart oracle nodes during the forensic window unless
  absolutely necessary. The cluster's in-memory state (current
  commit-reveal rounds, in-flight votes) is part of the trail; a
  restart loses it.
- Patch the scoring kernel mid-incident. Any change to the
  scoring code without a corresponding `scoring_code_hash`
  rotation is itself a VULN-04 / AW-04 anomaly.

**Anchor pins:**
- `audit/inflate_score_check.py` (ILS-1/2/3 audit gate).
- `audit/scoring_provenance_check.py` (AW-04 audit gate).
- `audit/baseline_provenance_check.py` (AW-03 audit gate).
- `helixor-indexer/indexer/cross_verify.py` (Geyser-vs-RPC sampling
  reconciler — the upstream-data poison defence).
- `helixor-oracle/oracle/score_velocity.py:MAX_SCORE_DELTA_PER_EPOCH = 200`
  (PDS-2 velocity floor).

---

## After action

1. Add the incident to `audit/reports/score_manipulation_<UTC>.md`
   with the dispute evidence digests, the YELLOW-list, the partner
   notifications, the Kafka snapshots, and the audit-gate re-runs.
2. Run the full audit gate suite (every gate, not just ILS):

   ```bash
   python3 audit/forge_high_score_check.py
   python3 audit/inflate_score_check.py
   python3 audit/freeze_cert_check.py
   python3 audit/scoring_provenance_check.py
   python3 audit/baseline_provenance_check.py
   python3 audit/consumer_integration_check.py
   python3 audit/centralization_check.py
   python3 audit/supply_chain_check.py
   ```

   All should return 0 HARD findings.
3. If a mitigation regression was the root cause, restore the
   anchor + add a regression test pinning the constant or rule.
4. Run a tabletop on what the *next* manipulation would look like.
   The challenge attester quorum (challenge_threshold) is the
   audit-of-the-audit: if forensics show the manipulation slipped
   past ILS-1/2/3 AND the challenge attesters disagree, the
   challenge-attester set is the next rotation candidate.

---

## Why this works without new code

Every move in this runbook composes existing primitives:

- **Step 1** uses `challenge_certificate` + `ChallengeRecord` PDA
  (AW-01-EXT.6 anchor) — the on-chain dispute flag IS the substrate.
- **Step 2** uses `issue_certificate` accepting `alert_tier` as input
  + the cluster-coordinator's `HELIXOR_FORCE_YELLOW_AGENTS` policy
  flag + FRP-3's 4h reissue cadence — the YELLOW alert is the
  cluster's normal issuance flow with a tier override.
- **Step 3** uses on-chain `challenge_state` reads (DBP-3 pattern) +
  SOL-3 per-operation freshness floors (DBP-3 SDK) + DBP-4
  cert-degrading webhook + courtesy notice — four layers, fired
  together.
- **Step 4** uses the existing audit-gate scripts + indexer Kafka
  log + TimescaleDB queries — the forensic trail is the operational
  data the cluster already records.

No new instruction. No new authority. No new attack surface. The
incident response IS the existing engineering substrate fired in
sequence, identical in shape to the oracle-key-compromise response
in `oracle_key_compromise_response.md`.
