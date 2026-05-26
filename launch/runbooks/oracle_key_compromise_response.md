# Runbook — Oracle Key Compromise incident response

**Severity:** Catastrophic. A cluster signing key (any of the 5 oracle
nodes' Ed25519 keys) is believed compromised, exfiltrated, or under
adversarial control.

**Triggers:**
- Operator-of-record reports a node's HSM seal was broken / KMS audit
  log shows unauthorised access.
- Continuous-monitoring (NSS-2 `signer_enforcement`) sees an
  `InProcessSigner` classification on a node that should be HSM-only.
- The threshold-signature audit gate (`audit/forge_high_score_check.py`)
  flags a key past the 90-day NIST SP 800-57 cryptoperiod ceiling
  (`MAX_KEY_AGE_SECONDS = 90 * 24 * 3600`) AND that key signed a cert
  whose payload contradicts independently observable on-chain inputs.
- Out-of-band attacker disclosure / bug bounty notification.

## What's happening

A cluster key compromise is the **1a** sub-leaf of red-team Path 1
(Forge High-Score Cert), but elevated to runtime: the attacker doesn't
need to find a key — they already have one. The other K−1 keys still
gate cert forgery (3-of-5 means a single compromised key cannot mint a
cert alone), so the immediate failure is NOT cert forgery but the
*next* compromise. Time is the adversary's resource here: every hour
the compromised key remains in `IssuerConfig.cluster_keys` is another
hour to compromise a second key.

The audit's incident-response strategy is four sequential moves:

  1. Remove the compromised key from `cluster_keys` via Squads + the
     on-chain rotation flow.
  2. Annotate any certs the compromised key signed as taint-suspect.
  3. Re-issue current-epoch certs under the new (now 4-key) cluster.
  4. Signal Verified Integrators to pause until the audit closes.

Every move below is mechanical: the substrate already exists on-chain
and in the cluster software. This runbook is the *order* in which to
fire them.

---

## Step 1 — Remove the compromised key via Squads

**Substrate:** the two-step propose / enact rotation flow on
`health-oracle`, both gated by the Squads vault.

  - `helixor-programs/programs/health-oracle/src/instructions/propose_oracle_key_rotation.rs`
  - `helixor-programs/programs/health-oracle/src/instructions/enact_oracle_key_rotation.rs`
  - `helixor-programs/programs/health-oracle/src/state/pending_oracle_rotation.rs`
    pins `MIN_TIMELOCK_SECONDS = 48 * 60 * 60` (48-hour minimum
    between propose and enact).

**Procedure (operator-of-record, signed Squads tx):**

```text
A. PROPOSE — Squads vault calls propose_oracle_key_rotation with:
     old_cluster_keys = [K0, K1, K2, K3, K4]       # current 5
     new_cluster_keys = [K0, K1, K3, K4, K_new]    # K2 removed,
                                                   # K_new replaces it
     new_threshold    = 3                          # unchanged
     unlock_at_unix   = now + 48h                  # MIN_TIMELOCK_SECONDS
     attestation_signers = K0, K1, K3, K4          # strict-majority gate
B. WAIT — 48h timelock. During the wait:
     - operators-of-record audit their HSM seals
     - the cluster CONTINUES to sign certs with the compromised set;
       the threshold (3-of-5) still protects against single-key forgery
     - if a second compromise is suspected, abort and re-propose with
       BOTH keys removed
C. ENACT — Squads vault calls enact_oracle_key_rotation. The
   on-chain VULN-13 anchor (FHS-3 `MAX_KEYS_REPLACED_PER_ROTATION = 1`)
   refuses wholesale replacement; one-key swaps pass.
```

**Verify the rotation took:**

```bash
# Inspect the on-chain IssuerConfig and OracleConfig
anchor account IssuerConfig --address <CFG_PDA>
# Confirm cluster_keys no longer contains K2.
```

**Do NOT:**
- Try to skip the 48h timelock. `MIN_TIMELOCK_SECONDS` is on-chain;
  any short-circuit attempt by an authority key fails closed.
- Lower the threshold below 3-of-N. The proptest harness in
  `programs/certificate-issuer/src/signing.rs::tests` machine-checks
  the spec; a config with `threshold = 0` would be rejected at config
  init.

**Test pin:** `programs/health-oracle/tests/vuln13_oracle_key_rotation.rs`
asserts `MIN_TIMELOCK_SECONDS == 172_800` and the FHS-3 overlap guard.

---

## Step 2 — Annotate certs signed by the compromised key

**Substrate:** the `VerifiedConsumer` revoke-flow (`Active → Revoked`)
in `programs/certificate-issuer/src/instructions/revoke_verified_consumer.rs`.
The account is **never closed** so the audit trail (`revoked_at_unix`,
`revoked_by`, `revoke_reason`) persists permanently on-chain.

Certs themselves are not individually closable (they live on the
`HealthCertificate` PDA and are overwritten by the next issue), but
two complementary annotations make a key-compromise window auditable
on-chain:

**2a. Revoke any Verified Integrator the compromised key on-boarded**

If the compromised key was used to sign the registration of a partner
(`VerifiedConsumerState.Active`), call:

```text
revoke_verified_consumer(
    integration_hash = <hash from registration>,
    reason           = RevokeReason.AdminBadFaith,   # post-incident audit
)
```

Reason codes (`programs/certificate-issuer/src/state/verified_consumer.rs`):

| Code | Name                | Use                                              |
|------|---------------------|--------------------------------------------------|
| 0    | NotRevoked          | sentinel — never written                         |
| 1    | PartnerSelfRevoke   | partner walked away                              |
| 2    | AdminBadFaith       | post-incident; cluster admin revokes             |
| 3    | AdminTerminated     | partnership terminated (not bad faith)           |

`AdminBadFaith` is the correct code for a post-compromise revoke: it
flags the badge as "do not honour" without claiming the partner itself
acted in bad faith.

**2b. Pin the compromise window in the audit trail**

Append to `audit/reports/oracle_key_compromise_<UTC_DATE>.md` (this
file is created by the responder; the repo already tracks similarly-
shaped incident records under `audit/reports/`). Include:

```text
- compromised_key:   K2 = <base58>
- discovered_at:     <UTC>
- last_known_clean:  <UTC>   # from HSM audit log
- rotation_proposed: <UTC>   # Squads tx sig
- rotation_enacted:  <UTC>   # Squads tx sig
- certs_in_window:   list of (agent, epoch, score) the cluster issued
                     while the key was in cluster_keys but suspect
- annotation_action: see step 3 below — fresh certs supersede stale
```

Any DeFi integrator running the FHS-1b cross-check (replay the
verifier against the canonical digest) will automatically refuse certs
whose declared signers don't intersect the post-rotation cluster.

**Test pin:** `helixor-sdk/test/verified_consumer.test.ts` exercises
the `Active → Revoked` transition and the layout-pinned decode.

---

## Step 3 — Re-issue current-epoch certs under the new cluster

**Substrate:** FRP-3 cluster-side cert-reissue cadence floor.

`helixor-oracle/oracle/cert_reissue_cadence.py` pins
`MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600` (4 hours). The cluster
re-signs every active agent's cert at least every 4 hours, REGARDLESS
of whether the score changed. After the rotation enacts in step 1,
those reissues are produced by the new 4+1 cluster and signed under
the new `IssuerConfig.cluster_keys` (which the on-chain
`verify_threshold_signatures` reads at handler time, so no program
upgrade is needed).

**Procedure:** none. The reissue is mechanical.

| t (since enact) | What the cluster does                                  |
|-----------------|--------------------------------------------------------|
| 0h              | enact_oracle_key_rotation lands; new keys are on-chain |
| 0–4h            | next epoch tick produces fresh certs signed by K_new   |
| 4h              | FRP-3 floor is satisfied for every active agent        |
| 12h             | LIQUIDATION_CHECK callers (SOL-3) start refusing stale |
| 48h             | LOAN_ISSUE / STATUS_READ callers fail-closed on stale  |

**Verify the reissue propagated:**

```bash
# For each active agent, the cluster's most recent cert should carry
# `signers` (off-chain telemetry) intersecting the new cluster_keys.
helixor-oracle-cli cert latest --agent <pubkey> | jq '.signers'
# Should NOT include the rotated-out key.
```

**Do NOT:**
- Try to lower the FRP-3 floor to "push" reissues faster — the floor
  is a *minimum cadence* (re-sign at least every 4h), not a maximum;
  the cluster is free to reissue immediately on epoch advance.
- Add a one-shot `force_reissue_all_active_agents` instruction. The
  cadence floor already produces the same effect within 4h and adds
  no new instruction surface (and no new attack surface). A forced-
  reissue ix is on the LONG-TERM roadmap as a *visibility* feature,
  not a correctness one.

**Test pin:** `helixor-oracle/tests/oracle/test_frp3_cert_reissue_cadence.py`.

---

## Step 4 — Pause Verified Integrators until audit closes

**Substrate:** DBP-4 cert-degrading webhook + SOL-3 per-operation
freshness floors in `SafeCertReader`.

If the cluster *suspends* cert issuance entirely (e.g. operators
decide the safe move during audit is to not re-sign), the existing
freshness floors fire in cascade across every Verified Integrator,
WITHOUT any new on-chain or off-chain action:

| t (since last cert) | Effect on integrators                            |
|---------------------|--------------------------------------------------|
| 0–4h                | LOAN_ISSUE / LOAN_INCREASE callers proceed       |
| 4h                  | `LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 60 * 60` →     |
|                     | LOAN_ISSUE callers fail-closed                   |
| 8h                  | LOAN_INCREASE callers fail-closed                |
| 12h                 | LIQUIDATION_CHECK callers fail-closed            |
| 36h                 | `cert.degrading` webhook fires to all Insured-   |
|                     | tier subscribers (DBP-4d threshold = 0.75 * 48h) |
| 48h                 | STATUS_READ callers fail-closed; every consumer  |
|                     | is now stale                                     |

**Procedure (responder):**

1. **Confirm the cluster is in halt-issuance state.** Check
   `helixor-oracle-cli cluster status` — `signing.suspended == true`.
2. **Post the incident notice** to the Verified Integrator channel
   (the email / Slack list maintained alongside `HELIXOR_WEBHOOKS`).
   The notice should reference this runbook section and the expected
   resume time. The notice is courtesy; the freshness floors are the
   binding mechanism.
3. **Wait for the DBP-4 webhook to fire.** Within 36h, every Insured-
   tier subscriber receives a `cert.degrading` event signed by HMAC-
   SHA256 with their per-partner secret
   (`helixor-api/api/webhooks.py:SIGNATURE_HEADER`). Partners that
   wire this event to their own monitoring see a pause signal even if
   they missed the courtesy notice.
4. **After audit completes** and step 1 has rotated the compromised
   key out: the cluster resumes signing. FRP-3 reissues fresh certs
   within 4h (step 3). Every `SafeCertReader` returns `{ok: true}` on
   the next read; no integrator action needed.

**Do NOT:**
- Try to add a global `protocol.frozen` flag or on-chain pause
  instruction during an incident. The existing primitives compose to
  the same outcome (stale certs ⇒ fail-closed ⇒ webhook), and adding
  a pause-authority key during the incident creates a *new*
  high-value target. The frozen-flag webhook event is on the
  LONG-TERM roadmap as additive surface, not a replacement.
- Reach into partners' callers to disable their integrations. The
  SafeCertReader is doing exactly its job by failing closed.
- Lift the cluster's signing halt until step 1 enacts.

**Anchor pins:**
- `helixor-sdk/src/safe_reader.ts` — `SafeCertReader` reject reasons
  (`StaleCert`, `VelocityExceeded`, `InsufficientHistory`).
- `launch/integrations/example_safe_partner/reader.ts` — SOL-3
  per-operation freshness floors:
  `LOAN_ISSUE_MAX_AGE_SECONDS = 4*60*60`,
  `LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12*60*60`.
- `helixor-api/api/webhooks.py` — `DEGRADING_THRESHOLD_FRACTION = 0.75`
  fires the `cert.degrading` event at 36h.

**Test pins:**
- `helixor-sdk/test/safe_reader.test.ts` — reject-reason coverage.
- `helixor-api/tests/test_dbp4_webhooks.py` — webhook trigger fires
  inside the age window and dedupes per (partner, agent, epoch).

---

## After action

1. Add the incident to `audit/reports/oracle_key_compromise_<UTC>.md`
   with timestamps for each of the 4 steps and the Squads tx sigs.
2. Run the full audit gate suite:

   ```bash
   python3 audit/forge_high_score_check.py
   python3 audit/centralization_check.py
   python3 audit/consumer_integration_check.py
   python3 audit/supply_chain_check.py
   ```

   All four should return 0 HARD findings.
3. Audit the HSM provenance trail for the OTHER 4 keys. The
   compromise may have been a probe, not the goal.
4. Run a tabletop on what the *next* compromise would look like.
   The 4-key cluster (post-rotation) is now `4-1-of-4 = 3-of-4`; a
   single further compromise drops the cluster below threshold and
   freezes signing automatically. Plan the second rotation BEFORE
   the second compromise.

---

## Why this works without new code

Every move in this runbook is a *composition* of primitives already
in the tree:

- **Step 1** uses `propose_oracle_key_rotation` + `enact_oracle_key_rotation`
  + the 48h on-chain timelock (VULN-13 anchor).
- **Step 2** uses `revoke_verified_consumer` with `AdminBadFaith`
  (DBP-2 anchor) for any partner the compromised key on-boarded, and
  appends to `audit/reports/` for the cert-window record.
- **Step 3** is the FRP-3 4h cadence floor running its normal loop —
  it doesn't even know a rotation happened; it just signs fresh
  certs with whatever `IssuerConfig.cluster_keys` says NOW.
- **Step 4** is the SOL-3 per-operation freshness floors + DBP-4
  cert-degrading webhook composing into a graceful integrator pause.

No new instruction. No new authority. No new attack surface. The
incident response IS the existing engineering substrate fired in
sequence.
