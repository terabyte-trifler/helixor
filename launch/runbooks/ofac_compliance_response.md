# Runbook — OFAC sanctions / nation-state delist pressure response

**Severity:** Critical. A nation-state actor (or any sanctions regulator)
has pressured one or more oracle node operators to stop scoring a
specific AI-agent wallet — i.e. to silently delist it. The threat
model assumes the cluster itself is honest by majority but that
*individual operators* may be subject to home-jurisdiction court
orders compelling action against their will.

**Triggers:**
- Operator-of-record receives a formal sanctions / cease-and-desist
  notice naming a specific `agent_wallet`.
- Cluster operator informs the rest of the cluster that they are
  invoking the `RefusalGate.OPERATOR_OVERRIDE` path.
- `agent.cert_events.refused` Kafka topic shows a refusal whose
  `gate == "OPERATOR-OVERRIDE"` — i.e. the transparency substrate
  fired in production.
- Diversity gate (`audit/centralization_check.py`) flags that the
  cluster's declared `MIN_DISTINCT_JURISDICTIONS` floor has dropped
  to 1 — every operator is in one country and is jointly subject to
  one court's authority.
- `verify_attestation_signatures` raises `OperatorSignatureError`
  at boot — a captured cluster has tried to silently re-declare its
  jurisdiction without re-signing.

## What's happening

Helixor is, in the worst-case framing, *financial infrastructure that
scores AI agents*. A sufficiently motivated nation-state could:

  1. Identify which countries the 5 oracle node operators reside in.
  2. Issue a binding court order in those countries compelling the
     operators to refuse to issue certs for a named `agent_wallet`.
  3. Achieve a silent delist: certs simply stop being signed, the
     agent's tier ages out, every consumer fails closed, the agent
     is effectively excluded from the network — and no on-chain
     trace explains why.

The audit's framing is that we **do not try to defeat sanctions law**;
we make the act of complying with one visible, attributable, and
expensive. The four-pronged defence is:

  1. **Geographic + organisational diversity (HCR-4).** A single
     country's court order cannot reach `MIN_DISTINCT_JURISDICTIONS = 2`
     of the cluster. Below 3 cooperating operators, the 3-of-5
     threshold cannot sign — the cluster halts signing for everyone,
     not just the targeted agent. That makes the cost of a single
     country's order *protocol-wide* rather than *agent-specific*.
  2. **Cryptographic jurisdiction binding (OFAC-1).** Each operator
     signs the canonical bytes of their own attestation with the
     Ed25519 key whose pubkey they declare. A captured cluster cannot
     re-declare "US" as "SG" without possession of the original keys.
     Lying about jurisdiction now requires the same key compromise
     the rest of the protocol assumes the adversary cannot achieve.
  3. **Transparency substrate (OFAC-1).** Every refusal — including
     `RefusalGate.OPERATOR_OVERRIDE` — emits a `CertRefusal` event
     on the dedicated `Topic.CERT_REFUSED` Kafka topic. Silent delist
     is *mechanically impossible*; the refusal is visible to any
     subscriber, including external auditors and the targeted agent
     themselves.
  4. **Quorum collapse fallback.** If an operator is genuinely
     compelled by their home court, they revoke their participation
     (step 4 below). The cluster falls below the 3-of-5 threshold
     and signing halts FOR EVERYONE. The court has shut down the
     protocol, not delisted one agent.

This runbook is the *order* in which to fire these mechanics. Every
substrate already exists; the runbook ties them together.

---

## What we explicitly do NOT do

> **Anti-pattern:** add a `SanctionedAgentList` PDA on-chain.

The temptation is to write a canonical on-chain denylist that every
oracle node and Verified Integrator must respect. We deliberately
refuse this pattern for three reasons:

  1. **Permissionless invariant.** Helixor's architecture promises
     that any agent can be scored. An on-chain denylist requires an
     authority key to mutate, and an authority key is exactly the
     surface a nation-state would target NEXT. The minute we ship a
     denylist mutator, that key becomes the highest-value compromise
     target in the system.
  2. **Wrong layer.** Sanctions compliance is per-jurisdiction. A
     U.S. operator cannot lawfully serve an OFAC-SDN-listed wallet;
     a Singaporean operator may have no such restriction. Pushing
     compliance to the on-chain layer forces the *most restrictive*
     jurisdiction's view on every consumer, including those in
     jurisdictions where the listing does not apply. The right place
     for sanctions compliance is at the operator level (refuse to
     sign) and at the integrator level (refuse to honour, per their
     own counsel).
  3. **Silent delist becomes the default.** Once a denylist exists,
     the path of least resistance is "just add the wallet, no event,
     no audit trail." OFAC-1 is the opposite design: refusal is
     *louder* than acceptance because it emits a Kafka event with a
     pinned reason code.

If a future regulator mandates an on-chain denylist, that
conversation happens through the audit + governance process, not
through an incident-response runbook. As of this commit there is no
such mandate and no such on-chain surface.

---

## Step 1 — Confirm the diversity floor still binds

**Substrate:** `helixor-oracle/oracle/operator_manifest.py` HCR-4
gate with `MIN_DISTINCT_JURISDICTIONS = 2` and
`MIN_DISTINCT_OPERATORS = 2`, plus the new OFAC-1 Ed25519 sig binding.

  - `verify_operator_diversity(manifest)` raises
    `OperatorDiversityError` if either floor fails.
  - `verify_attestation_signatures(manifest)` raises
    `OperatorSignatureError` if any operator's declared pubkey,
    jurisdiction, org, or contact does not match the canonical bytes
    they signed (domain-tagged
    `helixor.operator_attestation.v1`).

**Procedure (responder, no Squads ceremony required):**

```bash
# A. Verify both gates pass on the current production manifest.
cd helixor-oracle
python -c "
import json
from oracle.operator_manifest import (
    OperatorAttestation, build_manifest,
    verify_operator_diversity, verify_attestation_signatures,
)
with open('deploy/operator_manifest.json') as f:
    atts = [OperatorAttestation(**a) for a in json.load(f)['attestations']]
manifest = build_manifest(atts, threshold=3)
print('diversity:', verify_operator_diversity(manifest))
print('signatures:', verify_attestation_signatures(manifest))
"
```

If `verify_attestation_signatures` raises: the manifest has been
tampered with. Treat as a key-compromise incident
(`launch/runbooks/oracle_key_compromise_response.md`) — an attacker
with operator-key access has tried to silently re-declare their
jurisdiction.

If `verify_operator_diversity` raises with
`MIN_DISTINCT_JURISDICTIONS` below the floor: the cluster topology
itself has converged to a single court's reach. This is a *boot*
failure, not a runtime one. Refuse to start the cluster until the
topology is restored. Adding an operator in a fresh jurisdiction is
a Squads-governed onboarding (step 5 below).

**Do NOT:**
- Lower `MIN_DISTINCT_JURISDICTIONS` to make the gate pass. The
  audit-pinned floor IS the load-bearing defence; lowering it is a
  silent regression of the OFAC-1 mitigation suite.
- Re-sign a captured operator's attestation with a new key. The
  signature binding is per-key; rotating that key is an `enact_oracle_key_rotation`
  Squads ceremony with the 48h `MIN_TIMELOCK_SECONDS`, NOT an in-line
  edit during incident response.

**Test pins:**
- `helixor-oracle/tests/oracle/test_hcr4_operator_diversity.py`
- `helixor-oracle/tests/oracle/test_hcr4_operator_signature.py`

---

## Step 2 — Emit the OPERATOR_OVERRIDE refusal (the transparency move)

**Substrate:** OFAC-1 `CertRefusalLog` in
`helixor-oracle/oracle/cert_refusal_log.py`, paired with
`Topic.CERT_REFUSED = "agent.cert_events.refused"` and the
`serialize_cert_refused` wire format in the indexer.

When a node operator is compelled to refuse signing for a specific
agent, they MUST call:

```python
from oracle.cert_refusal_log import operator_override

refusal = operator_override(
    agent_wallet=<base58>,
    epoch=<int>,
    requested_tier=<"GREEN"|"YELLOW"|"INSURED"|"NEW">,
    justification="<court-order ref + jurisdiction + UTC>",
)
log.append(refusal)
```

The `operator_override` factory **refuses an empty justification** —
`RefusalGate.OPERATOR_OVERRIDE` cannot fire without an attributable
written reason. The justification is opaque to the protocol but is
captured verbatim into the Kafka event.

**What happens downstream (no responder action):**

  1. The collected `CertRefusal` rows feed the per-epoch refusal log.
  2. The cluster's indexer-publisher reads the log and emits one
     `serialize_cert_refused(...)`-encoded event per refusal onto the
     `agent.cert_events.refused` topic (dedicated topic per VULN-14
     consumer-lag isolation — refusals never queue behind high-volume
     `agent.transactions` telemetry).
  3. Subscribers — including external auditors, the targeted agent's
     own monitoring, and any DeFi integrator running a refusal
     listener — see the event with a `gate == "OPERATOR-OVERRIDE"`
     marker, the canonical agent wallet, the requested tier, and the
     attributable justification.

The silent delist threat is *mechanically* defeated: a refusal that
does not emit on this topic is not a refusal the cluster issued.
Consumers can audit the difference between "no cert" (cluster halted)
and "refused cert" (specific agent is being delisted).

**Do NOT:**
- Skip the `CertRefusalLog.append(...)` call. The Kafka event is
  what the audit gate (`audit/cert_refusal_check.py`) verifies still
  exists; removing it makes the OFAC-1 mitigation invisible.
- Edit the `RefusalGate.OPERATOR_OVERRIDE` value string. The audit
  gate pins `"OPERATOR-OVERRIDE"` exactly — a rename without a
  coordinated downstream update breaks the on-bus contract.
- Backdate the `detected_at` timestamp. The serialiser normalises
  to UTC and pins the wire version; tampering with the timestamp
  is detectable by any subscriber holding the canonical Kafka log.

**Test pins:**
- `helixor-oracle/tests/oracle/test_ofac1_cert_refusal_log.py`
- `helixor-indexer/tests/test_ofac1_cert_refused_serialization.py`
- `audit/cert_refusal_check.py` (boot-time and CI audit gate)

---

## Step 3 — Below-quorum effect: refusal becomes protocol-wide halt

**Substrate:** the existing 3-of-5 threshold in
`programs/certificate-issuer/src/signing.rs` and the cluster's
auto-halt on signing failure.

If 3 or more operators receive simultaneous court orders for the
same `agent_wallet`, the cluster cannot meet the threshold and
**halts signing for everyone**, not just the targeted agent.

This is the *intentional* failure mode. The court has not
selectively delisted one wallet; it has shut down a piece of
financial infrastructure. That cost is:

  - Visible to every consumer (cert reissue does not happen → SOL-3
    freshness floors fire across the board → DBP-4 `cert.degrading`
    webhook fires at 36h).
  - Attributable on the Kafka log: every refusal carries the
    `OPERATOR_OVERRIDE` gate marker and the issuing-operator's
    justification.
  - Recoverable only by the court vacating the order or operators
    legitimately withdrawing (step 4).

The audit's framing: making the cost of a single agent's delist
*protocol-wide* is the disincentive. A nation-state pursuing a
single wallet does not want to pay the political cost of shutting
down a public credentialing protocol.

**Procedure (responder):**

  1. **Confirm the halt is observed by SOL-3 floors.** Within 4h,
     `LOAN_ISSUE` callers see `StaleCert` rejections from
     `SafeCertReader` (
     `helixor-sdk/src/safe_reader.ts`). Within 36h, the
     `cert.degrading` webhook fires to every Insured-tier
     subscriber (`launch/integrations/example_safe_partner/reader.ts`
     `LIQUIDATION_CHECK_MAX_AGE_SECONDS = 12*60*60`,
     `helixor-api/api/webhooks.py` `DEGRADING_THRESHOLD_FRACTION = 0.75`).
  2. **Post the incident notice** to the Verified Integrator
     channel referencing this runbook + the public Kafka log of
     refusals on `agent.cert_events.refused`. Partners that wire
     the refusal topic to their own monitoring already see the
     event; the notice is courtesy.
  3. **Do NOT** ship a hotfix that ignores the threshold or
     promotes a 2-of-N cluster. The threshold IS the defence.

---

## Step 4 — Operator-of-record withdrawal (if compelled to comply)

**Substrate:** `revoke_verified_consumer` with `PartnerSelfRevoke`
+ Squads `propose_oracle_key_rotation` / `enact_oracle_key_rotation`
(48h `MIN_TIMELOCK_SECONDS`).

If an individual operator concludes they MUST comply with their
home jurisdiction's order — and cannot do so within the OPERATOR_OVERRIDE
transparency channel without violating the order — the correct move
is to *exit the cluster*, not to silently delist:

```text
A. PROPOSE — Squads vault calls propose_oracle_key_rotation with:
     old_cluster_keys = [K0, K1, K2, K3, K4]      # current 5
     new_cluster_keys = [K0, K1, K3, K4]          # exiting operator (K2) removed
     new_threshold    = 3                         # unchanged
     unlock_at_unix   = now + 48h
     attestation_signers = K0, K1, K3, K4         # strict-majority gate
B. WAIT — 48h `MIN_TIMELOCK_SECONDS`. The cluster CONTINUES to sign
   during the timelock; the exiting operator can publish
   OPERATOR_OVERRIDE refusals for the targeted agent during this
   window so the on-bus trail is preserved.
C. ENACT — `enact_oracle_key_rotation`. Cluster size drops from 5
   to 4; threshold remains 3, so the cluster is now 3-of-4. A single
   further compromise drops below threshold → automatic halt.
D. RE-DECLARE — the cluster's `operator_manifest.json` is updated
   in the SAME PR that lands the new `IssuerConfig.cluster_keys`.
   Every remaining operator signs the NEW canonical attestation
   bytes with their key (the existing OFAC-1 sig binding still
   binds). `verify_attestation_signatures` must pass for the new
   manifest before the cluster reboots.
```

The exiting operator's home court has the outcome they ordered (no
cert issuance for the targeted agent FROM THIS OPERATOR). The
protocol has the outcome IT requires (transparent withdrawal, no
silent delist, threshold preserved for the remaining cluster).

**Do NOT:**
- Try to skip the 48h timelock. The on-chain
  `MIN_TIMELOCK_SECONDS = 48 * 60 * 60` is enforced by the program
  and is the same anchor that protects against forced
  oracle-key-compromise rotations. Bypassing it for a sanctions
  withdrawal would create a precedent for bypassing it under any
  other pretext.
- Rotate in a replacement operator in the same jurisdiction as
  the exiting one. The HCR-4 diversity floor would still be met
  (probably), but the *court-reach* defence is weakened.
- Promote the cluster to 2-of-4 to avoid below-threshold halts.
  `programs/certificate-issuer/src/signing.rs::tests` proptest
  pins the threshold lower bound; the program would reject the
  config.

**Test pins:**
- `helixor-programs/programs/health-oracle/tests/vuln13_oracle_key_rotation.rs`
- `helixor-oracle/tests/oracle/test_hcr4_operator_diversity.py`
- `helixor-oracle/tests/oracle/test_hcr4_operator_signature.py`

---

## After action

1. Add the incident to `audit/reports/ofac_compliance_<UTC>.md` with:
   - The `agent_wallet` named in the order.
   - The issuing-jurisdiction operator(s).
   - Each OPERATOR_OVERRIDE refusal event's Kafka offset + UTC
     timestamp (so external auditors can pull the canonical record).
   - Squads tx sigs for any propose/enact rotations.
   - The pre-incident and post-incident operator-manifest digests
     (`attestation_canonical_bytes` SHA-256).
2. Run the full audit gate suite:

   ```bash
   python3 audit/centralization_check.py
   python3 audit/cert_refusal_check.py
   python3 audit/forge_high_score_check.py
   python3 audit/consumer_integration_check.py
   ```

   All four should return 0 HARD findings.
3. Audit the OFAC-1 sig binding on the post-rotation manifest:
   `verify_attestation_signatures(manifest)` must pass with the
   reduced cluster.
4. Run a tabletop on the next jurisdiction's exposure. The
   post-incident cluster is closer to single-court reach by
   construction (one operator gone); plan the next onboarding
   BEFORE the next order.

---

## Why this works without new code

Every move in this runbook is a *composition* of primitives already
in the tree:

- **Step 1** is `verify_operator_diversity` + `verify_attestation_signatures`
  in `helixor-oracle/oracle/operator_manifest.py`. The HCR-4 diversity
  floor and the OFAC-1 Ed25519 binding together prevent both
  jurisdictional convergence and silent jurisdictional lying.
- **Step 2** is `cert_refusal_log.operator_override(...)` +
  `Topic.CERT_REFUSED` + `serialize_cert_refused` — the transparency
  substrate that turns a silent delist into a Kafka event with an
  attributable justification.
- **Step 3** is the existing 3-of-5 threshold in
  `programs/certificate-issuer/src/signing.rs` composing with SOL-3
  freshness floors and the DBP-4 `cert.degrading` webhook to make a
  joint-compulsion attack protocol-wide and visible.
- **Step 4** is `propose_oracle_key_rotation` + `enact_oracle_key_rotation`
  + the 48h on-chain timelock (VULN-13 anchor) for legitimate
  operator withdrawal.

No on-chain denylist. No sanctions-authority key. No new attack
surface. The compliance response IS the existing engineering
substrate fired in sequence, with the cost of a silent delist made
visible to every observer.
