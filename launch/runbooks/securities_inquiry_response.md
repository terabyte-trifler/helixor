# Runbook — Securities regulator inquiry response (SEC-1)

**Severity:** Low operationally, **high** if mishandled — a
securities regulator's inquiry (subpoena, no-action-letter
exchange, civil investigative demand, MAS direction, ESMA Article
17 request, SEBI summons, FCA s.165 notice) requires a calibrated
response that protects the cluster's posture as a *technical trust
signal provider* (not an investment adviser, broker-dealer, CRA, or
CASP) while honouring the regulator's authority over the operator-
of-record's home jurisdiction.

**Triggers:**
- Inbound subpoena, civil investigative demand (CID), or
  equivalent process from a securities regulator (SEC, CFTC, FCA,
  BaFin, ESMA-routed, SEBI, MAS, ASIC, etc.) naming Helixor, a
  cluster operator, or a specific `agent_wallet`.
- No-action letter request that proposes to characterise a Helixor
  cert score as a "rating" or "investment advice" — the operator
  must respond on the record.
- Direct inquiry from a regulator's enforcement or examinations
  desk asking about the cluster's compensation arrangements or
  operator conflicts.
- Operator-of-record observes a press / advocacy claim that
  Helixor "rates investments" and wants to file a clarifying
  record.

## What's happening

The audit-flagged risk SEC-1 closes is that DeFi protocols
consume Helixor cert scores to size loans, and an oracle operator
who has a financial interest in that outcome (performance fee,
TVL-tracking token, revenue share) starts to align with Howey
prong 4 ("derived solely from efforts of others"). The SEC-1
substrate (`helixor-oracle/oracle/securities_compliance.py`)
defends the posture mechanically:

  * `compensation_model` is closed-enum, today only
    `FLAT_FEE_PER_CERT_FROM_TREASURY` — sig-bound into the
    operator's attestation so a lie costs the same private-key
    compromise the rest of the protocol assumes the adversary
    cannot perform.
  * `conflicts_disclosed` is a sig-bound tuple of
    `(rated_wallet, relationship_type)` — operators enumerate
    their financial relationships with rated agents up front.
  * `ADVISORY_DISCLAIMER` ships verbatim with every SDK and
    integration-reader surface that returns a score.

This runbook is the operational sequence the operator-of-record
runs when a regulator engages.

---

## Step 1 — Classify the inbound

**Substrate:** the inbound channel published in
`launch/legal/securities_notice.md` §5 + the operator-of-record's
counsel.

**Procedure (operator-of-record):**

  1. Confirm the inbound is from a regulator with **proper
     authority over the operator-of-record's home jurisdiction**.
     The home jurisdiction is the ISO-3166 code in the operator's
     attestation (`OperatorAttestation.jurisdiction`,
     OFAC-1 sig-bound).
  2. Classify the inquiry. The four shapes the runbook covers:
     - **Subpoena / CID / s.165 notice** → §2 (records production).
     - **No-action letter / interpretive request** → §3 (posture
       statement).
     - **Examination or interview request** → §4 (operator-only
       response — does NOT bind the protocol).
     - **Cross-border inquiry** (regulator NOT in operator's
       jurisdiction) → §5 (forward without protocol action).
  3. Engage counsel BEFORE responding. SEC-1 is the substrate, not
     the legal posture; the operator's counsel decides what to
     disclose and how.
  4. Record the ticket ID — the runbook's audit log requires it.

**Do NOT:**
- Respond on behalf of the protocol or the cluster as a whole. Each
  operator is the legal recipient of process directed at them; the
  protocol is not a legal person. The operator-of-record speaks
  only for themselves.
- Promise to "delist" or refuse to score a specific agent off-the-
  record. Any such action goes through the OFAC-1 runbook
  (`launch/runbooks/ofac_compliance_response.md`) with the
  refusal logged on the `agent.cert_events.refused` topic and
  bound by the `OperatorOverride` gate. Off-record action breaks
  the transparency invariant the audit explicitly preserved.

---

## Step 2 — Records production (subpoena / CID)

**Substrate:** the operator's local records + the on-disk
attestation in `helixor-oracle/deploy/operator_manifest.json` + the
audit reports under `audit/reports/`.

**Procedure:**

  1. Counsel reviews the subpoena's specific records request.
  2. Identify the categories the request maps to:
     - **Operator attestation** —
       `helixor-oracle/deploy/operator_manifest.json` (sig-bound
       JSON with the operator's pubkey, org, jurisdiction,
       compensation model, conflicts disclosed).
     - **Compensation records** — the operator's local accounting
       for cert-issuance payments. The protocol does NOT centrally
       record per-cert payments; each operator's books are their
       own.
     - **Conflict disclosures** — `collect_disclosed_conflicts(
       manifest)` enumerates every operator's declared conflicts
       in canonical sort order. Run:

       ```bash
       cd /helixor && source helixor-api/.venv/bin/activate
       cd helixor-oracle
       python -c "
       import json
       from oracle.securities_compliance import collect_disclosed_conflicts
       from oracle.operator_manifest import build_manifest, OperatorAttestation
       # Load manifest from disk (operator deploy substrate)...
       # then:
       # print(json.dumps([
       #     {'node_id': nid, 'rated_wallet': c.rated_wallet,
       #      'relationship_type': c.relationship_type}
       #     for nid, c in collect_disclosed_conflicts(manifest)
       # ], indent=2, sort_keys=True))
       "
       ```

     - **DSAR audit log** (if the subpoena is for processing
       records of a named wallet) — see
       `launch/runbooks/data_subject_request_response.md` §5,
       under `/var/log/helixor/dsar/`.
     - **OFAC-1 refusal log** (if the subpoena is for cluster
       cert-issuance decisions about a named wallet) — see
       `launch/runbooks/ofac_compliance_response.md` §3,
       Kafka topic `agent.cert_events.refused`.
     - **Audit gate reports** — `audit/reports/securities_compliance.json`
       (the SEC-1 gate's most recent pass), generated by
       `python3 audit/securities_compliance_check.py --json
       audit/reports/securities_compliance.json`.

  3. Counsel reviews each category against the subpoena's scope.
     The operator-of-record does NOT auto-produce records beyond
     scope.
  4. Produce on the regulator's preferred channel (paper, encrypted
     email, secure portal). Counsel handles delivery.

**Statutory window:** varies by regulator (SEC subpoenas: 14–30
days typical; FCA s.165: 14 days; SEBI summons: as specified).
Operator-of-record SLA is the minimum of the regulator's window
and 14 days, measured from counsel-confirmed receipt.

**Do NOT:**
- Produce on behalf of other operators. Each operator's records
  are theirs. If the subpoena reaches other operators, they each
  follow this runbook independently.
- Edit the on-disk manifest before production. The manifest is
  sig-bound — re-signing would invalidate the OFAC-1 gate and
  create a worse problem (a fresh signature with the current
  date would falsely appear to be the as-of-incident state).
- Bypass the VULN-20 wallet-validation guard when running the
  conflict-enumeration helper. Malformed wallets are rejected at
  the substrate; do not lower the guard "just this once".

---

## Step 3 — No-action letter / interpretive request

**Substrate:** `launch/legal/securities_notice.md` + the SEC-1
substrate.

If a regulator (or a third party CC'ing the regulator) requests an
on-the-record characterisation of a Helixor cert score, the
operator-of-record's response **MUST** ground every claim in code,
not in marketing language. Specifically:

  - Cite `helixor-oracle/oracle/securities_compliance.py` for the
    closed-enum compensation model (`FLAT_FEE_PER_CERT_FROM_TREASURY`).
  - Cite `helixor-oracle/oracle/operator_manifest.py` for the
    sig-bound attestation surface (OFAC-1 + SEC-1 fields folded
    into `attestation_canonical_bytes`).
  - Cite `helixor-sdk/src/safe_reader.ts:ADVISORY_DISCLAIMER` for
    the disclaimer surfaced to every consumer.
  - Reference `audit/securities_compliance_check.py` as the
    mechanical regression alarm verifying the above.

The not-investment-advice / not-rating / not-IA posture is **not
a marketing claim** — it is a substrate property. The disclaimer
text in §1.1 of the public notice is the audit-stable version of
that posture.

**Procedure:**

  1. Counsel drafts the response with the substrate citations
     above.
  2. Counsel files on the regulator's preferred channel.
  3. The response is added to the operator's local records (§2
     production scope for any future subpoena).
  4. The public notice and substrate are NOT modified in response
     to a no-action request unless the regulator's reasoning
     concretely shows the substrate is misaligned with their
     framework. In that case the change is a §6 (change-control)
     event, not an inline edit.

**Do NOT:**
- Promise interpretive carve-outs the substrate doesn't enforce.
  If the response says "operators are never paid more than the
  flat-fee rate", that becomes the substrate's job to enforce —
  expanding `ALLOWED_COMPENSATION_MODELS` later requires
  revisiting the no-action posture.
- Send the public notice as a substitute for an on-the-record
  response. The notice is a starting point; counsel writes the
  letter.

---

## Step 4 — Examination or interview request

If the regulator requests an examination, deposition, or interview
of the operator-of-record:

  1. Counsel attends with the operator. The protocol does not
     attend.
  2. The interview record is operator-local. The protocol does
     not host transcripts.
  3. If the interview produces a record that the regulator
     publishes (e.g. an examination findings letter), the
     operator-of-record adds it to their local records and to
     the SEC-1 audit log for future §2 production.
  4. The operator-of-record does NOT speak on behalf of other
     operators or the cluster as a whole. Statements about the
     protocol's mechanical substrate are bounded to what the
     audit gate verifies — anything beyond that is the
     operator's personal view, clearly framed.

**Do NOT:**
- Speak about the cluster's overall posture without grounding
  in the SEC-1 substrate. "The cluster never pays performance
  fees" is a substrate claim (`ALLOWED_COMPENSATION_MODELS`).
  "The cluster has no conflicts" is unverifiable — what is
  verifiable is the conflict-disclosure substrate (every
  operator's `conflicts_disclosed` tuple is sig-bound and
  audit-visible).

---

## Step 5 — Cross-border inquiry

Inbound from a regulator whose jurisdiction does NOT cover the
operator-of-record's home jurisdiction follows the same
"forward, do not act" pattern as the OFAC-1 runbook §3:

  1. Acknowledge receipt to the inquiring regulator.
  2. Forward the inquiry to the regulator's mutual-legal-
     assistance channel in the operator's home jurisdiction
     (e.g. for an SEC inquiry reaching an EU-based operator,
     the operator forwards to BaFin / ESMA's IOSCO MMOU contact).
  3. Do NOT take protocol-level action. A foreign regulator's
     authority does not reach the operator's protocol activity
     directly; the MLA path is the regulator's correct path.

**Do NOT:**
- Delist a wallet, modify cert issuance, or alter operator
  behaviour in response to a foreign-regulator inquiry without
  the operator's home-jurisdiction process catching up. That
  is exactly the silent-delist failure mode OFAC-1 was built to
  surface — handle it under OFAC-1's runbook, not silently.

---

## Step 6 — Audit log

**Substrate:** `/var/log/helixor/securities/<ticket_id>.json`.

Every SEC-1 inquiry (subpoena, no-action, examination, cross-
border forward) emits one canonical-JSON line. The operator-of-
record runbook pins:

  - **Path:** `/var/log/helixor/securities/<ticket_id>.<op>.json`
    where `<op>` is one of `subpoena`, `noaction`, `exam`,
    `forward`.
  - **Schema:**

    ```json
    {
      "wire_version": 1,
      "ticket_id": "<operator-local>",
      "regulator": "<short identifier, e.g. SEC, FCA, SEBI>",
      "operation": "subpoena|noaction|exam|forward",
      "filed_at": "<UTC ISO8601 with Z suffix>",
      "operator_node_id": "<node_id from manifest>",
      "operator_jurisdiction": "<ISO-3166 alpha-2>",
      "substrate_citations": [
        "<short label of the cited code module>",
        ...
      ],
      "outcome": "produced|filed|in_progress|forwarded"
    }
    ```

  - **Retention:** indefinite at the operator. Same posture as
    DSAR audit logs — regulators may audit response records years
    later.
  - **Backup:** operator's standard backup rotation. NOT the
    indexer's PITR.
  - **Read access:** operator-of-record + counsel.

The audit log is operator-local; it is NOT shared between
operators by default. Each operator's regulator inquiries are
their own.

---

## Step 7 — Verify the post-inquiry state

After a subpoena / no-action exchange, run the SEC-1 gate to
confirm the substrate did not drift during response:

```bash
python3 audit/securities_compliance_check.py --json /tmp/sec1.json
cat /tmp/sec1.json | jq '.summary'
# Should report hard_findings = 0.
```

If `hard_findings > 0`, an inline substrate edit happened during
response — investigate before continuing.

For a no-action exchange that produced an interpretive change,
verify the public notice was updated as a §6 change-control event
(not an inline edit):

```bash
git log -1 -- launch/legal/securities_notice.md
```

The commit should reference the no-action ticket and pass the
audit gate before being merged.

---

## After action

1. Close the inbound with counsel's response.
2. File the audit-log entry per §6.
3. If the inquiry produced a posture change, schedule a 30-day
   follow-up to confirm the SEC-1 audit gate is still green:

   ```bash
   python3 audit/securities_compliance_check.py
   ```

4. If the inquiry came from a jurisdiction not currently listed
   in `launch/legal/securities_notice.md` §4, flag the notice for
   a §6 update — a new regime may need explicit coverage.

---

## Why this works without new code

Every move in this runbook is a *composition* of primitives
already in the tree:

- **Step 1** is the operator's existing ticketing system + the
  SEC-1 `OperatorAttestation.jurisdiction` field (OFAC-1 sig-
  bound) — no protocol change.
- **Step 2** is the operator's local records + the
  `collect_disclosed_conflicts` helper + the existing DSAR /
  OFAC-1 audit logs. No new endpoint, no new authority key.
- **Step 3** grounds posture statements in the substrate the
  audit gate verifies. The disclaimer string is single-source-of-
  truth in `securities_compliance.py`.
- **Step 4** is operator-of-record + counsel; the protocol does
  not host the interview.
- **Step 5** mirrors the OFAC-1 §3 cross-border posture — refuse
  silent protocol-level action, route through MLA.
- **Step 6** is a canonical-JSON line in
  `/var/log/helixor/securities/` — same operator-local audit
  pattern the DSAR runbook uses.
- **Step 7** is the same SEC-1 audit gate replayed.

No on-chain action. No protocol-level legal personhood. The
compliance path IS the existing engineering substrate read in
sequence, with operator-jurisdiction process honoured by each
operator independently.
