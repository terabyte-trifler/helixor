# Runbook — AML/KYC complaint & regulator inquiry response (AML-1)

**Severity:** Low operationally, **high** if mishandled — an
AML/KYC regulator inquiry (FinCEN inquiry, ESMA / national-FIU
mutual-evaluation questionnaire, PMLA enquiry under §50 of the Act,
SG MAS direction, FATF mutual-evaluation team request) or a
formal AML complaint requires a calibrated response that protects
the cluster's posture as a *technical trust signal provider* (not a
VASP, MSB, CASP, custodian, or transmitter) while honouring the
regulator's authority over the operator-of-record's home
jurisdiction.

**Triggers:**
- Inbound formal inquiry from an AML regulator or FIU (FinCEN,
  FCA AML unit, BaFin AML division, FIU-IND, MAS AML division,
  AUSTRAC, etc.) naming Phylanx, a cluster operator, or a specific
  `agent_wallet`.
- FATF mutual-evaluation questionnaire about the operator-of-
  record's home-jurisdiction VASP landscape that names Phylanx.
- AML/KYC complaint filed with any regulator or FIU referencing
  Phylanx — even if the regulator has not yet opened an inquiry.
- Press / advocacy claim that "Phylanx enables unscreened AI agent
  lending" that the operator-of-record wants to file a clarifying
  record about.
- SAR-equivalent (Suspicious Activity Report) third-party query
  asking whether the cluster filed or should have filed.

## What's happening

The audit-flagged risk AML-1 closes is that large-scale AI agent
lending enabled by Phylanx certs may trigger AML compliance
requirements for DeFi protocols, creating a regulatory attack
surface that adversaries can exploit via regulatory complaints.
The AML-1 substrate (`phylanx-oracle/oracle/aml_compliance.py`)
defends the posture mechanically:

  * `AmlProgramAttestation` is closed-enum, today either
    `NO_AML_PROGRAM_REQUIRED_FOR_PHYLANX_ACTIVITY` or
    `EXTERNAL_AML_PROGRAM_DECLARED` — sig-bound into the
    operator's attestation so a lie costs the same private-key
    compromise the rest of the protocol assumes the adversary
    cannot perform.
  * `_KYC_FORBIDDEN_FIELDS` + `assert_no_kyc_fields(name)` raise
    `KycFieldRefusedError` if any future `DataCategory` (DP-1)
    field grows a KYC shape (`LEGAL_NAME`, `SSN`, `PASSPORT`,
    `STREET_ADDRESS`, `BANK_ACCOUNT`, `IBAN`, …).
  * `AML_KYC_DISCLAIMER` ships verbatim with every SDK and
    integration-reader surface that returns a score.

This runbook is the operational sequence the operator-of-record
runs when a regulator, FIU, FATF team, or complainant engages.

---

## Step 1 — Classify the inbound

**Substrate:** the inbound channel published in
`launch/legal/aml_kyc_notice.md` §5 + the operator-of-record's
counsel.

**Procedure (operator-of-record):**

  1. Confirm the inbound is from a regulator / FIU with **proper
     authority over the operator-of-record's home jurisdiction**.
     The home jurisdiction is the ISO-3166 code in the operator's
     attestation (`OperatorAttestation.jurisdiction`,
     OFAC-1 sig-bound).
  2. Classify the inquiry. The five shapes the runbook covers:
     - **Formal regulator inquiry / FIU production order** → §2
       (records production).
     - **Posture / interpretive question** → §3 (substrate-grounded
       reply).
     - **FATF mutual-evaluation questionnaire** → §4 (operator-only
       response — does NOT bind the protocol).
     - **Cross-border inquiry** (regulator NOT in operator's
       jurisdiction) → §5 (forward without protocol action).
     - **Adversarial / boilerplate complaint** (no regulator
       enquiry yet) → §6 (substrate-citation reply, no protocol
       action).
  3. Engage counsel BEFORE responding. AML-1 is the substrate, not
     the legal posture; the operator's counsel decides what to
     disclose and how.
  4. Record the ticket ID — the runbook's audit log requires it.

**Do NOT:**
- Respond on behalf of the protocol or the cluster as a whole. Each
  operator is the legal recipient of process directed at them; the
  protocol is not a legal person. The operator-of-record speaks
  only for themselves.
- File a SAR-equivalent report "to be safe". The cluster is not a
  reporting entity under any of the regimes catalogued in
  `launch/legal/aml_kyc_notice.md` §4. A precautionary SAR would
  itself misrepresent the cluster's posture.
- Promise to "delist" or refuse to score a specific agent off-the-
  record. Any such action goes through the OFAC-1 runbook
  (`launch/runbooks/ofac_compliance_response.md`) with the
  refusal logged on the `agent.cert_events.refused` topic and
  bound by the `OperatorOverride` gate.

---

## Step 2 — Records production (regulator inquiry / FIU order)

**Substrate:** the operator's local records + the on-disk
attestation in `phylanx-oracle/deploy/operator_manifest.json` + the
audit reports under `audit/reports/`.

**Procedure:**

  1. Counsel reviews the production order's specific records
     request.
  2. Identify the categories the request maps to:
     - **Operator attestation** —
       `phylanx-oracle/deploy/operator_manifest.json` (sig-bound
       JSON with the operator's pubkey, org, jurisdiction,
       compensation model, conflicts disclosed, and the AML-1
       `aml_program_attestation` field).
     - **AML attestation enumeration** —
       `collect_aml_attestations(manifest)` returns every
       operator's declared AML posture in canonical sort order.
       Run:

       ```bash
       cd /phylanx && source phylanx-api/.venv/bin/activate
       cd phylanx-oracle
       python -c "
       import json
       from oracle.aml_compliance import collect_aml_attestations
       # Load the operator manifest from disk first, then:
       # print(json.dumps([
       #     {'node_id': nid, 'aml_program_attestation': att}
       #     for nid, att in collect_aml_attestations(manifest)
       # ], indent=2, sort_keys=True))
       "
       ```

     - **DSAR audit log** (if the inquiry is for processing
       records of a named wallet) — see
       `launch/runbooks/data_subject_request_response.md` §5,
       under `/var/log/phylanx/dsar/`.
     - **OFAC-1 refusal log** (if the inquiry is for cluster
       cert-issuance decisions about a named wallet) — see
       `launch/runbooks/ofac_compliance_response.md` §3,
       Kafka topic `agent.cert_events.refused`.
     - **Audit gate reports** — `audit/reports/aml_compliance.json`
       (the AML-1 gate's most recent pass), generated by
       `python3 audit/aml_compliance_check.py --json
       audit/reports/aml_compliance.json`.
     - **DP-1 DataCategory snapshot** — proof of the KYC-field
       guard: the inquiry will sometimes ask "what personal data
       does Phylanx process?", and the answer is the
       `DataCategory` enum in
       `phylanx-oracle/oracle/data_protection_policy.py`. The AML-1
       gate verifies this is KYC-clean.

  3. Counsel reviews each category against the inquiry's scope.
     The operator-of-record does NOT auto-produce records beyond
     scope.
  4. Produce on the regulator's preferred channel (paper, encrypted
     email, secure portal). Counsel handles delivery.

**Statutory window:** varies by regulator (FinCEN 314(a)/(b)
requests: 14 days; FCA s.165 notices: 14 days; FIU-IND
production: as specified; MAS direction: as specified; FATF
mutual-evaluation: typically 30–60 days). Operator-of-record SLA
is the minimum of the regulator's window and 14 days, measured
from counsel-confirmed receipt.

**Do NOT:**
- Produce on behalf of other operators. Each operator's records
  are theirs. If the inquiry reaches other operators, they each
  follow this runbook independently.
- Edit the on-disk manifest before production. The manifest is
  sig-bound — re-signing would invalidate the OFAC-1 gate and
  create a worse problem (a fresh signature with the current
  date would falsely appear to be the as-of-incident state).
- Bypass the VULN-20 wallet-validation guard when running the
  AML-attestation enumeration helper. Malformed wallets are
  rejected at the substrate; do not lower the guard "just this
  once".

---

## Step 3 — Posture / interpretive request

**Substrate:** `launch/legal/aml_kyc_notice.md` + the AML-1
substrate.

If a regulator (or a third party CC'ing the regulator) requests an
on-the-record characterisation of whether Phylanx cluster activity
is a covered activity under their AML regime, the operator-of-
record's response **MUST** ground every claim in code, not in
marketing language. Specifically:

  - Cite `phylanx-oracle/oracle/aml_compliance.py` for the
    closed-enum `AmlProgramAttestation`
    (`NO_AML_PROGRAM_REQUIRED_FOR_PHYLANX_ACTIVITY` /
    `EXTERNAL_AML_PROGRAM_DECLARED`) and the
    `_KYC_FORBIDDEN_FIELDS` guard.
  - Cite `phylanx-oracle/oracle/operator_manifest.py` for the
    sig-bound attestation surface (OFAC-1 + SEC-1 + AML-1 fields
    folded into `attestation_canonical_bytes`).
  - Cite `phylanx-sdk/src/safe_reader.ts:AML_KYC_DISCLAIMER` for
    the disclaimer surfaced to every consumer.
  - Reference `audit/aml_compliance_check.py` as the mechanical
    regression alarm verifying the above.

The not-a-VASP / not-a-CASP / not-an-MSB / no-Travel-Rule posture
is **not a marketing claim** — it is a substrate property. The
disclaimer text in §1.1 of the public notice is the audit-stable
version of that posture.

**Procedure:**

  1. Counsel drafts the response with the substrate citations
     above.
  2. Counsel files on the regulator's preferred channel.
  3. The response is added to the operator's local records (§2
     production scope for any future inquiry).
  4. The public notice and substrate are NOT modified in response
     to a posture request unless the regulator's reasoning
     concretely shows the substrate is misaligned with their
     framework. In that case the change is a §6 (change-control)
     event in `launch/legal/aml_kyc_notice.md`, not an inline
     edit.

**Do NOT:**
- Promise interpretive carve-outs the substrate doesn't enforce.
  If the response says "the cluster will never ingest customer-
  identity fields", that posture is already enforced by
  `assert_no_kyc_fields()` — say so by citation, don't promise it
  in prose.
- Send the public notice as a substitute for an on-the-record
  response. The notice is a starting point; counsel writes the
  letter.

---

## Step 4 — FATF mutual-evaluation / examination request

If a FATF mutual-evaluation team (or a national-FIU equivalent)
requests an examination, deposition, or interview of the
operator-of-record:

  1. Counsel attends with the operator. The protocol does not
     attend.
  2. The interview record is operator-local. The protocol does
     not host transcripts.
  3. If the evaluation produces a record that the team publishes
     (e.g. a mutual-evaluation findings letter), the operator-of-
     record adds it to their local records and to the AML-1 audit
     log for future §2 production.
  4. The operator-of-record does NOT speak on behalf of other
     operators or the cluster as a whole. Statements about the
     protocol's mechanical substrate are bounded to what the
     audit gate verifies — anything beyond that is the operator's
     personal view, clearly framed.

**Do NOT:**
- Speak about the cluster's overall posture without grounding
  in the AML-1 substrate. "The cluster does no KYC" is a
  substrate claim (`_KYC_FORBIDDEN_FIELDS`). "No operator
  launders" is unverifiable — what is verifiable is that the
  cluster has no value-transmission surface a launderer could
  use, and that every operator's AML-program-attestation is
  sig-bound and audit-visible.

---

## Step 5 — Cross-border inquiry

Inbound from a regulator whose jurisdiction does NOT cover the
operator-of-record's home jurisdiction follows the same
"forward, do not act" pattern as the OFAC-1 runbook §3 and the
SEC-1 runbook §5:

  1. Acknowledge receipt to the inquiring regulator.
  2. Forward the inquiry to the regulator's mutual-legal-
     assistance channel in the operator's home jurisdiction
     (e.g. for a FinCEN inquiry reaching an EU-based operator,
     the operator forwards to the EU FIU's Egmont Group contact
     in their home jurisdiction).
  3. Do NOT take protocol-level action. A foreign regulator's
     authority does not reach the operator's protocol activity
     directly; the MLA / Egmont path is the regulator's correct
     path.

**Do NOT:**
- Delist a wallet, modify cert issuance, or alter operator
  behaviour in response to a foreign-regulator inquiry without
  the operator's home-jurisdiction process catching up. That
  is exactly the silent-delist failure mode OFAC-1 was built to
  surface — handle it under OFAC-1's runbook, not silently.

---

## Step 6 — Adversarial / boilerplate complaint

The AML-1 risk model explicitly includes the **process-tax
complaint vector**: an adversary files a boilerplate AML/KYC
complaint with a regulator naming Phylanx, hoping the
regulator-response cost itself becomes a DoS. The substrate is
already built so the complaint dies at intake.

**Procedure:**

  1. The operator-of-record (or anyone reading the complaint)
     compares the complaint's claim against the substrate
     citation set in §3 of this runbook. The four canonical
     positions to confirm:
     - Cluster does not custody / transmit / exchange value (§1
       of the public notice).
     - Cluster does not collect customer-identity fields
       (`_KYC_FORBIDDEN_FIELDS`).
     - Each operator's AML posture is sig-bound (§2 of the
       public notice).
     - The disclaimer ships with every consumer-facing score
       surface (`AML_KYC_DISCLAIMER`).
  2. If the complaint stays at the boilerplate level (no
     regulator inquiry has opened): the operator-of-record
     records the complaint in the AML-1 audit log (§7) and
     prepares a substrate-citation reply for the regulator to
     close the file at intake.
  3. If the complaint escalates to a formal regulator inquiry,
     drop into §2 or §3 above.
  4. The operator-of-record does NOT publicly engage with the
     complainant on social media or in the press in lieu of the
     regulator-facing reply. Public counter-statements are
     counsel-mediated.

**Do NOT:**
- Treat a boilerplate complaint as proof of substrate failure.
  The complaint is a *cost-imposing move*; the substrate is the
  defense. The audit gate ensures the defense still holds.
- Modify the substrate (e.g. add a "KYC field" defensively) in
  response to a complaint. Doing so would weaken the
  not-covered-activity posture exactly when the regulator is
  most likely to scrutinise it.

---

## Step 7 — Audit log

**Substrate:** `/var/log/phylanx/aml/<ticket_id>.<op>.json`.

Every AML-1 inquiry (regulator inquiry, FIU production, FATF
evaluation, cross-border forward, boilerplate complaint) emits
one canonical-JSON line. The operator-of-record runbook pins:

  - **Path:** `/var/log/phylanx/aml/<ticket_id>.<op>.json`
    where `<op>` is one of `inquiry`, `production`,
    `posture`, `evaluation`, `forward`, `complaint`.
  - **Schema:**

    ```json
    {
      "wire_version": 1,
      "ticket_id": "<operator-local>",
      "regulator": "<short identifier, e.g. FinCEN, FCA, FIU-IND>",
      "operation": "inquiry|production|posture|evaluation|forward|complaint",
      "filed_at": "<UTC ISO8601 with Z suffix>",
      "operator_node_id": "<node_id from manifest>",
      "operator_jurisdiction": "<ISO-3166 alpha-2>",
      "substrate_citations": [
        "<short label of the cited code module>"
      ],
      "outcome": "produced|filed|in_progress|forwarded|closed_at_intake"
    }
    ```

  - **Retention:** indefinite at the operator. Same posture as
    DSAR audit logs — regulators and FIUs may audit response
    records years later.
  - **Backup:** operator's standard backup rotation. NOT the
    indexer's PITR.
  - **Read access:** operator-of-record + counsel.

The audit log is operator-local; it is NOT shared between
operators by default. Each operator's regulator inquiries are
their own.

---

## Step 8 — Verify the post-inquiry state

After an inquiry / production / posture exchange, run the AML-1
gate to confirm the substrate did not drift during response:

```bash
python3 audit/aml_compliance_check.py --json /tmp/aml1.json
python3 -c "import json; print(json.load(open('/tmp/aml1.json'))['summary'])"
# Should report hard_findings = 0.
```

If `hard_findings > 0`, an inline substrate edit happened during
response — investigate before continuing.

For a posture exchange that produced an interpretive change,
verify the public notice was updated as a §6 change-control event
(not an inline edit):

```bash
git log -1 -- launch/legal/aml_kyc_notice.md
```

The commit should reference the inquiry ticket and pass the
audit gate before being merged.

---

## After action

1. Close the inbound with counsel's response.
2. File the audit-log entry per §7.
3. If the inquiry produced a posture change, schedule a 30-day
   follow-up to confirm the AML-1 audit gate is still green:

   ```bash
   python3 audit/aml_compliance_check.py
   ```

4. If the inquiry came from a jurisdiction not currently listed
   in `launch/legal/aml_kyc_notice.md` §4, flag the notice for
   a §6 update — a new regime may need explicit coverage.

---

## Why this works without new code

Every move in this runbook is a *composition* of primitives
already in the tree:

- **Step 1** is the operator's existing ticketing system + the
  AML-1 `OperatorAttestation.jurisdiction` field (OFAC-1 sig-
  bound) — no protocol change.
- **Step 2** is the operator's local records + the
  `collect_aml_attestations` helper + the existing DSAR /
  OFAC-1 audit logs. No new endpoint, no new authority key.
- **Step 3** grounds posture statements in the substrate the
  audit gate verifies. The disclaimer string is single-source-
  of-truth in `aml_compliance.py`.
- **Step 4** is operator-of-record + counsel; the protocol does
  not host the evaluation.
- **Step 5** mirrors the OFAC-1 §3 / SEC-1 §5 cross-border
  posture — refuse silent protocol-level action, route through
  MLA / Egmont.
- **Step 6** turns the substrate into the *defense* against the
  process-tax complaint vector — the complaint dies at intake
  on the regulator's side because the substrate citation set is
  ready.
- **Step 7** is a canonical-JSON line in `/var/log/phylanx/aml/` —
  same operator-local audit pattern the DSAR and SEC-1 runbooks
  use.
- **Step 8** is the same AML-1 audit gate replayed.

No on-chain action. No protocol-level legal personhood. No
cluster-side KYC. The compliance path IS the existing engineering
substrate read in sequence, with operator-jurisdiction process
honoured by each operator independently.
