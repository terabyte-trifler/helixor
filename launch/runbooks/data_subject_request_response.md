# Runbook — Data Subject Access / Erasure Request (DSAR) response

**Severity:** Low operationally, **high** if mishandled — a DSAR is a
statutory request under GDPR Arts. 15/17, DPDP s.11/12, or CCPA
§1798.110/§1798.105. Non-response or partial response within the
statutory window (GDPR: 1 month; DPDP: under rules; CCPA: 45 days)
exposes the operator-of-record to direct regulatory action in their
home jurisdiction.

**Triggers:**
- Inbound email or ticket from a data subject naming an
  `agent_wallet` and invoking GDPR Art. 15 (access), Art. 17
  (erasure), DPDP s.11 or s.12, or CCPA §1798.110 or §1798.105.
- Direct CLI invocation by an operator (`python -m
  oracle.data_subject_request query|erase ...`) where the audit
  log entry needs to be filed.
- `audit/data_protection_check.py` regression — the DP-1
  substrate or one of the canonical retention floors has drifted
  (handle as a CI regression, not a DSAR).

## What's happening

A data subject is exercising a statutory right against the
operator-of-record. The DP-1 substrate
(`phylanx-oracle/oracle/data_protection_policy.py`) has already
classified every per-agent store the protocol writes to as either
ERASABLE or CARVED OUT, and the public privacy notice
(`launch/legal/privacy_notice.md`) has disclosed the carve-outs
BEFORE registration. This runbook is the operational sequence the
operator runs.

The two failure shapes need different responses:

- **Access request** — enumerate everything stored for the named
  wallet and reply with the report.
- **Erasure request** — purge the off-chain erasable slices and
  reply with the report, including the explicit carve-outs the
  operation did NOT touch.

Both flows end with one canonical-JSON audit-log entry, byte-
identical across operators given the same input.

---

## Step 1 — Verify the request

**Substrate:** the inbound channel published in
`launch/legal/privacy_notice.md` §1 + the operator-of-record's
ticketing system. There is no on-chain verification path — the
data subject is identified by the same wallet pubkey the protocol
itself uses, and proof-of-control of the wallet is the only
authentication signal the operator should rely on.

**Procedure (operator-of-record):**

  1. Confirm the inbound message names a specific `agent_wallet`
     in base58 form. If not, request clarification — the DSAR
     CLI rejects non-base58 wallets at runtime (VULN-20 carry-
     over), so a malformed wallet cannot proceed.
  2. Verify proof-of-control. The data subject signs a fixed
     challenge string with the wallet's private key and includes
     the signature in the request. Operator verifies with
     `solana-keygen verify <signature> <message> <pubkey>` or
     the equivalent SDK call.
  3. Categorise the request: access (Art. 15 / s.11 /
     §1798.110) → §2 below. Erasure (Art. 17 / s.12 /
     §1798.105) → §3 below. Objection (Art. 21 / s.13) → run
     §3 erasure + add wallet to the local objection list (§4).
  4. Record the ticket ID — this is the `justification` string
     the erasure CLI requires.

**Do NOT:**
- Accept a DSAR without a proof-of-control signature. A
  malicious party could otherwise file erasures against
  wallets they do not control, defeating the audit trail.
- Skip the categorisation step. The CLI takes different
  subcommands and the audit-event `operation` field is the
  per-request differentiator regulators read.

---

## Step 2 — Access request (Art. 15 / s.11 / §1798.110)

**Substrate:** `oracle.data_subject_request.query_data_subject` +
the CLI entry.

**Procedure:**

```bash
# Repo root, with operator's production DB DSN in env.
cd /phylanx && source phylanx-api/.venv/bin/activate
cd phylanx-oracle

export PHYLANX_DB_DSN='postgres://...prod...'

python -m oracle.data_subject_request query <agent_wallet> \
    > /var/log/phylanx/dsar/<ticket_id>.access.json
```

The output is one line of canonical JSON. The schema:

```json
{
  "wire_version": 1,
  "operation": "query",
  "wallet": "<agent_wallet>",
  "justification": "",
  "detected_at": "<UTC ISO8601 with Z suffix>",
  "slices": [
    {
      "category": "<DataCategory.value>",
      "storage_location": "<StorageLocation.value>",
      "record_count": <int>,
      "erasure_applied": false,
      "carve_out_reason": "<string, '' if no carve-out>"
    },
    ...
  ]
}
```

**Reply to the data subject** with the JSON or a human-readable
rendering of it. The reply MUST include:

  - The slice list (every category, even those with 0 records or
    a carve-out reason).
  - A reference to `launch/legal/privacy_notice.md` §3 (the
    retention table) and §6 (the on-chain carve-out).
  - A pointer to `python -m oracle.data_subject_request erase ...`
    if the subject wants to follow up with an erasure.

**Statutory window:** GDPR Art. 12(3) gives the controller 1
month from receipt; DPDP rules pin a similar period; CCPA
§1798.130(a)(2) gives 45 days. Operator-of-record SLA is 14 days
to leave headroom.

**Do NOT:**
- Mutate the canonical JSON before storing it in the audit log.
  Sorted keys + fixed key order is the byte-identity invariant
  the audit gate verifies; a manual edit breaks downstream
  reconciliation.
- Reply with only the erasable slices. Regulators read the
  carve-out section to confirm the controller is transparent
  about what they will NOT delete.

---

## Step 3 — Erasure request (Art. 17 / s.12 / §1798.105)

**Substrate:** `oracle.data_subject_request.erase_data_subject` +
the CLI entry.

**Procedure:**

```bash
export PHYLANX_DB_DSN='postgres://...prod...'

python -m oracle.data_subject_request erase <agent_wallet> \
    --justification "<ticket_id> + <Art./section reference>" \
    > /var/log/phylanx/dsar/<ticket_id>.erase.json
```

The `--justification` flag is REQUIRED — the CLI rejects an empty
or whitespace-only string. The format the operator-of-record
runbook pins is:

```
<ticket-id> | <jurisdiction Art./section> | <one-line reason>
```

Example: `DSAR-2026-0001 | GDPR Art.17 | controller-side erasure
of off-chain stores`.

**What happens at the SQL layer:**

```sql
-- The two erasable slices in DP-1 today:
DELETE FROM agent_transactions WHERE agent_wallet = %s;
DELETE FROM agent_scores       WHERE agent_wallet = %s;
```

Both run through `psycopg`'s `%s` parameter binding — never
f-strings — backed by the VULN-20 base58 wallet guard for
defense-in-depth. The deletes are issued in one logical
transaction at the connection layer.

**Reply to the data subject** with the erase report. The reply
MUST include:

  - The slice list with `erasure_applied: true` for the deleted
    slices and `record_count` showing the rows that WERE present
    before deletion (i.e. how many rows we actually deleted).
  - The on-chain carve-out — name the four affected categories
    explicitly (CERT_HISTORY, REGISTRATION_METADATA, REFUSAL_LOG,
    CHALLENGE_HISTORY) and link to privacy notice §6 for the
    rationale.
  - A pointer to the privacy notice's right-to-complain channel
    if the subject disputes the carve-out.

**Statutory window:** same as §2. Operator-of-record SLA is
14 days.

**Do NOT:**
- Re-run the erase CLI a second time hoping to "make sure" — the
  second run will report `record_count = 0` for the erasable
  slices (since the first deleted them), which is functionally
  correct but produces a misleading audit event. If you must
  re-verify, run a `query` instead.
- Try to lower the VULN-20 wallet guard to handle a malformed
  wallet "just this once". The guard is the load-bearing
  defense-in-depth against SQL splicing; bypassing it during a
  DSAR is exactly the slip path a future audit would flag.
- Skip the justification. A DSAR erasure without a recorded
  reason is structurally indistinguishable from a malicious
  insider zeroing out a wallet's record. The justification IS
  the audit defense.

---

## Step 4 — Objection (Art. 21 / DPDP s.13)

**Substrate:** the §3 erasure flow + the operator-local objection
list.

If the request is an OBJECTION to processing (not just an
erasure), the operator-of-record:

  1. Runs the §3 erasure flow with `--justification` including
     "OBJECTION" verbatim.
  2. Adds the wallet to the operator-local objection list
     (`/etc/phylanx/objections.txt`, one wallet per line). The
     indexer ingest path reads this file at startup and skips
     transactions whose `agent_wallet` matches.
  3. Confirms via `query` after the next epoch that no new rows
     are appearing for the wallet in `agent_transactions`.

**Do NOT:**
- Maintain the objection list on-chain. An on-chain objection
  list creates a high-value authority key (the wallet that can
  mutate the list) and breaks the permissionless invariant —
  the same anti-pattern OFAC-1 declined for the same reasons.
- Share the objection list between operators without consent.
  Each operator's list is local to their processing; consent
  to one operator does not imply consent to all.

---

## Step 5 — Audit log

**Substrate:** `serialize_dsar_audit_event(...)` +
`/var/log/phylanx/dsar/`.

Every DSAR (access OR erasure OR objection) emits one canonical-
JSON line. The operator-of-record runbook pins:

  - **Path:** `/var/log/phylanx/dsar/<ticket_id>.<op>.json`
    where `<op>` is `access` or `erase`.
  - **Retention:** indefinite at the operator. The audit-log
    file is the only permanent record of a DSAR; regulators may
    audit it years later.
  - **Backup:** included in the operator's standard backup
    rotation (NOT the indexer's PITR — DSAR audit logs are
    operator-local).
  - **Read access:** operator-of-record + one designated DP
    deputy. Not exposed via any public API.

The audit-event canonical JSON is byte-identical across
operators given the same input (sorted keys, UTC-normalised
`detected_at`, wire-versioned). Two operators running the same
DSAR independently produce verifiable parallel audit logs.

**Test pin:** `phylanx-oracle/tests/oracle/
test_dp1_data_subject_request.py::test_audit_event_is_canonical_json`.

---

## Step 6 — Verify the post-DSAR state

After an erasure, run a `query` to confirm the slices are at
zero:

```bash
python -m oracle.data_subject_request query <agent_wallet> | \
    jq '.slices | map(select(.erasure_applied == false and .carve_out_reason == ""))'
```

The list should be empty for the erasable slices (both
`agent_transactions` and `agent_scores` rows show `record_count
= 0`). The carved-out slices are still present in the output
with their carve-out reasons — that is correct, NOT a regression.

For an objection, additionally verify the objection list:

```bash
grep -x <agent_wallet> /etc/phylanx/objections.txt
```

---

## After action

1. Close the inbound ticket with the reply rendered from the
   audit-event JSON.
2. If the request was an OBJECTION, schedule a 30-day follow-up
   `query` to confirm the indexer is honouring the objection list
   (no new rows for the wallet).
3. Run the full DP-1 audit gate before mainnet redeploys:
   ```bash
   python3 audit/data_protection_check.py --json /tmp/dp1.json
   cat /tmp/dp1.json | jq '.summary'
   # Should report hard_findings = 0.
   ```
4. If you handled an inbound from a new jurisdiction not listed
   in `launch/legal/privacy_notice.md` §7, flag the privacy
   notice for review — a new transfer regime may need to be
   covered in §7.

---

## Why this works without new code

Every move in this runbook is a *composition* of primitives
already in the tree:

- **Step 1** is the operator's existing ticketing system plus the
  proof-of-control challenge — no protocol change.
- **Steps 2–3** are the DSAR CLI in
  `oracle.data_subject_request` with the DP-1 substrate it
  consumes. The VULN-20 base58 guard, the parameterised SQL,
  and the DBConnection Protocol all pre-exist; the DSAR module
  composes them.
- **Step 4** is `oracle.data_subject_request.erase_data_subject`
  + a 100-line local text file — no on-chain surface, no new
  authority key.
- **Step 5** is `serialize_dsar_audit_event` writing canonical
  JSON to disk, exactly the same pattern the OFAC-1
  `serialize_cert_refused` uses for its on-bus event.
- **Step 6** is the same CLI's `query` subcommand replayed.

No on-chain erasure instruction. No DP authority key. The
compliance path IS the existing engineering substrate fired in
sequence, with the carve-outs disclosed upfront in the privacy
notice.
