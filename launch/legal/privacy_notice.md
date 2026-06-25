# Phylanx Privacy Notice

**Effective:** mainnet launch date (see `launch/LAUNCH_CHECKLIST.md`).
**Last reviewed:** 2026-05-27.
**Canonical substrate:** `phylanx-oracle/oracle/data_protection_policy.py`.
**Audit gate:** `audit/data_protection_check.py`.

This notice is the public-facing surface of the DP-1 mitigation
suite. It describes what data Phylanx collects about agent
operators, on what legal basis, for how long, where it lives, and
how to exercise data-subject rights against it. The notice is
written for three jurisdictions whose laws converge on the same
mechanical requirements: GDPR (EU/EEA), DPDP (India), and CCPA/CPRA
(California). Where the regimes diverge, the most restrictive
applies.

The notice is **mechanical**, not aspirational: every retention
floor and lawful-basis claim below is pinned in code (see the
"Source of truth" pointers throughout) and verified at boot by
`audit/data_protection_check.py`. If this notice and the code
diverge, the code wins and this notice must be updated to match.

---

## 1. Who we are

Phylanx is a Solana-based trust-scoring protocol for autonomous AI
agents. The protocol is operated by a 3-of-5 multi-jurisdiction
oracle cluster (see HCR-4 + OFAC-1, `phylanx-oracle/oracle/
operator_manifest.py`); the cluster operators are the joint
"controllers" of the personal data described below within the
meaning of GDPR Art. 4(7). The Verified Integrators consuming
issued certificates are independent controllers for their own
processing; this notice does not cover them.

For data-subject requests, contact the operator-of-record listed
in `phylanx-oracle/deploy/operator_manifest.json`.

---

## 2. What is "personal data" here

Phylanx identifies agent operators by their Solana wallet pubkey
(a base58 string of 32–44 characters). The wallet pubkey is a
**pseudonymous identifier** in the GDPR Recital 26 sense: it
does not directly name the operator, but it is linkable to one,
so the data we hold about it is treated as personal data under
GDPR Art. 4(1), DPDP s.2(t), and CCPA §1798.140(o).

We do **NOT** collect any of the following:

  - Real names, postal addresses, phone numbers, or email
    addresses of agent operators.
  - IP addresses of agent operators (the oracle has no public
    write path; agents are identified solely by their on-chain
    signature).
  - Government-issued identifiers (SSN, Aadhaar, etc.).
  - Special-category data under GDPR Art. 9 / DPDP s.9.

Verified Integrator partners DO provide a contact channel as part
of the on-chain registration (`VerifiedConsumer` account); that
contact is processed under the contract basis (§3 below) and is
not described as agent data.

---

## 3. What we store, where, on what basis, and for how long

The closed set of data categories the protocol stores is declared
in `oracle/data_protection_policy.py::DataCategory`. The audit gate
verifies every category has a declared policy. The table below
is rendered from `RETENTION_POLICIES` and pinned in code:

| Category | Where | Retention | Lawful basis | Erasable? |
|---|---|---|---|---|
| **TRANSACTION_HISTORY** | TimescaleDB `agent_transactions` | 180 days | Legitimate interest — fraud prevention (GDPR Art. 6(1)(f)) | **Yes** |
| **TRANSACTION_HISTORY** | Kafka `agent.transactions` | 7 days (retention rotation) | Legitimate interest — fraud prevention | **Yes** (by rotation) |
| **SCORE_HISTORY** | TimescaleDB `agent_scores` | 180 days from last activity | Legitimate interest — fraud prevention | **Yes** |
| **CERT_HISTORY** | Solana on-chain (`HealthCertificate` PDAs) | Indefinite (immutable ledger) | Legal obligation — audit trail (GDPR Recital 65) | **No** (see §6) |
| **REGISTRATION_METADATA** | Solana on-chain (`AgentRegistration` PDA) | Indefinite | Contract — consumer integration | **No** (see §6) |
| **REFUSAL_LOG** | Kafka `agent.cert_events.refused` | 30 days | Legal obligation — sanctions transparency | **No** (see §6) |
| **CHALLENGE_HISTORY** | Solana on-chain (`ChallengeRecord` PDA) | Indefinite | Legal obligation — audit trail | **No** (see §6) |
| **OPERATIONAL_TELEMETRY** | Prometheus TSDB | 30 days (retention rotation) | Legitimate interest — fraud prevention | **Yes** (by rotation) |

**Source of truth:**
- TimescaleDB retention: `phylanx-oracle/db/migrations/0009_timescaledb.sql`
  pins `INTERVAL '180 days'`.
- Prometheus retention: `launch/deploy/docker-compose.indexer.yml`
  pins `--storage.tsdb.retention.time=30d`.
- All retention seconds and lawful-basis values:
  `phylanx-oracle/oracle/data_protection_policy.py`.

---

## 4. Why we store this — purpose limitation

GDPR Art. 5(1)(b), DPDP s.7(c), and CCPA §1798.100(c) all require
that data be processed only for declared, compatible purposes.
Phylanx processes the data above for **exactly two** purposes:

  1. **Trust-scoring of autonomous agents.** The
     TRANSACTION_HISTORY + SCORE_HISTORY + OPERATIONAL_TELEMETRY
     categories feed the per-epoch scoring pipeline. These are
     the inputs the scoring functions need; nothing else is fed
     into them. Source: `phylanx-oracle/features/extract.py` +
     `phylanx-oracle/scoring/`.
  2. **Tamper-resistant audit trail.** The CERT_HISTORY +
     REGISTRATION_METADATA + REFUSAL_LOG + CHALLENGE_HISTORY
     categories exist so that any party — auditor, integrator,
     operator, or the data subject themselves — can verify what
     the cluster decided and why. The audit trail is the load-
     bearing defense against silent score forgery (FRP-3),
     silent delisting (OFAC-1), and rewrite attacks
     (VULN-13 + AW-01).

We do **NOT** sell or share this data with third parties. The
on-chain audit-trail categories are publicly readable on the
Solana ledger by anyone (this is a defining property of public
ledgers, not a privacy-policy concession); but we do not push,
syndicate, or license the data.

---

## 5. Your rights

The rights below come from GDPR Arts. 12–22, DPDP Ch. III, and
CCPA §1798.100 et seq. They apply against the OFF-CHAIN slices of
your data; the on-chain carve-out is described in §6.

### 5.1 Right to access (GDPR Art. 15, DPDP s.11, CCPA §1798.110)

You can ask us what we store about your wallet. The mechanical
path is:

```bash
python -m oracle.data_subject_request query <your_wallet>
```

This is the same command the operator-of-record runs on your
behalf if you file a request via the contact in §1. The report
enumerates every category in §3 — both the slices we will erase
on request and the carve-outs we will not.

### 5.2 Right to erasure (GDPR Art. 17, DPDP s.12, CCPA §1798.105)

You can ask us to purge the OFF-CHAIN slices of your data. The
mechanical path is:

```bash
python -m oracle.data_subject_request erase <your_wallet> \
    --justification "<ticket reference + reason>"
```

The operator runs this against the production TimescaleDB. The
operation:

  - Deletes every row in `agent_transactions` and
    `agent_scores` for your wallet.
  - Records an audit event (canonical JSON, wire-versioned) to
    the DSAR audit log (`launch/runbooks/
    data_subject_request_response.md` pins the log path).
  - Does **NOT** touch any on-chain account (see §6).
  - Does **NOT** delete from the OFAC-1 refusal log (see §6).
  - Does **NOT** push to Kafka or Prometheus — those substrates
    erase by retention rotation within 7 days (Kafka) and 30
    days (Prometheus).

If we receive an erasure request via email or other channel, the
operator-of-record runs the same CLI; the audit event records
the request reference verbatim.

### 5.3 Right to object (GDPR Art. 21, DPDP s.13)

You can object to processing under the legitimate-interest basis.
Our position is that fraud-prevention scoring of autonomous
agents is the GDPR Recital 47 / DPDP s.7(b) "fair and reasonable
purposes" use case. If you object, the operator-of-record
will:

  1. Run the §5.2 erasure flow.
  2. Add your wallet to the operator's local objection list,
     which causes future TRANSACTION_HISTORY ingestion to skip
     your wallet.

We do not maintain an on-chain objection list; that would create
the OFAC-1-style high-value authority key target and break the
permissionless invariant. The objection list is operator-local.

### 5.4 Right to portability (GDPR Art. 20, DPDP s.11)

The §5.1 query CLI emits the data in canonical JSON suitable for
machine import. There is no separate "export" endpoint.

### 5.5 Right to lodge a complaint

EU/EEA residents can complain to their national supervisory
authority. Indian residents can complain to the Data Protection
Board under DPDP s.27. California residents can complain to the
California Privacy Protection Agency.

---

## 6. The on-chain carve-out

GDPR Recital 26 and DPDP s.3(c) recognise that **technical
infeasibility** of erasure is a documented constraint, provided
the data subject is informed BEFORE the data is collected. This
notice is that disclosure.

The on-chain categories — CERT_HISTORY, REGISTRATION_METADATA,
CHALLENGE_HISTORY — and the OFAC-1 REFUSAL_LOG are **not
erasable on request** for the following reasons:

  - **Public ledger immutability.** The Solana ledger is
    append-only by design. Removing or rewriting a confirmed
    account is mechanically infeasible at the program layer.
    Phylanx does not, and cannot, hold a private key with
    authority to mutate every operator's `HealthCertificate`.
  - **Audit-trail load-bearing.** The on-chain audit trail is
    what proves the cluster did not silently delist your agent
    (OFAC-1), forge your score (FRP-3 / VULN-13), or rewrite
    history (AW-01). An on-demand erasure path would dissolve
    those guarantees for every other agent.
  - **Refusal-log transparency invariant.** The OFAC-1
    `Topic.CERT_REFUSED` stream records every refusal so that a
    captured cluster cannot silently delist any agent. Erasing
    refusal records would defeat that invariant.

**What we store on-chain is minimal and pseudonymous.** The
on-chain payload is wallet pubkey, epoch number, score (0–1000),
alert tier (GREEN/YELLOW/RED), signer set, and the audit hashes
(baseline / input commitment / slot anchor). Nothing else.
There is no name, contact, IP, or special-category data on the
ledger.

**Cohort-level pseudonymity.** A wallet pubkey is linkable to a
natural person ONLY if the linker holds an off-chain mapping
(KYC record at an exchange, social-media post claiming the
wallet, etc.). Phylanx does not collect, hold, or publish such
mappings. Pseudonymous wallet data on a public ledger is the
state-of-the-art baseline under GDPR Art. 4(5) /
Art. 25 (pseudonymisation by design).

If you require a guarantee that NO data about your activity will
ever exist on a public ledger, you should not register an agent.
Registration is the point at which you provide informed consent
to the on-chain carve-out by performing it.

---

## 7. International transfers

The 3-of-5 oracle cluster operators run nodes in at least 2
distinct jurisdictions (HCR-4 floor in
`oracle/operator_manifest.py`; see also OFAC-1 sig binding). The
exact jurisdictions are published in
`phylanx-oracle/deploy/operator_manifest.json` and verifiable via
`verify_attestation_signatures`. Off-chain stores (TimescaleDB,
Kafka, Prometheus) live in the operator's hosting region; the
audit / privacy notice surfaces this. For GDPR Chapter V
purposes, each operator's processing of EU-resident personal
data is covered by their own Standard Contractual Clauses or
adequacy decision; the operator-of-record contact in §1 lists
the relevant instruments.

---

## 8. Changes to this notice

Material changes to this notice are gated by the audit-gate
review process (`audit/data_protection_check.py` + the
`launch/LAUNCH_CHECKLIST.md` DP-1 entry). A change that weakens
a retention floor, expands a lawful-basis claim, or removes a
data-subject right requires:

  1. A coordinated PR updating the canonical substrate
     (`oracle/data_protection_policy.py`), the audit gate, the
     migration / docker-compose configs, and this notice in the
     SAME commit.
  2. Sign-off by the operator-of-record + at least one other
     cluster operator in a distinct jurisdiction (the HCR-4
     diversity floor applies to governance, not just signing).
  3. A new "Last reviewed" date at the top.

A change that expands a right or shortens a retention is
fast-tracked through the same review with a relaxed sign-off
requirement.

---

## 9. Contact

Operator-of-record contact: see
`phylanx-oracle/deploy/operator_manifest.json`.
Audit log of past DSAR requests: see
`launch/runbooks/data_subject_request_response.md` (operator-only,
not publicly readable; the existence of the log is disclosed
here, individual entries are not).
