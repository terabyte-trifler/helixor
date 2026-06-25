# Phylanx Securities & Investment-Advice Notice

**Effective:** mainnet launch date (see `launch/LAUNCH_CHECKLIST.md`).
**Last reviewed:** 2026-05-27.
**Canonical substrate:** `phylanx-oracle/oracle/securities_compliance.py`.
**Audit gate:** `audit/securities_compliance_check.py`.

This notice is the public-facing surface of the SEC-1 mitigation
suite. It describes (a) what a Phylanx cert score IS and IS NOT, (b)
how oracle cluster operators are compensated, (c) what financial
relationships an operator may have with rated agents and how those
are disclosed, and (d) the channel a regulator may use to obtain
operator records under a properly served subpoena or equivalent.

The notice is **mechanical**, not aspirational: every claim below is
pinned in code (see the "Source of truth" pointers throughout) and
verified at boot by `audit/securities_compliance_check.py`. If this
notice and the code diverge, the code wins and this notice must be
updated to match.

---

## 1. What Phylanx IS

Phylanx is a Solana-based trust-scoring protocol for autonomous AI
agents. The oracle cluster ingests observable on-chain behaviour
(per `phylanx-oracle/oracle/data_protection_policy.py` §`TRANSACTION_HISTORY`)
and computes a numeric score and an alert tier per agent per epoch.
The output is an on-chain `HealthCertificate` PDA signed by 3-of-5
cluster operators (`programs/certificate-issuer/src/signing.rs`).

The score is a **technical trust signal** — it reflects what the
cluster has observed about an agent's on-chain conduct, weighed
against the cluster's published scoring kernel
(`phylanx-oracle/oracle/scoring/_scoring.py`, hash-bound into the
cert via AW-04). The score does NOT incorporate, predict, or
recommend any market price or rate of return.

**Source of truth:** `ADVISORY_DISCLAIMER` in
`phylanx-oracle/oracle/securities_compliance.py`. Every consumer-
facing SDK surface that returns a score renders this text
verbatim — see §1.1.

### 1.1 What a Phylanx cert score is NOT

A Phylanx cert score is **NOT**:

  * **Investment advice** under Investment Advisers Act §202(a)(11)
    (US), MiCA Title V (EU), SEBI's Investment Advisers Regulations
    2013 (India), or any analogous regime.
  * **A security rating** under SEC Rule 17g-1 et seq., the EU
    Credit Rating Agencies Regulation (CRA III, 1060/2009), or any
    NRSRO framework. The cluster does not opine on credit risk,
    repayment likelihood, or default probability of any debt
    instrument.
  * **Issued by a registered investment adviser, broker-dealer,
    credit rating agency, CASP (under MiCA), or registered IA
    (under SEBI).** No cluster operator holds any of those
    registrations in their capacity as a Phylanx operator. An
    operator may hold such a registration in a separate capacity;
    that registration is theirs alone and does not extend to their
    operator activity.
  * **A recommendation** to buy, sell, hold, lend against, borrow
    against, or otherwise transact in any digital asset, including
    the rated agent's wallet, any token associated with it, or any
    other party's asset.

Consumers integrating Phylanx MUST NOT present a Phylanx cert score
as any of the above to their own users. The
`ADVISORY_DISCLAIMER` constant is provided in the SDK precisely so
this carve-out can travel with the score verbatim.

---

## 2. Cluster operator compensation

**Source of truth:** `OperatorAttestation.compensation_model` in
`phylanx-oracle/oracle/operator_manifest.py` +
`ALLOWED_COMPENSATION_MODELS` in
`phylanx-oracle/oracle/securities_compliance.py`.

Each cluster operator declares their compensation model in their
signed attestation. The set of allowed models is closed and pinned
in the SEC-1 audit gate
(`PINNED_ALLOWED_COMPENSATION_MODELS`); widening the set requires
updating this notice, the substrate, and the audit gate in
lockstep, plus public governance disclosure.

Today the **only** allowed compensation model is:

> **`FLAT_FEE_PER_CERT_FROM_TREASURY`** — the operator is paid a
> fixed, predetermined amount per cert issued, out of the protocol
> treasury. The amount does not vary with:
>
>   * the alert tier or numeric score of the cert,
>   * the size of any loan or position that consumes the cert,
>   * the total value locked (TVL) in any consumer protocol,
>   * the market price of any token,
>   * the on-chain outcome of any transaction informed by the cert.

Models intentionally **NOT** allowed (and refused at the boot gate):

  * Performance-fee or revenue-share arrangements.
  * Token grants whose value tracks protocol TVL or cert-gated
    capital flows.
  * Equity in any Phylanx-affiliated entity that does not exist
    purely for service delivery.

The audit-mandated reading is: under this compensation model, the
operator is a **service provider** compensated for cert issuance
labour — the classic Howey prong 4 ("derived solely from efforts of
others") consideration does not align with the cluster's output
because the operator's income is decoupled from consumer-side
capital flows. The flat-fee posture is the load-bearing
non-investment-adviser argument.

An operator who lies about their compensation_model invalidates
the OFAC-1 Ed25519 sig binding over their attestation
(`attestation_canonical_bytes` includes both SEC-1 fields). The
lie costs the same private-key compromise the rest of the
protocol assumes the adversary cannot perform.

---

## 3. Conflict-of-interest disclosure

**Source of truth:** `OperatorAttestation.conflicts_disclosed` in
`phylanx-oracle/oracle/operator_manifest.py` +
`ConflictDisclosure(rated_wallet, relationship_type)` in
`phylanx-oracle/oracle/securities_compliance.py`.

Each operator declares, in their signed attestation, every
financial relationship they have with any rated `agent_wallet`.
"Financial relationship" includes (non-exhaustively):

  * the rated agent is the operator (same legal person),
  * the rated agent is owned by the operator or by a related party,
  * the operator is an employee, officer, or director of the rated
    agent or its operator,
  * the operator is paid, in any form, by the rated agent or its
    operator (outside the flat-fee treasury compensation above),
  * the operator holds debt, equity, or token positions in the
    rated agent or its operator.

The protocol does NOT refuse to issue a cert for a disclosed agent.
That decision belongs to each operator's counsel (under their home-
jurisdiction self-dealing rules under IA Act §206 / SEBI IA Reg.
15(3) / MiCA Art. 60). The protocol DOES ensure that:

  * The disclosure is **sig-bound** — hiding a relationship or
    retroactively editing the conflict list invalidates the
    operator's attestation signature (see §2).
  * The disclosure is **audit-visible** — every disclosed conflict
    is enumerable via `collect_disclosed_conflicts(manifest)` and
    published alongside the operator manifest at deploy.

A regulator inspecting the on-disk manifest sees the conflict list
as plainly as the operator's own org affiliation.

---

## 4. Geographic scope & analogous regimes

This notice is written for the same three primary jurisdictions
the DP-1 privacy notice covers (US, EU/EEA, India), and the
posture below applies symmetrically across them:

  * **United States** — IA Act of 1940 §202(a)(11) (investment
    adviser definition); SEC v. Howey Co., 328 U.S. 293 (1946);
    Reves v. Ernst & Young, 494 U.S. 56 (1990) for note-like
    instruments. No cluster operator acts in an IA capacity
    through their Phylanx operator activity.
  * **European Union / EEA** — MiCA Regulation (2023/1114), Title
    V on Crypto-Asset Service Providers, and the MiFID II
    investment-advice definition. The cluster's output is not a
    "crypto-asset service" under MiCA Art. 3(1)(16) — no asset is
    issued, exchanged, or custodied; the cert is an analytical
    output the consumer reads.
  * **India** — SEBI (Investment Advisers) Regulations 2013, Reg.
    2(1)(l) (definition of "investment advice"). No operator
    provides advice "in return for consideration" relating to
    investment products — the consideration is paid for cert
    issuance, not for advice on a security.
  * **United Kingdom** — FSMA 2000 §22 (regulated activities) +
    PERG 8.24 (advising on investments). The carve-out is the
    same as IA Act: the cluster does not opine on the merits of
    any investment.
  * **Singapore** — FAA 2001 §2 (definition of "financial adviser").
    Same carve-out.

The compensation-independence floor (§2) and conflict-disclosure
substrate (§3) apply regardless of which regime an operator's
home jurisdiction lands in.

---

## 5. Channels for regulator inquiry

Regulators with proper authority over an operator's home
jurisdiction may contact that operator-of-record via:

  1. The contact channel published in
     `phylanx-oracle/deploy/operator_manifest.json`'s
     `operator_contact` field. This is the canonical inbound for
     subpoenas, no-action letters, and information requests.
  2. The DP-1 privacy-notice channel
     (`launch/legal/privacy_notice.md` §1) for data-subject-rights
     questions that intersect with regulator inquiries (e.g. a
     regulator-initiated DSAR on behalf of a complainant).

Operational handling is documented in
`launch/runbooks/securities_inquiry_response.md`. Inbound from
non-operator-jurisdiction regulators is forwarded to the
operator-of-record without protocol-level action; cross-border
mutual legal assistance is the regulator's path, not the
protocol's.

---

## 6. Changes to this notice

Changes follow the same two-phase process as the privacy notice:
draft + 30-day public comment, then merge with the audit gate
green. Substantive changes (new compensation model, new allowed
relationship_type taxonomy, regime-coverage extension to a new
jurisdiction) require a governance event referenced in
`launch/governance_log.md`.

---

## 7. Contact

For SEC-1 / securities-posture questions or to report an
operator who you believe is in violation of the
compensation-independence or conflict-disclosure substrate:

  * **Operator-of-record:**
    `phylanx-oracle/deploy/operator_manifest.json`
    `operator_contact` field.
  * **Per-jurisdiction regulator inquiry path:**
    `launch/runbooks/securities_inquiry_response.md`.
  * **Bug bounty / disclosure:** see
    `SECURITY.md` at the repo root.

The substrate is auditable in code. If you find a divergence
between this notice and the gate, the gate wins; please open an
issue referencing the divergence so the notice can be updated.
