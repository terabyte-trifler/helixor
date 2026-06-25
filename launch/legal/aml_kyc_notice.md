# Phylanx KYC / AML Posture Notice

**Effective:** mainnet launch date (see `launch/LAUNCH_CHECKLIST.md`).
**Last reviewed:** 2026-05-27.
**Canonical substrate:** `phylanx-oracle/oracle/aml_compliance.py`.
**Audit gate:** `audit/aml_compliance_check.py`.

This notice is the public-facing surface of the AML-1 mitigation
suite. It describes (a) why Phylanx's cluster activity does NOT fall
within the customer-due-diligence regimes (BSA / FinCEN, FATF
Recommendations 10 / 15 / 16, 5AMLD/6AMLD, MiCA CASP, PMLA, MLR 2017,
PSA 2019), (b) what each cluster operator attests about their own
KYC/AML program shape, (c) why the cluster mechanically refuses to
collect customer-identity fields, and (d) the channel a regulator or
complainant may use when raising an AML/KYC concern about the
protocol or a specific operator.

The notice is **mechanical**, not aspirational: every claim below is
pinned in code (see the "Source of truth" pointers throughout) and
verified at boot by `audit/aml_compliance_check.py`. If this notice
and the code diverge, the code wins and this notice must be updated
to match.

---

## 1. What Phylanx IS

Phylanx is a Solana-based trust-scoring protocol for autonomous AI
agents. The oracle cluster ingests observable on-chain behaviour
(per `phylanx-oracle/oracle/data_protection_policy.py` §
`TRANSACTION_HISTORY`) and computes a numeric score and an alert
tier per agent per epoch. The output is an on-chain
`HealthCertificate` PDA signed by 3-of-5 cluster operators
(`programs/certificate-issuer/src/signing.rs`).

The score is a **technical trust signal** — it reflects what the
cluster has observed about an agent's on-chain conduct, weighed
against the cluster's published scoring kernel
(`phylanx-oracle/oracle/scoring/_scoring.py`, hash-bound into the
cert via AW-04). The cluster does NOT take custody of any asset,
move value between parties, or hold an account-of-record for any
natural or legal person.

**Source of truth:** `AML_KYC_DISCLAIMER` in
`phylanx-oracle/oracle/aml_compliance.py`. Every consumer-facing
SDK surface that returns a score renders this text verbatim — see
§1.1.

### 1.1 What a Phylanx cert score is NOT

A Phylanx cert score is **NOT**:

  * **A KYC control.** The cluster has no customer-identity
    information about any rated `agent_wallet` and no mechanism to
    acquire it. The on-chain wallet is the only addressing primitive
    the cluster recognises; there is no off-chain person-to-wallet
    binding under the cluster's control.
  * **An AML screen.** The cluster does not run a sanctions list
    check, PEP screening, or adverse-media check against a rated
    wallet. (OFAC-1's refusal channel handles **operator-side**
    refusals against operator-jurisdiction sanctions lists; that is
    a separate substrate and is itself transparently logged. See
    `launch/legal/ofac_compliance_notice.md`.)
  * **A Travel Rule originator/beneficiary record.** The cluster
    does not originate, transmit, or beneficiate any value transfer.
    FATF Recommendation 16 / 5AMLD Art. 32a / FinCEN's Travel Rule
    require an entity that "transmits funds"; the cluster does not.
  * **A substitute for the consumer's own customer due-diligence.**
    A DeFi lender, exchange, or wallet that consumes a Phylanx cert
    score in its own risk decision REMAINS the obligated party for
    its own KYC/AML/CTF program under its home jurisdiction.

Consumers integrating Phylanx MUST NOT present a Phylanx cert score
as any of the above to their own users. The `AML_KYC_DISCLAIMER`
constant is provided in the SDK precisely so this carve-out can
travel with the score verbatim.

---

## 2. Cluster operator AML-program attestation

**Source of truth:**
`OperatorAttestation.aml_program_attestation` in
`phylanx-oracle/oracle/operator_manifest.py` +
`AmlProgramAttestation` + `ALLOWED_AML_ATTESTATIONS` in
`phylanx-oracle/oracle/aml_compliance.py`.

Each cluster operator declares their AML-program posture in their
signed attestation. The set of allowed values is closed and pinned
in the AML-1 audit gate (`PINNED_ALLOWED_AML_ATTESTATIONS`);
widening the set requires updating this notice, the substrate, and
the audit gate in lockstep, plus public governance disclosure.

The allowed values are:

  * **`NO_AML_PROGRAM_REQUIRED_FOR_PHYLANX_ACTIVITY`** — the
    operator attests that, with respect to their Phylanx operator
    activity, they are not a covered person under their home-
    jurisdiction AML regime. The cluster activity is the
    *observation and signing* of trust signals; it does not involve
    custody, transmission, exchange, or any other regulated VASP /
    MSB / CASP activity. This is the load-bearing AML-1 posture for
    most operators.
  * **`EXTERNAL_AML_PROGRAM_DECLARED`** — the operator runs an AML
    program for an *unrelated* line of business (e.g. they also
    operate a registered exchange or payment service) and discloses
    that posture here so a regulator inspecting the manifest does
    not need to subpoena to find out. This value is NOT an
    admission that the operator's Phylanx activity is itself a
    covered activity — it is a transparency surface for the
    operator's external program.

Postures intentionally **NOT** allowed (and refused at the boot
gate):

  * `OPERATES_AS_MSB` / `OPERATES_AS_VASP` / `OPERATES_AS_CASP` —
    declaring the operator's Phylanx activity itself a covered
    activity would invert the cluster's posture; the cluster does
    not custody, transmit, or exchange value.
  * Free-text declarations — closed-enum only, so a regulator
    inspecting the manifest sees a known shape, not prose.

An operator who lies about their `aml_program_attestation`
invalidates the OFAC-1 Ed25519 sig binding over their attestation
(`attestation_canonical_bytes` includes the AML-1 field — see
`phylanx-oracle/oracle/operator_manifest.py`). The lie costs the
same private-key compromise the rest of the protocol already
assumes the adversary cannot perform.

---

## 3. KYC field guard

**Source of truth:** `_KYC_FORBIDDEN_FIELDS` +
`assert_no_kyc_fields(name)` +
`KycFieldRefusedError` in
`phylanx-oracle/oracle/aml_compliance.py`.

The cluster's substrate refuses, by construction, to carry
customer-identity fields. Any future `DataCategory` (DP-1) or
operator-side data feed that introduces a field whose name matches
a known KYC-shaped pattern (`LEGAL_NAME`, `SSN`, `TAX_ID`,
`PASSPORT`, `STREET_ADDRESS`, `BANK_ACCOUNT`, `IBAN`, etc.) raises
`KycFieldRefusedError` at substrate construction time.

This is a defensive invariant against drift: the substrate cannot
quietly grow a KYC shape and have the audit gate notice only after
launch. The guard is verified by the AML-1 audit gate against the
current DP-1 `DataCategory` allowlist
(`audit/aml_compliance_check.py:check_datacategory_kyc_clean`) — a
drift trips the gate HARD.

The protocol therefore makes **two** mechanical commitments:

  1. It does not ingest customer-identity fields today.
  2. It cannot quietly start ingesting them tomorrow without
     tripping the audit gate.

---

## 4. Geographic scope & analogous regimes

This notice is written for the same five primary jurisdictions the
DP-1 privacy notice and SEC-1 securities notice cover, plus the
FATF carve-out path. The posture below applies symmetrically:

  * **United States — BSA / FinCEN.** The Bank Secrecy Act
    (31 U.S.C. §5311 et seq.) and FinCEN's 2019 CVC guidance
    (FIN-2019-G001) define Money Services Business / money
    transmitter status by *acceptance and transmission* of value or
    by *exchange* of value. The cluster does neither. The cluster
    is not a money transmitter, not a money services business, and
    not an obligated person under 31 CFR Chapter X. Cluster
    activity does not trigger SAR-filing obligations under 31 CFR
    §1022.320.
  * **European Union / EEA — 5AMLD / 6AMLD / MiCA CASP.**
    Directive (EU) 2018/843 (5AMLD) Art. 2(1)(g)(h) extends
    obligated-person status to "providers engaged in exchange
    services between virtual currencies and fiat currencies" and to
    "custodian wallet providers". The cluster does neither. MiCA
    Regulation (EU) 2023/1114 Art. 3(1)(16) defines a Crypto-Asset
    Service Provider by reference to a closed list of services
    (custody, exchange, transfer, placement, advice, portfolio
    management, etc.); cluster activity matches none of them. The
    6AMLD harmonisation of money-laundering offences targets the
    *perpetrator* of laundering — not an analytics provider.
  * **India — PMLA.** The Prevention of Money-Laundering Act
    2002 + the March 2023 PMLA-amendment notification extend
    obligations to "reporting entities" engaged in exchange,
    transfer, safekeeping, or administration of virtual digital
    assets. The cluster's activity is none of these — the
    on-chain cert is an analytical signal, not a custody or
    exchange service. Cluster activity does not trigger STR-filing
    under PMLA §12.
  * **United Kingdom — MLR 2017.** The Money Laundering,
    Terrorist Financing and Transfer of Funds Regulations 2017
    Reg. 8 / Reg. 14A define cryptoasset-business obligations
    around exchange and custody. Cluster activity matches neither
    head of the cryptoasset-business definition.
  * **Singapore — PSA 2019.** The Payment Services Act 2019
    (as amended by the PS(A) Act 2021) defines Digital Payment
    Token services by reference to dealing-in, exchange,
    custody, and transfer of DPTs. The cluster does none. Cluster
    activity is not a DPT service.
  * **FATF Recommendation 15 / 16 (Travel Rule).** FATF R.15
    obligates jurisdictions to apply AML/CFT measures to VASPs;
    R.16 extends the Travel Rule to value transfers. The cluster
    is not a VASP under R.15's definition (no exchange, no
    transfer, no safekeeping, no participation in issuance) and
    therefore has no R.16 originator/beneficiary information to
    transmit.

The AML-program attestation (§2) and KYC-field guard (§3) apply
regardless of which regime an operator's home jurisdiction lands
in. An operator whose home-jurisdiction regulator concludes that
some specific activity by that operator is covered (e.g. the
operator also runs a registered exchange) declares it via
`EXTERNAL_AML_PROGRAM_DECLARED` (§2) — the disclosure travels
with the manifest.

---

## 5. Channels for AML/KYC inquiry or complaint

Regulators with proper authority over an operator's home
jurisdiction, FATF-mutual-evaluation teams, and members of the
public who wish to raise an AML/KYC concern may contact the
operator-of-record via:

  1. The contact channel published in
     `phylanx-oracle/deploy/operator_manifest.json`'s
     `operator_contact` field. This is the canonical inbound for
     regulator inquiries, mutual-evaluation questionnaires, and
     formal complaints.
  2. The DP-1 privacy-notice channel
     (`launch/legal/privacy_notice.md` §1) for AML inquiries that
     intersect with data-subject-rights questions.
  3. The OFAC-1 channel
     (`launch/legal/ofac_compliance_notice.md` §6) when the
     inquiry is specifically about sanctions screening — that is
     OFAC-1's substrate, not AML-1's.

Operational handling is documented in
`launch/runbooks/aml_complaint_response.md`. Inbound from
non-operator-jurisdiction regulators is forwarded to the
operator-of-record without protocol-level action; cross-border
mutual legal assistance is the regulator's path, not the
protocol's.

**Adversarial complaint posture.** AML-1's risk model explicitly
includes the *process-tax* complaint vector: an adversary may file
boilerplate AML complaints with multiple regulators against
cluster operators in the hope that the regulator-response cost
itself becomes a DoS. The defense is that the substrate (§§2 / 3),
the AML-1 audit gate, and this notice together let any operator
respond in under an hour with a substrate-grounded reply — the
complaint dies at intake on the regulator's side. The complaint-
response runbook in §5 of `launch/runbooks/aml_complaint_response.md`
documents this path.

---

## 6. Changes to this notice

Changes follow the same two-phase process as the privacy notice
and the securities notice: draft + 30-day public comment, then
merge with the audit gate green. Substantive changes (new allowed
attestation value, KYC-field-guard relaxation, regime-coverage
extension to a new jurisdiction) require a governance event
referenced in `launch/governance_log.md`.

---

## 7. Contact

For AML-1 / KYC-posture questions or to report an operator who
you believe is in violation of the AML-program-attestation or
KYC-field-guard substrate:

  * **Operator-of-record:**
    `phylanx-oracle/deploy/operator_manifest.json`
    `operator_contact` field.
  * **Per-jurisdiction regulator inquiry path:**
    `launch/runbooks/aml_complaint_response.md`.
  * **Bug bounty / disclosure:** see
    `SECURITY.md` at the repo root.

The substrate is auditable in code. If you find a divergence
between this notice and the gate, the gate wins; please open an
issue referencing the divergence so the notice can be updated.
