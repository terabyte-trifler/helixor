# AW-03 — On-Chain Baseline Data Availability

**Status:** IMPLEMENTED. Phase 4 ship-blocker, resolved.
**Audit finding:** AW-03 (No On-Chain Data Availability Proof)
**Owner:** cluster engineering + integrator-experience
**Related code:**
- `programs/health-oracle/src/state/baseline_data.rs` (`BaselineDataAccount`)
- `programs/health-oracle/src/state/agent_registration.rs` (`baseline_data_pointer`)
- `programs/health-oracle/src/instructions/commit_baseline.rs`
- `programs/certificate-issuer/src/state/baseline_stats.rs` (`baseline_commit_nonce`)
- `programs/certificate-issuer/src/state/health_certificate.rs` (`baseline_commit_nonce`, layout v6)
- `programs/certificate-issuer/src/signing.rs` (`cert_payload_digest`)
- `programs/certificate-issuer/src/instructions/record_baseline.rs`
- `phylanx-oracle/oracle/cluster/cert_signing.py` (`baseline_commit_nonce` kwarg)
- `phylanx-oracle/baseline/hashing.py` (canonical payload bytes)
- `phylanx-sdk/src/baseline_provenance.ts` (`verifyBaselineProvenance`)
- `phylanx-sdk/src/pdas.ts` (`baselineDataPda`)
- `audit/baseline_provenance_check.py`
- `launch/runbooks/baseline_provenance.md`

---

## The threat AW-03 closed

`baseline_hash` on `AgentRegistration` is a 32-byte SHA-256 commitment over
behavioural baseline statistics (feature means, standard deviations,
txtype distribution, action entropy, daily success series). The hash is
folded into every score-deviation calculation and every certificate the
cluster signs.

Before AW-03 the on-chain record contained the COMMITMENT but not the
BYTES BEHIND IT. The 32-byte value proved nothing about provenance — a
third party reading a cert had no way to:

1. **Re-derive** the hash from observable inputs. The canonical payload
   lived only in the cluster's Postgres tables; an external consumer
   could not reach it.
2. **Audit** what behavioural model a given cert was scored against.
   The baseline could rotate any time `commit_baseline` was called, and
   the only on-chain artefact of the rotation was a fresh hash.
3. **Detect substitution.** A compromised cluster DB could replace the
   baseline mid-attack: legitimate baseline → adversarial baseline →
   harmful score → adversarial baseline → legitimate baseline. Every
   step would produce a valid hash; no off-chain log would survive a
   coordinated DB rewrite.

The single-source-of-truth gap mirrored the AW-01 commitment-without-DA
shape but for behavioural data rather than upstream-input data. AW-01
fixed the input layer via cluster-majority commitments + slot-anchor
binding; AW-03 fixes the baseline layer via on-chain bytes.

| Attack                                  | Mechanism                                                                                                                              | Impact                                                                                                                                                          |
|-----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Silent baseline substitution**        | Compromised DB rewrites the baseline rows backing a given `baseline_hash`. The hash on chain still matches the rewritten rows.        | Every cert issued against that baseline is unverifiable — the consumer cannot tell the cluster's stored bytes were swapped post-commit.                         |
| **Rotation-and-replay**                 | Cluster commits baseline A → signs adversarial cert → commits baseline B → claims cert was scored against B all along.                | Audit trail is lost: there is no on-chain record of WHICH baseline a given cert was scored against, only the hash at issuance time.                            |
| **Asymmetric trust**                    | AW-01 already requires cluster-majority + Solana-ledger binding for input data. Baseline data has neither — strictly weaker.            | Inconsistent threat model — a sophisticated adversary attacks the weakest link. Baseline manipulation lands harmful scores without tripping AW-01 defences.    |

---

## The fix — on-chain canonical payload + per-rotation immutable account

`commit_baseline` now writes a `BaselineDataAccount` PDA each time it
runs:

```
seeds = ["baseline_data", agent_wallet, commit_nonce.to_le_bytes()]
```

At init time the handler enforces:

```
sha256(BaselineDataAccount.payload) == AgentRegistration.baseline_hash
```

Because the seeds include `commit_nonce` AND the handler enforces
strictly-monotonic `commit_nonce` (`BaselineNonceRegression` on
regress), every rotation produces a NEW immutable PDA. Old baseline
data accounts stay on chain forever — a permanent audit trail.

The `payload` field stores the EXACT canonical JSON bytes produced by
`baseline.hashing.build_hash_payload` + `json.dumps(sort_keys=True,
separators=(",", ":"))`. A consumer with only the account can:

1. `sha256(account.payload)` and compare to `cert.baseline_hash`.
2. Parse the JSON and audit the underlying statistics directly.

No external DA service (Arweave / IPFS / Celestia) is involved. Solana
itself is the DA layer; the trust domain is unchanged from the rest of
phylanx.

### Pointer carved from the registration reserve

`AgentRegistration` carries a `baseline_data_pointer: Pubkey` field
carved out of the original 64-byte reserve (32 bytes consumed, 32
remaining). It names the LATEST `BaselineDataAccount` PDA. Cert
consumers do not strictly need it — the cert itself carries the
`baseline_commit_nonce` and `agent`, which is all
`baselineDataPda(...)` needs — but the pointer gives a cheap "latest"
read for cluster operators and integration tests.

### Cert-payload digest binds the nonce

`HealthCertificate` is at `layout_version = 6` and carries
`baseline_commit_nonce: u64`. `BaselineStats` carries the same field.
Both are folded into `cert_payload_digest` as 8 BE bytes appended after
the AW-01-EXT slot-anchor block:

```
sha256(
    agent || epoch(BE8) || score(BE2) || alert_tier(1) || flags(BE4)
    || baseline_hash(32) || immediate_red(1)
    || input_commitment(32)                       // AW-01
    || slot_anchor_slot(BE8) || slot_anchor_hash(32)   // AW-01-EXT
    || baseline_commit_nonce(BE8)                 // AW-03
)
```

A cluster cannot issue a cert that names baseline N while the on-chain
record at `baselineDataPda(agent, N)` has different bytes — the digest
the cluster signs IS the digest the on-chain verifier reproduces from
the cert's stored fields, and the bytes-behind-the-hash live at a
deterministic PDA that any consumer can fetch.

### Off-chain ↔ on-chain digest parity

Python `cert_payload_digest` accepts `baseline_commit_nonce` as a
keyword-only argument with `default=0`. The default-0 path is reserved
for legacy/test code that predates AW-03; production callsites pass
the agent's current nonce explicitly. The audit sweep
(`audit/baseline_provenance_check.py`) enforces this asymmetry by
scoping its production-pin scan to `phylanx-oracle/oracle/...` and
allowing test code to exercise the legacy path freely.

The TS test harness (`phylanx-programs/tests/certificate_issuer.integration.ts`)
re-implements the digest layout end-to-end and is the canonical fixture
for the on-chain ↔ off-chain ↔ SDK byte parity guarantee.

---

## Threat-model coverage matrix (post-AW-03)

| Threat                                                  | Defence                                                                                                                                         |
|---------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| **Silent baseline-bytes substitution**                  | Defeated: on-chain `sha256(payload) == baseline_hash` is enforced at write time and the account is immutable thereafter.                       |
| **Rotation-and-replay (history rewrite)**               | Defeated: each `commit_nonce` produces a UNIQUE PDA; old accounts persist as the audit trail.                                                  |
| **Cert claims baseline N, account at N differs**        | Impossible to construct: the cert's `baseline_hash` and `baseline_commit_nonce` are both folded into the threshold-signed digest.              |
| **Nonce regression / replay an old baseline**           | Defeated: `commit_baseline` rejects with `BaselineNonceRegression` if `new_nonce <= current_nonce`.                                            |
| **Consumer fetches wrong PDA**                          | Mitigated: `baselineDataPda(agent, nonce)` is deterministic; SDK returns `BaselineHashMismatch` on any divergence.                             |
| **Pre-AW-03 cert presented to a post-AW-03 consumer**   | Detected: SDK returns `PreV6Cert` — the consumer's integration policy pins the v6 cutover epoch.                                               |

---

## Why on-chain bytes (not Arweave / IPFS / Celestia)

External DA layers were considered and rejected:

1. **Trust-domain expansion.** Arweave's permanence depends on its
   own consensus and economic incentives. IPFS pins are best-effort.
   Celestia adds a second consensus surface. A phylanx cert consumer
   already trusts Solana finality for the cert itself; layering a
   second DA system means the consumer now trusts BOTH Solana AND the
   chosen DA layer for a single semantic operation.

2. **Cross-chain verification ergonomics.** Solana programs cannot
   verify Arweave / IPFS / Celestia proofs cheaply at write time. The
   on-chain `sha256(payload) == baseline_hash` check would have to be
   shifted off chain into a fraud-proof window, which is the exact
   "DA assumption" footgun AW-03 is closing.

3. **Cost.** A 3 KB baseline payload at devnet rent (currently
   ~0.0007 SOL/KB-year) costs <0.003 SOL once. An Arweave permaweb
   write is comparable; the wire trip and pinning ops are not.

4. **Operational simplicity.** One trust surface, one fetch path, one
   audit script. Every existing integration tool (RPC, indexer, SDK)
   already speaks Solana.

External DA is the right shape when payload sizes dwarf chain-state
costs (megabytes per item) OR when the producer and consumer live on
different chains. Neither applies here.

---

## Why nonce-keyed PDAs (not overwrite-in-place)

An alternative was to keep a single `BaselineDataAccount` per agent and
overwrite the payload on each rotation. Rejected:

1. **Audit trail lost.** A regulator or partner investigating a past
   cert at epoch E would need to know what baseline was active at E.
   With overwrite-in-place the answer is "whatever happens to be
   stored right now" — useless. With nonce-keyed PDAs the answer is
   `baselineDataPda(agent, cert.baseline_commit_nonce)` — exact.

2. **Race conditions.** Cert issuance and baseline rotation are
   independent ops. With overwrite-in-place a rotation racing a cert
   issuance could land the cert against a baseline different from the
   one its `baseline_hash` names. With nonce-keyed PDAs the cert pins
   the nonce, the PDA seed pins the nonce, and the race is
   structurally impossible.

3. **Rent neutrality at small N.** Rotations are infrequent (one per
   30-day window per agent, by current cluster policy). The "history
   bloat" concern doesn't materialise: 12 baselines/agent/year × 3 KB
   ≈ 36 KB/agent/year. Acceptable for a system whose value depends
   on auditability.

---

## Acceptance criteria — all met

- [x] `BaselineDataAccount` PDA at seeds `["baseline_data", agent,
      commit_nonce_le]` storing the canonical payload bytes.
- [x] `commit_baseline` enforces `sha256(payload) == baseline_hash`
      at init time.
- [x] `commit_baseline` enforces strictly-monotonic `commit_nonce`
      (rejects regress with `BaselineNonceRegression`).
- [x] `AgentRegistration.baseline_data_pointer: Pubkey` carved from
      reserve, updated on every commit.
- [x] `BaselineStats.baseline_commit_nonce: u64` threaded through
      `record_baseline`.
- [x] `HealthCertificate` at `layout_version = 6` carries
      `baseline_commit_nonce`; the field is folded into
      `cert_payload_digest` as 8 BE bytes.
- [x] Python `cert_payload_digest(... , baseline_commit_nonce=)`
      keyword-only kwarg with `default=0` for legacy compatibility.
- [x] Audit sweep `audit/baseline_provenance_check.py` flags any
      production callsite that drops the binding. PYTHON_ROOTS is
      scoped to `phylanx-oracle/oracle/...` so test callers can
      exercise the legacy default freely. Self-test
      `audit/test_baseline_provenance_check.py` pins the detector
      contract (10 passing).
- [x] SDK `verifyBaselineProvenance(connection, healthOracleProgram, cert)`
      reproduces the hash byte-for-byte from the fetched
      `BaselineDataAccount`. Returns typed rejections (`NoDataAccount`,
      `AccountNotFound`, `AccountUnreadable`, `HashMismatch`,
      `AgentMismatch`, `NonceMismatch`).
- [x] SDK `baselineDataPda(healthOracle, agent, commitNonce)`
      deterministic PDA derivation.
- [x] Rust unit + integration tests: 17 health-oracle tests,
      31 certificate-issuer tests, 5 integration test scenarios in
      `certificate_issuer.integration.ts` exercising the full
      baseline-commit → record-baseline → issue-certificate flow.
- [x] SDK tests: 9 cases in `phylanx-sdk/test/baseline_provenance.test.ts`
      (happy path + every rejection variant).
- [x] Python tests: digest changes with nonce, default == 0,
      out-of-range rejected.
- [x] `LAUNCH_CHECKLIST` extended with AW-03 audit gate, AW-03
      first-live-cert ship-discipline gate, and AW-03 daily-review
      gate.
- [x] Runbook at `launch/runbooks/baseline_provenance.md`.

---

## What "done" looks like in production

Every steady-state `commit_baseline` on mainnet emits a
`BaselineCommitted` event with a strictly-monotonic `commit_nonce`
for that agent. Every steady-state `issue_certificate` emits a cert
at `layout_version = 6` with `baseline_commit_nonce > 0`. Any DeFi
consumer can:

```ts
import { verifyBaselineProvenance } from "@phylanx/sdk";

const result = await verifyBaselineProvenance(cert, connection);
if (!result.ok) {
  // Reject the score. Do NOT relax the check.
}
```

and reject any cert whose on-chain bytes do not match its on-chain
hash — without trusting the cluster, the indexer, or any external DA
service. The post-launch daily-review gate verifies this end-to-end
and the runbook governs the response to any `BaselineHashMismatch`
finding.
