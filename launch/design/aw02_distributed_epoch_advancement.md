# AW-02 — Distributed Epoch Advancement (M-of-N Threshold)

**Status:** IMPLEMENTED. Phase 4 ship-blocker, resolved.
**Audit finding:** AW-02 (Centralized Epoch Advancement)
**Owner:** cluster engineering
**Related code:**
- `programs/health-oracle/src/instructions/advance_epoch.rs`
- `programs/health-oracle/src/state/epoch_state.rs`
- `programs/health-oracle/src/events.rs` (`EpochAdvancedByThreshold`)
- `phylanx-sdk/src/advance_epoch.ts` (`advancePayloadDigest`)
- `tests/aw02_threshold_advance.integration.ts`
- `launch/runbooks/epoch_advance_stalled.md`

---

## The threat AW-02 closed

Every HealthCertificate PDA is keyed on the current epoch
(`["cert", agent, epoch]`). Epoch progression is therefore the
single timing primitive the entire cert-issuance pipeline depends on.

Before AW-02 the Tier-1 advance path was a **single-key gate**:
`EpochState.advance_authority` was the sole signer that could tick the
epoch during the 1×-to-2× duration window. The VULN-02 fix added a
liveness fallback (any cluster member at 2× duration) so a lost or
compromised key could not permanently halt the protocol — but the
Tier-1 normal path remained single-key. That left a coverage gap the
audit (AW-02) flagged: every OTHER consensus-critical operation in
the protocol (score submission, cert issuance, oracle key rotation)
goes through the cluster's M-of-N threshold mechanism. Only epoch
advancement did not.

The single-key Tier-1 path enabled the following attacks even with
the VULN-02 fallback in place:

| Attack                                  | Mechanism                                                                                                                                                     | Impact                                                                                                                                                                                                                  |
|-----------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Tick timing manipulation**            | Compromised advance_authority key advances at an attacker-chosen moment within the [1×, 2×) window.                                                          | Race condition: the attacker decides which cert lands in epoch N vs N+1, potentially burying a bad score in a fresh epoch or stranding a good score in a stale one.                                                    |
| **Liveness-window grief**               | Compromised key refuses to advance, forcing every cluster to wait the FULL 2× duration (24 extra hours) before the Tier-2 fallback opens.                  | At minimum 24h of stale certs for every agent in the system — even though the cluster is otherwise healthy. Degraded SLO with no on-chain remedy until the 2× window opens.                                            |
| **Cluster-asymmetric authority**        | Score submission requires M-of-N cluster consensus. Cert issuance requires M-of-N Ed25519 attestations. Key rotation requires N-of-M attestations + timelock. Epoch advance: ONE key. | Inconsistent threat model — the weakest link in the chain. An attacker only needs to compromise ONE key to manipulate the protocol's primary timing primitive, even after defeating the M-of-N protection elsewhere. |

---

## The fix — M-of-N threshold-attested Tier-1 advance

The Tier-1 normal path now requires `consensus_threshold(cluster)`
distinct Ed25519 precompile signatures over a canonical advance
digest, in the SAME transaction as the `advance_epoch` instruction.
The same atomic-bundle pattern already used by:

- `certificate_issuer::issue_certificate` — cluster sigs over the cert
  payload digest
- `certificate_issuer::challenge_certificate` — disjoint attester sigs
  over the challenge payload digest

The submitter of the tx is just the fee payer / tx assembler; they
have NO sole-signer privilege. The protocol cannot tell whose tx it
is and does not care — what it verifies is the precompile signatures
in the tx's instruction list.

### Canonical advance digest

```
sha256(
    "phylanx-epoch-advance"        // 21-byte domain tag
    || current_epoch.to_le_bytes() //  8 bytes
    || target_epoch.to_le_bytes()  //  8 bytes (= current_epoch + 1)
    || last_advanced_at.to_le_bytes() // 8 bytes (i64 from EpochState)
)
```

The `last_advanced_at` field is the single most important anti-replay
mechanism: an attacker who collects cluster sigs for advance N→N+1 at
some time T1 CANNOT later push them through for the SAME numeric
advance at T2, because the `last_advanced_at` snapshot at the moment
of the previous tick is folded into the digest. Any two real ticks
differ on this field.

The domain tag `phylanx-epoch-advance` is distinct from
`phylanx-cert-v1` (cert signing) and `phylanx-aw01-ext-challenge`
(challenge attestations), so no honest cluster sig produced for any
other purpose can be lifted into an advance attestation.

### Two-tier authority preserved

```
Tier 1 (normal, ≥ 1× duration):
    Verify M-of-N cluster Ed25519 attestations over the canonical
    advance digest. Counts only distinct signers from
    OracleConfig.oracle_keys. M = consensus_threshold(cluster)
    = floor(N/2) + 1.

Tier 2 (liveness, ≥ 2× duration):
    UNCHANGED. Any single current cluster member may advance solo,
    no precompile attestations required. The catastrophic-failure
    recovery path. Emits EpochAdvancedByFallback so an operator
    pages.
```

The Tier-1 path is tried first. The Tier-2 fallback only fires if
the M-of-N path could not be assembled AND the fallback window is
open AND the submitter is a current cluster member.

### The legacy `advance_authority` field

Retained in `EpochState` for layout compatibility (the singleton is
already deployed; removing the field would force a realloc-migration).
It is now a **non-authoritative hint** — neither Tier-1 nor Tier-2
reads it. `rotate_advance_authority` still works, updating the hint
for ops-team conventions. A stale or zero value never blocks
advancement.

---

## Threat-model coverage matrix (post-AW-02)

| Threat                                                  | Tier 1 (M-of-N)                              | Tier 2 (fallback)                           |
|---------------------------------------------------------|----------------------------------------------|---------------------------------------------|
| **Single cluster key compromise**                       | Defeated: insufficient sigs without quorum. | Defeated: fallback also requires the key to be cluster-member; one compromised key still cannot push without 2× delay. |
| **Tick timing race within window**                     | Defeated: needs M-of-N online and coordinated. | N/A — fallback only opens after window.    |
| **Permanent halt via lost keys**                       | Defeated: fallback path remains.            | Defeated: any single cluster member can act.|
| **Cluster < threshold for ≥ 2× duration**              | Detected via fallback event.                | Mitigated but flagged P0 — see runbook.    |
| **Cluster < threshold AND fallback unavailable**       | Detected via stuck `current_epoch`.         | This is the catastrophic case; manual recovery via admin path. |
| **Cross-tick sig replay**                              | Defeated: `last_advanced_at` in digest.     | N/A.                                       |
| **Cross-protocol sig replay (cert ↔ challenge ↔ advance)** | Defeated: distinct domain tag.          | N/A.                                       |
| **Stale-`advance_authority`-blocks-advance grief**     | Defeated: field is no longer read.          | Defeated: same.                            |

---

## Why an atomic-bundle Ed25519 design (not two-phase governance)

A two-phase propose/attest/enact pattern (like VULN-13's key
rotation governance) was considered and rejected for daily epoch
advancement. The reasoning:

1. **Frequency.** Key rotation happens rarely (months between
   rotations). Epoch advance happens DAILY. Two-phase governance
   adds 3 txs per ceremony plus a timelock-style window that
   conflicts with "advance on the boundary".
2. **Pattern match.** The cluster ALREADY assembles Ed25519
   bundles in a single tx for cert issuance. Cluster nodes have
   the off-chain signing infrastructure for this exact pattern.
   Adding a second pattern (two-phase) doubles operational
   complexity for no security gain.
3. **State minimisation.** A two-phase advance would require a
   `PendingEpochAdvance` PDA per cycle. The atomic bundle has
   ZERO additional on-chain state — the EpochState singleton is
   the only mutated account.
4. **Coordination cost.** Cluster nodes already coordinate
   off-chain for scoring (commit-reveal rounds). Reusing the
   same coordination layer for the daily advance digest is
   trivial; standing up a separate proposal/attestation flow
   on chain would require a new daemon role.

The atomic Ed25519-bundle pattern is the right shape for any
HIGH-FREQUENCY M-of-N op. Two-phase governance is the right
shape for RARE, HIGH-STAKES configuration changes.

---

## Acceptance criteria — all met

- [x] Tier-1 advance requires `consensus_threshold(cluster)`
      distinct cluster Ed25519 signatures over the canonical digest.
- [x] Single-key `advance_authority` Tier-1 path REMOVED. The
      field is retained as a non-authoritative hint.
- [x] Tier-2 liveness fallback unchanged: any single cluster
      member at ≥ 2× duration.
- [x] Domain-separation tag `phylanx-epoch-advance` distinct from
      `phylanx-cert-v1` and `phylanx-aw01-ext-challenge`.
- [x] `last_advanced_at` folded into digest — defeats cross-tick
      replay of stashed cluster sigs.
- [x] `EpochAdvancedByThreshold` event emitted on Tier-1 advance
      with `attester_count` field for trend monitoring.
- [x] 13 unit tests in `advance_epoch::tests` cover digest
      properties, threshold math, cluster filtering, and replay
      defences.
- [x] 7 layout / domain tests in `tests/epoch_logic.rs` pin the
      domain tag bytes and digest binding properties.
- [x] 11 SDK tests in `phylanx-sdk/test/advance_epoch.test.ts`
      pin off-chain ↔ on-chain digest parity.
- [x] Integration test in
      `tests/aw02_threshold_advance.integration.ts` covers the
      happy path (2-of-3 sigs) and three negative paths
      (below-threshold, wrong-digest, non-cluster).
- [x] `LAUNCH_CHECKLIST` extended with AW-02 gate (audit) and
      daily-review gate (post-launch).
- [x] Runbook at `launch/runbooks/epoch_advance_stalled.md`.
- [x] State + handler doc-comments updated to describe the
      deprecation of single-key advance.

---

## What "done" looks like in production

Every steady-state epoch tick on mainnet emits a pair of events:

```
EpochAdvanced            { from_epoch: N, to_epoch: N+1, advanced_at: T }
EpochAdvancedByThreshold { from_epoch: N, to_epoch: N+1, advanced_at: T,
                           attester_count: M, submitter: <fee payer> }
```

where `M >= consensus_threshold(OracleConfig.oracle_keys)`. The
post-launch daily-review gate verifies this pairing. Any
`EpochAdvancedByFallback` event in steady state is a P0; the
runbook governs the response.
