# AW-04 — Scoring Engine Provenance (Code Hash + Components DA)

**Status:** IMPLEMENTED. Phase 4 ship-blocker, resolved.
**Audit finding:** AW-04 (Scoring Engine is a Black Box to On-Chain Consumers)
**Owner:** cluster engineering + integrator-experience
**Related code:**
- `programs/certificate-issuer/src/state/score_components.rs` (`ScoreComponentsAccount`)
- `programs/certificate-issuer/src/state/health_certificate.rs` (`scoring_code_hash`, layout v7)
- `programs/certificate-issuer/src/signing.rs` (`cert_payload_digest` — 64 new AW-04 bytes)
- `programs/certificate-issuer/src/instructions/issue_certificate.rs` (init the components PDA + fold the hashes)
- `programs/health-oracle/src/instructions/submit_score.rs` (CPI forwarding)
- `phylanx-oracle/scoring/bundle_hash.py` (`compute_scoring_bundle_hash`, `bundle_members`)
- `phylanx-oracle/oracle/score_components.py` (canonical-JSON serializer + sha256)
- `phylanx-oracle/oracle/cluster/cert_signing.py` (`scoring_code_hash=` + `score_components_hash=` kwargs)
- `phylanx-oracle/oracle/cluster/pipeline.py` (threads both through to the digest + on-chain write)
- `phylanx-sdk/src/scoring_provenance.ts` (`verifyScoreComputation`, `verifyScoringCodeHash`, `replayScoreFromComponents`)
- `phylanx-sdk/src/decode.ts` (`decodeScoreComponentsAccount`, v7 cert decode)
- `phylanx-sdk/src/pdas.ts` (`scoreComponentsPda`)
- `audit/scoring_provenance_check.py`
- `audit/test_scoring_provenance_check.py`
- `launch/runbooks/score_provenance.md`

---

## The threat AW-04 closed

A v6 certificate carries a 16-bit `score` and 32-bit `flags`. The
threshold signature attests that some signed cluster emitted the
number — it does NOT attest that the number is a faithful reduction
of behavioural inputs into the documented scoring algorithm. An
on-chain consumer reading the cert had no mechanism to:

1. **Audit which scoring kernel the number came from.** The dimension
   weights, normalisation curves, and the composite formula live in
   `phylanx-oracle/scoring/`. A compromised cluster could ship an
   adversarial fork that re-weights `flow_health` to favour a
   captured agent — every cert still threshold-signed, still
   verifiable as "from the cluster", and the on-chain bytes would be
   indistinguishable.
2. **Replay the score from observable inputs.** Even if the kernel
   version were pinned, the per-dimension breakdown (which
   contribution did each of the five dimensions make? what was each
   dimension's normalised value? which flags fired?) lived only in
   the cluster's Postgres tables.
3. **Detect a kernel swap.** An adversarial cluster could compute the
   "correct" score for an agent, then ship a one-day kernel
   modification that biases a different agent's score upward,
   pocket the DeFi gains, then revert. Every cert in that window
   would carry a valid signature. No on-chain artefact would name
   the kernel version that produced the bias.

The shape mirrors AW-01 (input-DA) and AW-03 (baseline-DA): a
commitment is on chain (here implicitly: the `score`+`flags` ARE the
commitment) but the BYTES BEHIND it are not. AW-04 closes the gap by
adding both prongs on chain — the scoring kernel itself becomes a
versioned, hashed artefact, AND the per-dimension breakdown is
written to a write-once PDA that the cluster's threshold signature
binds to.

| Attack                                  | Mechanism                                                                                                                          | Impact                                                                                                                                                          |
|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Silent scoring-kernel swap**          | Cluster ships a forked `scoring/composite.py` that biases one agent. The signed cert still carries a valid score field.            | Every consumer that trusts the cert at face value accepts the biased score. The legitimate kernel cannot be re-derived from on-chain state.                     |
| **Components fabrication**              | Cluster claims `flow_health=0.9, action_diversity=0.05, ...` but the underlying behavioural data does not support these dim values. | Consumers cannot tell whether the headline score is structurally consistent with its dimension breakdown — the breakdown only lives in cluster Postgres.        |
| **Algo / weights version drift**        | Cluster updates `SCORING_WEIGHTS_VERSION` mid-attack without re-attesting the new version on chain.                                 | A cert at epoch E is scored against weights vX; a cert at epoch E+1 is scored against weights vY; consumer has no way to tell which.                            |

---

## The fix — three prongs

### 1. Code-bundle hash, folded into the digest

`phylanx-oracle/scoring/bundle_hash.py` computes a deterministic
SHA-256 over the canonical scoring-kernel source bytes:

```python
sha256(
    b"phylanx-scoring-bundle-v1\n" ||
    for each sorted path:
        path_bytes || b"\n" || sha256(file_bytes) || b"\n"
    ||
    f"algo=v{SCORING_ALGO_VERSION}\n".encode() ||
    f"weights=v{SCORING_WEIGHTS_VERSION}\n".encode()
)
```

The five members pinned today (`scoring/composite.py`,
`scoring/weights.py`, `scoring/_gaming.py`, `scoring/determinism.py`,
`detection/types.py`) are the closure of source files whose change
can shift the headline score. Adding/removing a member is a
deliberate act that invalidates every prior cert's hash by
construction — exactly the property we want.

`HealthCertificate` is at `layout_version = 7` and carries
`scoring_code_hash: [u8; 32]` appended after the AW-03 nonce.
The cert-payload digest folds it in as 32 BE bytes, AND the
on-chain handler refuses to write a cert whose `scoring_code_hash`
is all-zero — by construction, every v7 cert names a SPECIFIC
kernel version on chain.

### 2. Components account, hashed on chain

A second PDA, `ScoreComponentsAccount`, sits at:

```
seeds = ["score_components", agent_wallet, epoch.to_le_bytes()]
```

The instruction takes the RAW canonical-JSON payload bytes
(`score_components_payload: Vec<u8>`, ≤ 4 KB) and computes
`sha256(payload)` ON CHAIN. The hash is folded into the
cert-payload digest as 32 BE bytes appended after `scoring_code_hash`.
**The chain never trusts a caller-supplied hash** — the threshold
signatures necessarily attest to whatever bytes the handler actually
wrote.

The payload schema is canonical JSON (`json.dumps(sort_keys=True,
separators=(",", ":"))`) with these required keys (schema `v=1`):

```
{
  "v":              1,
  "algo_v":         "<algo version label>",
  "weights_v":      "<weights version label>",
  "score":          0..1000,
  "raw_score":      sum of dim contribs,
  "delta_clamped":  bool,
  "previous_score": 0..1000 | null,
  "alert":          "GREEN" | "YELLOW" | "RED",
  "immediate_red":  bool,
  "agg_flags":      u32,
  "confidence":     "<n>/<m>",
  "gaming":         { ... gaming subreport ... },
  "gaming_drop":    bool,
  "dims": [
    { "id": "<dim_id>", "norm": <float>, "flags": <u32>,
      "algo_v": "<algo version>", "contrib": <int> },
    ... five entries, canonical order ...
  ]
}
```

Floating-point fields use the `canon_float` serializer (9 fractional
decimals, `-0.0` collapsed to `0.0`) so a bit-exact round-trip is
possible from any deserialiser.

### 3. SDK replay verifier

`@phylanx/sdk` exports `verifyScoreComputation(connection,
certificateIssuer, cert)`. The flow:

1. `scoreComponentsPda(certificateIssuer, agent, epoch)` → PDA.
2. Fetch + decode → `DecodedScoreComponentsAccount`.
3. Cross-check `account.agent === cert.agent && account.epoch === cert.epoch`.
4. Recompute `sha256(account.payload)`; compare to
   `account.componentsHash`. **This is the AW-04 binding** —
   if these diverge, the on-chain handler is broken or the
   chain was corrupted (impossible by construction; treat as P0).
5. Parse the canonical-JSON payload; pin `v === 1`.
6. Replay: `raw = sum(d.contrib for d in dims)` →
   `clamp(0, 1000, raw)` → optional `delta_guard_rail` (200-pt
   max move from `previous_score`).
7. Cross-check `replay.finalScore === cert.score &&
   parsed.score === cert.score && parsed.deltaClamped === replay.deltaClamped`.

A separate sync helper, `verifyScoringCodeHash(cert,
expectedHash)`, lets the consumer pin the deployed kernel hash
against a caller-supplied value (read from a configured
`OracleConfig` or pinned in the partner's integration policy).
Pre-v7 certs return `CodeHashCheckResult.PreV7Cert`; the
consumer's policy declares the cutover.

### Cert-payload digest layout (post-AW-04)

```
sha256(
    agent(32) || epoch(BE8) || score(BE2) || alert_tier(1) || flags(BE4)
    || baseline_hash(32) || immediate_red(1)
    || input_commitment(32)                       // AW-01
    || slot_anchor_slot(BE8) || slot_anchor_hash(32)  // AW-01-EXT
    || baseline_commit_nonce(BE8)                 // AW-03
    || scoring_code_hash(32)                      // AW-04
    || score_components_hash(32)                  // AW-04
)
```

The Python `cert_payload_digest`, the Rust on-chain
`cert_payload_digest`, and the TS test helper in
`phylanx-programs/tests/certificate_issuer.integration.ts` all
reproduce these bytes byte-for-byte — the integration test is the
canonical fixture for the three-way byte parity.

---

## Threat-model coverage matrix (post-AW-04)

| Threat                                                  | Defence                                                                                                                                              |
|---------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Silent kernel swap**                                  | Defeated: every v7 cert's `scoring_code_hash` is folded into the threshold-signed digest. A swap changes the hash → the digest → the signatures.    |
| **Components fabrication**                              | Defeated: `sha256(payload) == components_hash` is enforced on chain at init time, and the hash is folded into the digest.                            |
| **Replay arithmetic divergence** (score ≠ Σ contribs)   | Defeated: SDK `replayScoreFromComponents` re-derives the headline score; any divergence is a `ScoreReplayMismatch` rejection.                       |
| **Algo / weights version drift**                        | Defeated: `algo_v` and `weights_v` are bytes of `scoring_code_hash` (via the version-label suffix) AND are pinned inside the components payload.   |
| **Pre-AW-04 cert presented to a post-AW-04 consumer**   | Detected: SDK returns `PreV7Cert` for layout v < 7 OR zero `scoring_code_hash`. Partner pins the v7 cutover epoch in their integration policy.     |
| **Adversarial-cluster forged components payload**       | Impossible: the on-chain handler computes the hash from the bytes it stored. The cluster cannot lie about what the chain wrote.                     |

---

## Why on-chain bytes (not Arweave / IPFS / Celestia)

Same rationale as AW-03 (cf. that doc's "Why on-chain bytes" section).
The 4 KB cap on `score_components_payload` keeps rent under the
0.001 SOL per cert ballpark while preserving full byte-level
auditability without expanding the trust domain.

## Why per-(agent, epoch) PDAs (not per-(agent) overwrite)

Mirrors AW-03's nonce-keyed-PDA decision. Each cert at epoch E names
its OWN components account at `scoreComponentsPda(agent, E)`. The
account is `init` (write-once); old components persist as a
permanent audit trail. A regulator investigating an old cert can
always fetch the exact dimension breakdown that produced that score,
not "whatever happens to be stored right now".

## Why the chain computes the components hash (not the cluster)

Two reasons:

1. **The chain is the ground-truth verifier.** If the cluster
   supplies both the payload AND the hash, an honest cluster gains
   nothing (the chain still checks `sha256(payload) == hash`) but a
   compromised cluster gains the ability to mismatch the two if the
   on-chain check is ever broken in a future upgrade. Removing the
   check from the trusted code path means the bug surface shrinks
   — the chain CAN'T be wrong about its own hash function.
2. **Schema robustness.** The chain doesn't need to parse the
   payload's JSON to hash it. The hash is over raw bytes, so adding
   a future schema field (still inside the 4 KB cap) does not
   require an on-chain program upgrade. The SDK pins
   `v === 1` and refuses unknown schema versions — that's the right
   place for the parsing contract.

---

## Acceptance criteria — all met

- [x] `ScoreComponentsAccount` PDA at seeds `["score_components",
      agent, epoch_le]` storing canonical-JSON payload bytes.
- [x] `issue_certificate` enforces `sha256(payload) ==
      components_hash` at init time (handler computes the hash;
      a caller-supplied hash is impossible to forge).
- [x] `issue_certificate` rejects empty payload
      (`ScoreComponentsPayloadEmpty`), oversize payload
      (`ScoreComponentsPayloadTooLarge`, > 4 KB), zero
      `scoring_code_hash` (`MissingScoringCodeHash`), and zero
      derived `components_hash` (`MissingScoreComponentsHash`).
- [x] `HealthCertificate` at `layout_version = 7` carries
      `scoring_code_hash`; the field is folded into
      `cert_payload_digest` as 32 BE bytes appended after the
      AW-03 nonce. `score_components_hash` is appended after that
      (also 32 BE bytes).
- [x] Python `cert_payload_digest(... , scoring_code_hash=,
      score_components_hash=)` keyword-only kwargs with
      32-zero defaults for legacy compatibility.
- [x] `phylanx-oracle/scoring/bundle_hash.py` —
      `compute_scoring_bundle_hash()` returns 32 deterministic
      bytes; `bundle_members()` returns the sorted canonical
      tuple. Five members pinned today.
- [x] `phylanx-oracle/oracle/score_components.py` —
      `build_components_and_hash(score_result, baseline,
      previous_score)` returns `(payload_bytes,
      components_hash)`; `serialise_canonical(payload_dict)`
      enforces the 4 KB ceiling and produces deterministic
      byte output with `sort_keys=True, separators=(",", ":")`.
- [x] Pipeline (`oracle/cluster/pipeline.py`) computes the
      bundle hash + components hash and threads both through
      to `cert_payload_digest`.
- [x] Audit sweep `audit/scoring_provenance_check.py` flags any
      production callsite that drops the binding. PYTHON_ROOTS
      scoped to `phylanx-oracle/oracle/...`. 5 pins:
      `cert_payload_digest-missing-scoring_code_hash`,
      `cert_payload_digest-missing-score_components_hash`,
      `certPayloadDigest-missing-scoringCodeHash`,
      `certPayloadDigest-missing-scoreComponentsHash`,
      `scoreComponentsPda-missing-epoch`. Self-test
      `audit/test_scoring_provenance_check.py` pins the detector
      contract (15 passing).
- [x] SDK `verifyScoreComputation(connection,
      certificateIssuer, cert)` re-fetches the PDA,
      re-asserts the hash binding, parses the payload, and
      replays the score arithmetic. Returns typed rejections
      (`NoComponentsAccount`, `AccountNotFound`,
      `AccountUnreadable`, `HashMismatch`, `AgentMismatch`,
      `EpochMismatch`, `PayloadMalformed`,
      `ScoreReplayMismatch`).
- [x] SDK `verifyScoringCodeHash(cert, expectedHash)` returns
      `Ok` / `Mismatch` / `PreV7Cert` / `CodeHashMismatch`.
- [x] SDK `scoreComponentsPda(certIssuer, agent, epoch)`
      deterministic PDA derivation.
- [x] SDK `decodeScoreComponentsAccount(data)` and
      v7-aware `decodeHealthCertificate` (210 → 242 bytes,
      `scoring_code_hash` appended; legacy v6 certs decode
      with a 32-byte zero sentinel).
- [x] Rust unit tests: 93+ certificate-issuer tests including
      score-components layout, signing-digest fold tests.
- [x] Python tests: 72 across `tests/scoring/test_aw04_bundle_hash.py`
      (14), `tests/oracle/test_aw04_score_components.py` (22),
      `tests/oracle/test_cert_signing.py` (36, of which 7
      are new AW-04 fold tests).
- [x] SDK tests: 28 cases in
      `phylanx-sdk/test/scoring_provenance.test.ts` covering
      pure helpers, replay math, OK path, every rejection
      reason, code-hash check variants, decode round-trip.
      Total 102 SDK tests.
- [x] `LAUNCH_CHECKLIST` extended with AW-04 audit gate,
      AW-04 first-live-cert ship-discipline gate, and AW-04
      daily-review gate.
- [x] Runbook at `launch/runbooks/score_provenance.md`.

---

## What "done" looks like in production

Every steady-state `issue_certificate` on mainnet emits a v7 cert
with non-zero `scoring_code_hash` AND a paired `ScoreComponentsAccount`
PDA whose `sha256(payload) === cert.scoreComponentsHash`. Any DeFi
consumer can:

```ts
import {
  verifyScoreComputation,
  verifyScoringCodeHash,
  CodeHashCheckResult,
} from "@phylanx/sdk";

const replay = await verifyScoreComputation(connection, certIssuer, cert);
if (!replay.ok) {
  // Reject the score. Do NOT relax the check.
}

const codeCheck = verifyScoringCodeHash(cert, EXPECTED_SCORING_CODE_HASH);
if (codeCheck.result !== CodeHashCheckResult.Ok) {
  // Score was produced by a kernel the consumer hasn't audited.
  // Reject or escalate per integration policy.
}
```

A consumer that wires BOTH checks gets:
1. The cert is bound to a SPECIFIC scoring kernel (auditable source).
2. The score is bound to a SPECIFIC dimension breakdown (replayable).
3. The breakdown's bytes live on chain and can be re-hashed against
   the cert's binding — without trusting the cluster or any
   external DA service.

The post-launch daily-review gate verifies this end-to-end and the
runbook governs the response to any `HashMismatch` /
`ScoreReplayMismatch` / `CodeHashMismatch` finding.
