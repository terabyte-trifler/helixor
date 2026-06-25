# Red-Team Path 4 — "DeFi Bypass" — Closure Design

> **Status:** ACTIVE. DBP-1 (consumer integration linter + reference safe
> reader + manifest schema) ships in this commit; DBP-2 (on-chain
> `VerifiedConsumer` PDA), DBP-3 (flip `@phylanx/sdk` default export), and
> DBP-4 (telemetry + freshness webhooks) land in follow-up commits and are
> the revenue surface for the "Verified Integrator" tier.

## 1 — The attack tree

From the red-team review:

```
ROOT: Drain DeFi Protocol Integrated with Phylanx
└── Path 4: DeFi Bypass (exploit DeFi, not Phylanx)
    ├── DeFi protocol uses cert without freshness check
    ├── DeFi protocol uses cert without score threshold validation
    └── DeFi protocol's cert-reading code has bugs
```

Paths 1, 2, 3 (`FHS`, `ILS`, `FRP`) attack Phylanx's own substrate and have
been closed by per-path orthogonal mitigations. Path 4 lives ENTIRELY in
the consumer's code. Phylanx cannot close it from its own substrate — the
only durable mitigation is to make the safe path the *easy* path and reward
partners who provably adopt it.

### What's already in place (necessary but not sufficient)

| Leaf | Phylanx-side defence already shipped |
|---|---|
| 4a freshness | `SafeCertReader.CERT_MAX_AGE_SECONDS = 48 * 60 * 60` (VULN-23) + `is_fresh_default` (TA-6) + `verify_operation_freshness` (SOL-3) + cert-reissue cadence floor (FRP-3) |
| 4b threshold | `SafeCertReader` velocity check (VULN-23) + agent-registration-age floor (NSS-3) + score-velocity contract (PDS-2) |
| 4c reader bugs | `verifyInputProvenance` (AW-01) + `verifyAgainstSolanaLedger` (AW-01-EXT) + `verifyBaselineProvenance` (AW-03) + `verifyScoreComputation` (AW-04) |

Every defence above only fires if the consumer ACTUALLY USES the safe
surface. Path 4's residual is the gap between "safe surfaces exist" and
"safe surfaces are wired."

## 2 — The closure: three orthogonal substrates + a revenue line

The closure mirrors the FHS / ILS / FRP three-substrate pattern but the
substrates are *integration substrates*, not Phylanx-internal subsystems:

| Family | Substrate | Concrete deliverable | Status |
|---|---|---|---|
| **DBP-1** | Audit gate | `audit/consumer_integration_check.py` + reference manifest + safe-reader reference implementation | ✅ this commit |
| **DBP-2** | On-chain badge | `programs/health-oracle/src/state/verified_consumer.rs` PDA + `register_verified_consumer` ix | 🔜 follow-up |
| **DBP-3** | SDK default | Flip `@phylanx/sdk` default export to `SafeCertReader`; raw `getScore()` behind `@phylanx/sdk/unsafe` | 🔜 follow-up |
| **DBP-4** | Telemetry + revenue | `safe_reader_share` metric per partner + `/integrations/leaderboard` + SLA-backed freshness webhooks | 🔜 follow-up |

### DBP-1 — Consumer integration linter (this commit)

**What it is.** A self-serve Python linter at
`audit/consumer_integration_check.py`. Any DeFi partner who wants the
"Verified Integrator" badge runs the linter against their own checked-out
fork, fixes the findings, and opens a PR adding their manifest under
`launch/integrations/<partner>.json`.

**What it verifies (per manifest):**

1. **Schema** — required fields present, `partner_name` non-empty,
   `partner_wallet` is base58 of length 32-44, `integration_version` is
   non-empty, `operations_bound` is a non-empty subset of
   `{LOAN_ISSUE, LOAN_INCREASE, LIQUIDATION_CHECK, STATUS_READ}`, and the
   three `*_imported` / `*_verified` attestation flags are all `true`.
2. **Source markers** — every `cert_reader_source_paths` entry exists on
   disk and contains the `SafeCertReader`, `verifyInputProvenance`, and
   `verifyAgainstSolanaLedger` markers, plus the per-operation constant
   or enum label for each entry in `operations_bound`.
3. **Canonical hash** — `integration_hash` matches `SHA256(canonical_json(
   manifest minus integration_hash and signature_ed25519))`. Catches
   accidental drift between the manifest and its pinned hash.
4. **Signature presence** — `signature_ed25519` is non-empty. The linter
   does NOT verify the signature; that's the chain-side `DBP-2
   register_verified_consumer` ix's job.

**What it cross-checks (anchors):**

- **VULN-23 anchor** — `SafeCertReader` + `CERT_MAX_AGE_SECONDS = 48 * 60 *
  60` + `MAX_SCORE_VELOCITY = 200` + `VELOCITY_WINDOW_EPOCHS = 3` +
  `MIN_HISTORY_REQUIRED = 2` in `phylanx-sdk/src/safe_reader.ts`.
- **SOL-3 anchor** — `class Operation(str, Enum)` + every per-op constant
  (`LOAN_ISSUE_MAX_AGE_SECONDS = 4 * 3600`, etc.) in
  `phylanx-oracle/oracle/operation_freshness.py`.
- **AW-01-EXT anchor** — `verifyAgainstSolanaLedger` +
  `verifyInputProvenance` in `phylanx-sdk/src/input_provenance.ts` and the
  re-export from `phylanx-sdk/src/index.ts`.

If any anchor is renamed or removed without updating every existing
partner manifest, the gate lights red here BEFORE the refactor reaches
mainnet.

**Reference implementation.** `launch/integrations/example_safe_partner/
reader.ts` is the canonical safe reader. A partner who copy-pastes it is
by construction safe along every axis Phylanx cares about. The reference
manifest at `launch/integrations/example_safe_partner.json` points at it
and IS the linter's primary green target.

### DBP-2 — On-chain `VerifiedConsumer` PDA (follow-up)

PDA seeded by `[b"verified_consumer", partner_wallet]`. Created by
`register_verified_consumer(integration_hash, signature_ed25519)`:

- The on-chain handler verifies `signature_ed25519` against
  `partner_wallet` using the Ed25519 precompile, ensuring the partner
  actually controls the wallet they claim.
- Stores `(integration_hash, registered_at_slot, partner_wallet)`.
- Revocable by the partner via `revoke_verified_consumer`.

Downstream-of-downstream lending contracts can CPI / account-existence-
check `VerifiedConsumer(partner_wallet)` to verify a caller is a
registered integrator BEFORE accepting their cert-derived parameters.
This is the **monetization hook**: paid-tier partners get the badge
minted; downstream contracts who want a "verified" upstream get a
recognizable marker.

### DBP-3 — Safe default SDK (follow-up)

Flip `@phylanx/sdk`'s default exports. After DBP-3:

- `import { ... } from '@phylanx/sdk'` ONLY exposes `SafeCertReader`,
  `verifyAgainstSolanaLedger`, `verifyInputProvenance`, the SOL-3
  `Operation` helpers, and the structurally-safe surfaces.
- `import { rawGetScore, ... } from '@phylanx/sdk/unsafe'` exposes the
  raw cert-reader primitives. Importing from `/unsafe` should require
  an explicit eslint-disable comment in the consumer's repo — the
  reference linter (DBP-1) flags imports from `/unsafe` outside an
  audit-annotated allowlist.

This is the **friction-killer**: a `npm install @phylanx/sdk` followed by
the simplest possible "get the score" call is by construction safe.
Misuse becomes opt-in, not opt-out.

### DBP-4 — Telemetry, leaderboard, freshness webhooks (follow-up)

Three deliverables stacked:

1. **Per-partner safe-reader share metric.** The read API at
   `phylanx-api/api/telemetry.py` tracks the ratio of `safe_score`
   calls to raw `score` calls per partner (keyed by API token).
2. **Public leaderboard.** `/integrations/leaderboard` JSON endpoint
   surfaces every Verified Integrator's `safe_reader_share`, their
   on-chain `VerifiedConsumer` PDA, and a 30-day uptime / freshness
   score. Becomes a marketing surface and a recruiting tool.
3. **SLA-backed freshness webhooks.** A paid tier ("Phylanx Insured")
   where Verified Integrators subscribe to `cert_degrading(agent)`
   webhooks BEFORE a cert hits the SOL-3 ceilings (e.g. notify at
   `LOAN_ISSUE_MAX_AGE_SECONDS - 60min`). Mirrors the Stripe Radar
   pattern — Phylanx underwrites a refund/indemnity tier for
   integrators who adopt the full stack. **This is the revenue line.**

## 3 — Why this shape (vs the alternatives)

### Alternative A: Hard-gate the API

"Refuse to issue an API token unless the partner ships a green manifest."

- ✗ Kills self-serve onboarding (the #1 GTM moat for an oracle).
- ✗ Phylanx becomes a gatekeeper for adoption velocity — Cloudflare /
  Stripe / Plaid all explicitly chose NOT to do this.
- ✗ A token-gate is an arms race with motivated bypassers anyway —
  they'll script around it.

### Alternative B: Documentation only

"Publish the safe pattern in docs. Hope partners read them."

- ✗ The first big drain from a sloppy integration becomes "Phylanx's
  fault" in headlines, regardless of who actually wrote the broken code.
- ✗ No revenue surface — Phylanx has nothing to charge for beyond raw
  cert reads, which is a commodity.

### Alternative C (chosen): Self-serve safe-by-default + verified-integrator tier

- ✓ Safe default = free, raw access = explicit opt-out → minimum friction
  for adoption.
- ✓ Verified badge is *earned*, not required → no GTM tax on day-one
  integration.
- ✓ Verified Integrators get a real on-chain badge (DBP-2) downstream
  contracts can recognize → social proof becomes the gate, not the audit.
- ✓ Insured tier (DBP-4) is the revenue line and is by construction
  available ONLY to Verified Integrators → security adoption *funds*
  the security program.

## 4 — Audit-gate guarantees (mechanical)

A regression that does any of the following lights `consumer_integration_check`
RED BEFORE the change reaches mainnet:

1. Removes `SafeCertReader` or any of its four pinned constants from
   `phylanx-sdk/src/safe_reader.ts`.
2. Stops re-exporting `SafeCertReader` from `phylanx-sdk/src/index.ts`.
3. Removes the `Operation` enum or any of the four `*_MAX_AGE_SECONDS`
   constants from `phylanx-oracle/oracle/operation_freshness.py`.
4. Removes `verifyAgainstSolanaLedger` or `verifyInputProvenance` from
   `phylanx-sdk/src/input_provenance.ts`.
5. Mutates the reference `example_safe_partner.json` without
   recomputing its `integration_hash`.
6. Removes a marker (SafeCertReader / verifyInputProvenance /
   verifyAgainstSolanaLedger / per-op constant) from the reference
   `reader.ts` source the manifest points at.

## 5 — Calibration story

The linter is text-static — it grep-pattern matches markers, not AST.
This is deliberate:

- **Cross-language reach.** Partners write in TS, JS, Python, Rust, Go.
  An AST tool that parses one language is a step-change worse than a
  marker matcher that works across all of them.
- **Cheap to bypass in BAD faith.** Yes — a partner could embed
  `SafeCertReader` in dead code and pass. The badge is a *good-faith*
  attestation backed by the partner's own Ed25519 signature on the
  integration hash. Bad-faith attestations void the badge and forfeit
  any SLA tier (DBP-4); a drain that traces back to a known-bad-faith
  manifest revokes their on-chain `VerifiedConsumer` PDA via
  `revoke_verified_consumer`.
- **The teeth are downstream.** The DBP-2 PDA + DBP-4 SLA tier are
  what give the linter real teeth. The linter itself is the
  pre-flight; the on-chain badge + the revenue tier are the
  enforcement.

The SOL-3 floors the manifest binds (`LOAN_ISSUE = 4h`, `LOAN_INCREASE =
8h`, `LIQUIDATION_CHECK = 12h`, `STATUS_READ = 48h`) are calibrated for
risk-asymmetry: a 12× safety margin between LOAN_ISSUE and STATUS_READ
matches the FRP-3 12× margin between cluster-side reissue cadence (4h)
and on-chain TA-6 ceiling (48h). The two systems are in lockstep so the
on-chain ceiling and the consumer-side floor cannot drift independently.
