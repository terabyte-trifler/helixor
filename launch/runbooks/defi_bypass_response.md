# Runbook — DBP-1 DeFi Bypass

> When to use: the `consumer_integration_check` gate lights red in CI, a
> partner is onboarding, or a drain event traces back to a Verified
> Integrator's manifest.

## 1 — Partner onboarding flow

A DeFi partner who wants the "Verified Integrator" badge runs this flow:

1. **Read** `launch/integrations/MANIFEST_SCHEMA.md`.
2. **Read** the reference reader at
   `launch/integrations/example_safe_partner/reader.ts`. The simplest
   onboarding path is to copy-paste it into your own repo, change the
   `ChainReader` wiring to your own RPC, and adjust the `Operation` set
   you actually use.
3. **Run the linter locally** against your own checked-out repo:
   ```sh
   python3 audit/consumer_integration_check.py \
       --json /tmp/my_integration.json
   ```
   The linter is pure-stdlib Python and has no external dependencies.
   Fix any HARD findings before continuing.
4. **Compute your manifest's canonical hash:**
   ```python
   import json, hashlib
   m = json.load(open("launch/integrations/<your_name>.json"))
   m.pop("integration_hash", None); m.pop("signature_ed25519", None)
   canonical = json.dumps(m, sort_keys=True, separators=(",", ":"))
   print(hashlib.sha256(canonical.encode()).hexdigest())
   ```
5. **Sign the hash** with the Ed25519 keypair whose pubkey is your
   `partner_wallet`. Base58-encode the 64-byte signature and set
   `signature_ed25519`.
6. **Open a PR** adding `launch/integrations/<your_name>.json` and any
   reference reader sources to the Phylanx repo. The CI gate verifies
   your manifest before review.
7. **Mint your on-chain badge.** Once your PR merges, call
   `register_verified_consumer(integration_hash)` on the
   `certificate-issuer` program. Your `partner_wallet` IS the
   transaction Signer (no off-chain Ed25519 dance — Anchor's
   `Signer<'info>` constraint is the cryptographic binding). The
   handler validates non-zero `integration_hash` + non-zero
   `partner_wallet` and inits the PDA at
   `[b"verified_consumer", partner_wallet]`. SDK helper:
   ```ts
   import { verifiedConsumerPda, fetchVerifiedConsumer,
            isVerifiedConsumerActive } from "@phylanx/sdk";
   const [pda] = verifiedConsumerPda(programId, partnerWallet);
   const decoded = await fetchVerifiedConsumer(connection, pda);
   assert(isVerifiedConsumerActive(decoded));
   ```
   The PDA is the downstream gate — lending contracts MUST CPI-
   check `isVerifiedConsumerActive(decoded)` on every value-
   bearing read. Presence alone is insufficient because revoked
   badges persist on chain (the account is never closed; the
   `state` byte flips Active → Revoked).

## 2 — Triage: CI gate lights red

The gate emits one or more `HARD [DBP-1<a-e>] <rule>: <detail>` lines.
Resolve in order:

### 2a — `[DBP-1a]` per-manifest findings

These fire when a partner manifest is malformed. The detail line names
the manifest and the rule that failed.

| Rule | What's wrong | Fix |
|---|---|---|
| `manifest-valid-json` | The manifest file is malformed JSON. | Validate with `python3 -m json.tool < <file>` and fix syntax. |
| `required-field:<name>` | The manifest is missing a required field. | Add the field per `launch/integrations/MANIFEST_SCHEMA.md`. |
| `partner-wallet-base58` | The wallet is not a valid Solana base58 pubkey. | Replace with the actual base58 of the partner's signing pubkey (length 32-44, base58 alphabet). |
| `operations-bound-known` | The manifest names an unknown operation. | Limit `operations_bound` to the subset of `{LOAN_ISSUE, LOAN_INCREASE, LIQUIDATION_CHECK, STATUS_READ}` the partner actually uses. |
| `attest-flag:*` | An attestation flag is not `true`. | Either fix the underlying integration to wire that surface and flip the flag to `true`, or remove the manifest — Verified Integrator status requires all three. |
| `cert-reader-exists` | A path in `cert_reader_source_paths` is not on disk. | Either the path is wrong or the file was deleted. Sync. |
| `safe-reader-marker` | The cert-reader source does not import `SafeCertReader`. | Wire `SafeCertReader` per the reference reader. Raw `getScore()` is NOT acceptable for a Verified Integrator's value-bearing reads. |
| `input-provenance-marker` | The source does not call `verifyInputProvenance`. | Add the AW-01 verification step per the reference reader. |
| `slot-anchor-marker` | The source does not call `verifyAgainstSolanaLedger`. | Add the AW-01-EXT ledger re-verification per the reference reader. Provider MUST be an RPC INDEPENDENT from the cluster's RPC fleet. |
| `operation-floor-marker[*:OP]` | The source does not reference operation `OP` via any of the known constants or enum labels. | Add the SOL-3 per-operation floor per the reference reader OR remove the operation from `operations_bound`. |
| `unsafe-import-must-wrap[*]` | The cert-reader source imports from `@phylanx/sdk/unsafe` but does NOT reference `SafeCertReader`. This is the Path-4 attack pattern: raw `getScore()` with no freshness/velocity guard. | Wrap the raw client in `SafeCertReader` per the reference reader. If you genuinely need raw chain reads for a non-value-bearing surface (e.g. analytics), move that code OUT of `cert_reader_source_paths` — the linter only enforces the wrap for sources you've claimed as your cert reader. |
| `integration-hash-matches` | The manifest's `integration_hash` doesn't match canonical recompute. | Recompute via the helper in MANIFEST_SCHEMA.md and update the field, then re-sign. |
| `signature-present` | `signature_ed25519` is empty. | Sign the canonical hash with the `partner_wallet` keypair. |

### 2b — `[DBP-1b]` VULN-23 anchor findings

These fire when `phylanx-sdk/src/safe_reader.ts` has been refactored in a
way that voids every existing partner manifest.

Fix one of:

- **Restore the deleted symbol** if removal was accidental.
- **Bump the manifest schema version** if removal was intentional. Every
  existing partner manifest must be re-issued under the new schema. This
  is a coordinated rollout — DO NOT remove the symbol without first
  agreeing the migration plan with active partners.

### 2c — `[DBP-1c]` SOL-3 anchor findings

These fire when `phylanx-oracle/oracle/operation_freshness.py` has been
refactored in a way that voids the SOL-3 floors partner manifests bind
against.

Same fix shape as 2b: restore the symbol OR bump the schema version with
a partner migration plan.

### 2d — `[DBP-1d]` AW-01-EXT anchor findings

These fire when `phylanx-sdk/src/input_provenance.ts` no longer exports
the AW-01-EXT verification surfaces.

Same fix shape as 2b/2c.

### 2e — `[DBP-1e][DBP-3 safe-default]` findings

These pin the DBP-3 partition: raw cert-reader primitives
(`PhylanxClient`, `PhylanxChainClient`) live ONLY at
`@phylanx/sdk/unsafe`; the default `@phylanx/sdk` export carries
the safe-by-default surface (`SafeCertReader`, `verify*`,
decoders, PDA helpers, `VerifiedConsumer` helpers).

| Rule | What's wrong | Fix |
|---|---|---|
| `unsafe-subpath-exists` | `phylanx-sdk/src/unsafe.ts` is missing. Any partner who imports from `@phylanx/sdk/unsafe` will resolve to `undefined` at runtime. | Restore `phylanx-sdk/src/unsafe.ts` re-exporting `PhylanxClient` + `PhylanxChainClient` from the raw clients. If the removal is intentional, coordinate a partner migration BEFORE landing the change — every active integrator imports from this subpath. |
| `unsafe-reexports[*]` | `phylanx-sdk/src/unsafe.ts` no longer re-exports a raw client class (`PhylanxClient` or `PhylanxChainClient`). | Same fix shape. |
| `default-does-not-leak[*]` | The default `phylanx-sdk/src/index.ts` references `PhylanxClient` or `PhylanxChainClient` anywhere in its source — even in a comment. The DBP-3 invariant is that the default surface MUST NOT name the raw primitives at all (the linter is a text-marker check, so even a documentation mention is treated as a structural leak signal). | Move the raw client export to `unsafe.ts`. If a comment mentions the class names, rewrite the comment generically (e.g. "raw cert-reading clients live behind `@phylanx/sdk/unsafe`"). |

The SDK side has a matching `tsx test/unsafe_surface.test.ts`
which pins the partition from the OTHER direction (default entry
exposes safe surfaces; default entry does NOT expose forbidden
names; `/unsafe` entry exposes raw primitives). Run it via
`cd phylanx-sdk && npm test` — the partition is double-pinned by
intent.

## 3 — Triage: a drain event traces back to a Verified Integrator

When a drain post-mortem identifies a Verified Integrator's cert-reader
as the proximate failure:

1. **Fetch the manifest** — `cat launch/integrations/<partner>.json`. The
   `partner_wallet` is the on-chain identity.
2. **Re-run the linter** against the merged-in source:
   ```sh
   python3 audit/consumer_integration_check.py
   ```
   If the gate is still green, the partner's source-as-checked-in is
   structurally safe — the drain was either (a) caused by the partner
   running DIFFERENT code in production than what they merged, OR (b)
   caused by something OUTSIDE the linter's coverage (runtime
   configuration, RPC choice, missing eslint-disable on `@phylanx/sdk/
   unsafe` imports — see DBP-3).
3. **Pull the on-chain `VerifiedConsumer` PDA.** Use the SDK
   helper:
   ```ts
   import { verifiedConsumerPda, fetchVerifiedConsumer } from "@phylanx/sdk";
   const [pda] = verifiedConsumerPda(programId, partnerWallet);
   const decoded = await fetchVerifiedConsumer(connection, pda);
   ```
   The decoded `integration_hash` tells you which manifest version
   was registered. If the on-chain hash doesn't match the latest
   committed manifest, the partner registered a stale version and
   has been running on a stale claim — revoke the PDA immediately
   (see step 5).
4. **Diff the manifest claim against the production code.** Request a
   read-only snapshot of the partner's production cert-reader source.
   If the production source is materially different from the committed
   manifest's `cert_reader_source_paths` entries, the manifest is
   structurally a bad-faith attestation — proceed to step 5.
5. **Revoke** via `revoke_verified_consumer(reason)` on the
   `certificate-issuer` program. Reason is dual-path:
   - `AdminBadFaith` (byte `1`) — `issuer_config.authority` must
     sign. Use this when the partner's production code materially
     diverges from the committed manifest (a bad-faith
     attestation).
   - `AdminTerminated` (byte `2`) — `issuer_config.authority` must
     sign. Use this when the partner's tier subscription is being
     terminated for non-payment, ToS violation, or coordinated
     wind-down.
   - `PartnerSelfRevoke` (byte `3`) — the `partner_wallet` itself
     signs. Use this when the partner is voluntarily winding down
     or rotating to a new wallet.

   The on-chain `VerifiedConsumer` account is NOT closed — the
   `state` byte flips Active → Revoked, the `revoked_*` fields are
   filled, and the badge persists on chain as a permanent audit
   trail. Downstream contracts that gate on
   `isVerifiedConsumerActive(decoded)` will refuse the partner's
   certs from this point forward; the difference between "had a
   badge, lost it" and "never had a badge" remains observable.
6. **Forfeit SLA tier** (post-DBP-4). The Insured-tier indemnity that
   the partner subscribed to is voided per the bad-faith clause in the
   tier contract. The drain remains the partner's loss, not Phylanx's.

## 4 — When to add a new operation to SOL-3

DBP-1 binds partners against the SOL-3 operation set
`{LOAN_ISSUE, LOAN_INCREASE, LIQUIDATION_CHECK, STATUS_READ}`. If a new
operation class is needed (e.g. `MARGIN_CALL`):

1. **Propose the constant** in `phylanx-oracle/oracle/operation_freshness.py`
   with a calibration story (what max-age, why, what risk asymmetry).
2. **Add the enum label** to `Operation`.
3. **Update** the linter's `KNOWN_OPERATIONS` + `OPERATION_SOURCE_MARKERS`
   + `SOL3_FLOORS` in `audit/consumer_integration_check.py`.
4. **Update** the reference reader at
   `launch/integrations/example_safe_partner/reader.ts`.
5. **Update** `launch/integrations/MANIFEST_SCHEMA.md` with the new
   operation + ceiling.
6. **Bump** the manifest schema version. Existing partners can either
   bind the new operation or leave it out — adding operations is
   non-breaking for existing manifests.

## 5 — Final verification

After resolving findings:

```sh
python3 audit/consumer_integration_check.py \
    --json audit/reports/consumer_integration.json
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest \
    audit/test_consumer_integration_check.py -v
```

Both must report green. The gate is then ready to land in CI.

## 6 — DBP-4 partner identity + telemetry + webhooks

### 6a — Binding a partner to an API key

A Verified Integrator's read-side calls are attributed to their
on-chain `partner_wallet` via the API key's 5th colon field:

```
# PHYLANX_API_KEYS in the systemd unit / deploy manifest
keyid-acme:secret-acme-redacted:partner:1000:9ZcXc...AcmeWallet44
keyid-foo :secret-foo-redacted :partner:1000:7Yz... FooWallet44
keyid-internal:secret-internal:internal:5000
```

Lines without a 5th field (e.g. the `internal` row above) are
NOT attributed to any partner and do NOT appear on the
leaderboard, by design.

The `partner_wallet` MUST be the same base58 pubkey that owns the
on-chain `VerifiedConsumer` PDA — that is the link between the
off-chain API calls and the on-chain badge. A mismatch makes the
leaderboard look right but the audit trail breaks: a drain
post-mortem that walks (api log → key_id → partner_wallet →
on-chain PDA) will dead-end.

### 6b — Reading the leaderboard

```sh
curl https://api.phylanx.example/integrations/leaderboard
```

Returns:
```json
{
  "_v": 1,
  "ranking": [
    {"partner_wallet": "9ZcXc...", "safe_calls": 4520,
     "raw_calls": 12, "total_calls": 4532,
     "safe_share": 0.997},
    {"partner_wallet": "7Yz...",   "safe_calls": 100,
     "raw_calls": 900, "total_calls": 1000,
     "safe_share": 0.10},
    {"partner_wallet": "FreshPartner",
     "safe_calls": 0, "raw_calls": 0, "total_calls": 0,
     "safe_share": null}
  ]
}
```

Sort order: observed partners first by `safe_share` desc with a
`total_calls` tiebreak; idle partners (`total_calls == 0`) last
in `partner_wallet` order. A partner whose ranking degrades is
running raw reads — investigate via 6c.

### 6c — Investigating a partner's low safe share

A partner ranking visibly below the rest is likely either:

  1. **Importing `@phylanx/sdk/unsafe` directly** without wrapping
     in `SafeCertReader`. The DBP-1e `unsafe-import-must-wrap[*]`
     check (§2a) would catch this if their reader source was
     listed in their manifest's `cert_reader_source_paths` — so a
     low rank PLUS a green linter means the partner is reading
     from a source they DIDN'T disclose in their manifest. That
     is a bad-faith attestation: revoke via §3 step 5
     (`AdminBadFaith`).
  2. **Reading the API directly with `/health` instead of
     `/safe_score`.** This is a misuse of the public surface that
     bypasses the freshness + velocity guards. Reach out, point
     them at the SDK's `SafeCertReader`, and re-rank in 30 days.

### 6d — Cert-degrading webhook subscription

A Verified Integrator on the Insured tier registers a webhook via
the deploy env var:

```
# PHYLANX_WEBHOOKS in the systemd unit / deploy manifest
9ZcXc...AcmeWallet44:https://acme.example/phylanx/cert-degrading:hmac-secret-redacted
```

Restart the API process for the change to take effect (the
registry is immutable at runtime, same posture as
`PHYLANX_API_KEYS`).

### 6e — Verifying a webhook delivery

A partner who receives a POST must:

  1. Check `X-Phylanx-Webhook-Event: cert.degrading`.
  2. Read the raw body bytes.
  3. Compute `expected = HMAC-SHA256(shared_secret, body_bytes)`
     (hex).
  4. Compare against `X-Phylanx-Webhook-Signature` in constant
     time (`hmac.compare_digest`).
  5. Decode the JSON body. Required fields:
     `_v=1`, `event="cert.degrading"`, `partner_wallet`,
     `agent_wallet`, `epoch`, `issued_at_unix`,
     `cert_age_seconds`, `threshold_seconds`,
     `cert_max_age_seconds`, `sent_at_unix`.
  6. If `sent_at_unix - issued_at_unix >= threshold_seconds`,
     page the cluster on-call to push a fresh cert BEFORE
     `issued_at_unix + cert_max_age_seconds`.

A failed signature check is a FORGERY — drop the body and alert
infosec.

### 6f — Triage: a partner reports a missed webhook

When a partner says "you didn't tell me my cert was degrading":

  1. Confirm the partner is on the Insured tier (DBP-4 is paid).
  2. `grep phylanx.api.webhooks /var/log/phylanx-api/*.log` for
     a `dispatch` entry with their `partner_wallet`. If absent
     the trigger never fired — proceed to (3). If present but the
     partner says they didn't receive it, the issue is downstream
     of Phylanx (their endpoint dropped the POST, their HMAC
     verifier rejected, etc).
  3. Confirm the partner was polling `/safe_score` (NOT
     `/health`) — the trigger is REACTIVE and only fires when
     the partner asks for the guarded surface. A partner who
     polls only `/health` will never be warned: that is by
     design (raw consumers opted out of the safety surface).
     Direct them to switch to `/safe_score` or the SDK's
     `SafeCertReader`.
  4. Confirm `cert_age_seconds` actually crossed
     `degrading_threshold_seconds(48*3600) == 36*3600` during
     the partner's polling window. A partner whose cert was
     rotated faster than 36h never enters the degrading window;
     no webhook is owed.
