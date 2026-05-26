# Partner Integration Manifest — DBP-1 Schema

> **Status:** ACTIVE. The audit gate (`audit/consumer_integration_check.py`)
> enforces this schema for every `launch/integrations/*.json` file.

A DeFi partner that wants the "Verified Integrator" badge — and the
downstream-of-downstream contract surface that comes with it (DBP-2 on-chain
`VerifiedConsumer` PDA, DBP-4 freshness webhooks, SLA-backed support) —
publishes a single JSON manifest declaring their cert-reader entrypoint and
the safety surfaces it wires.

The audit linter is a **self-serve tool**: any partner can run it against
their own checked-out source, fix the findings it surfaces, and only then
file a PR adding their manifest under `launch/integrations/`. Failing the
linter does NOT block onboarding (Helixor is opt-in-safe, not gated-safe)
— it just means the partner doesn't get the badge. Once green, the partner
signs the canonical manifest hash with an Ed25519 key whose pubkey is the
`partner_wallet` field, and the DBP-2 PDA can be minted on chain.

## Schema

```json
{
  "partner_name": "Example Safe Partner",
  "partner_wallet": "Hi11xor11Veri1f1ed1Consumer1Examp1e1Partner1111",
  "integration_version": "1.0.0",
  "cert_reader_source_paths": [
    "launch/integrations/example_safe_partner/reader.ts"
  ],
  "operations_bound": [
    "LOAN_ISSUE",
    "LOAN_INCREASE",
    "LIQUIDATION_CHECK",
    "STATUS_READ"
  ],
  "safe_reader_imported": true,
  "input_provenance_verified": true,
  "slot_anchor_verified": true,
  "integration_hash": "<SHA256 hex of canonical JSON minus this field and signature>",
  "signature_ed25519": "<base58 Ed25519 signature over integration_hash>"
}
```

## Required fields

| Field | Type | Rule |
|---|---|---|
| `partner_name` | string | Non-empty, ≤ 64 chars. Human-readable label. |
| `partner_wallet` | string | Base58 Solana pubkey, length ≥ 32. The DBP-2 `VerifiedConsumer` PDA is seeded on this wallet. |
| `integration_version` | string | SemVer. Bumped per manifest revision. |
| `cert_reader_source_paths` | string[] | Non-empty list of repo-relative paths. Every path must exist on disk. |
| `operations_bound` | string[] | Non-empty subset of `{LOAN_ISSUE, LOAN_INCREASE, LIQUIDATION_CHECK, STATUS_READ}`. At minimum every WRITE operation the partner performs must be listed. |
| `safe_reader_imported` | bool | MUST be `true`. The linter cross-checks each `cert_reader_source_paths` entry contains the `SafeCertReader` marker. |
| `input_provenance_verified` | bool | MUST be `true`. The linter cross-checks each source contains `verifyInputProvenance`. |
| `slot_anchor_verified` | bool | MUST be `true`. The linter cross-checks each source contains `verifyAgainstSolanaLedger`. |
| `integration_hash` | string | 64-hex SHA256 over `canonical_json(manifest without integration_hash and signature_ed25519 fields)`. The linter recomputes and compares. |
| `signature_ed25519` | string | Base58 Ed25519 signature over the 32-byte `integration_hash`, signed by `partner_wallet`. **Verified on chain at DBP-2 register time, NOT by the audit linter.** |

## Per-operation floor contract

By listing an operation in `operations_bound`, the partner attests that the
cert-reader source enforces the SOL-3 per-operation freshness floor for
that operation:

| Operation | Max cert age (audit-mandated) |
|---|---|
| `LOAN_ISSUE` | 4 h |
| `LOAN_INCREASE` | 8 h |
| `LIQUIDATION_CHECK` | 12 h |
| `STATUS_READ` | 48 h (matches TA-6 ceiling) |

The linter cross-checks that the partner's cert-reader source contains
EITHER the named constant (e.g. `LOAN_ISSUE_MAX_AGE_SECONDS`) OR the
enum label (e.g. `Operation.LOAN_ISSUE`) for every operation listed in
`operations_bound`.

## What the linter does NOT check

- **Ed25519 signature validity.** That's a chain-side concern verified by
  the DBP-2 `register_verified_consumer` ix at manifest-registration time.
  The linter is a pre-flight; the on-chain PDA is the ground truth.
- **Runtime behaviour.** The linter is text-static. A partner could embed
  the markers in dead code and the linter would pass. The badge is a
  good-faith attestation backed by the partner's own Ed25519 signature on
  the integration hash — bad-faith attestations void the badge and forfeit
  any SLA tier.
- **The presence of `getScore()` calls.** Raw cert reads are NOT forbidden
  in a Verified Integrator's source — telemetry and dashboards legitimately
  use them. What's forbidden is gating real money through them; the linter
  enforces the safe surfaces are PRESENT but does not prove every read goes
  through them.

## How to compute `integration_hash`

```python
import json, hashlib

with open("launch/integrations/<partner>.json") as fh:
    m = json.load(fh)
m.pop("integration_hash", None)
m.pop("signature_ed25519", None)
canonical = json.dumps(m, sort_keys=True, separators=(",", ":"))
print(hashlib.sha256(canonical.encode()).hexdigest())
```

Set `integration_hash` to that value, sign it with the `partner_wallet`
keypair, base58-encode the signature, and set `signature_ed25519`.
