# Runbook — Cert submission failure spike

**Severity:** Page.
**Trigger:** `CertSubmissionFailureSpike` — > 5% of cert submissions
failing for 5 minutes.

## What's happening

The cluster is producing valid (signed, threshold-met) certificates
off-chain, but the on-chain submission is failing. The most likely
causes:

1. **Solana RPC outage** — the configured RPC endpoint is unhealthy.
   The cluster keeps producing certs; they just can't land.
2. **Fee-payer ran out of SOL** — the submitter account is empty.
3. **Squads vault rejected** — the upgrade authority is the vault now;
   if a cert ix tries to bump version or migrate config it needs a
   Squads vote.
4. **Threshold sig assembly bug** — the cluster THINKS it has 3 sigs
   but the on-chain `verify_threshold_signatures` rejects them.
   InsufficientSignatures (6033) in the logs.

## Triage

```bash
# 1. Top error from last 5 min:
journalctl -u phylanx-submitter -n 500 | grep -oE 'error: [A-Za-z]+' \
    | sort | uniq -c | sort -rn

# 2. RPC health:
curl -s "$SOLANA_RPC_URL" -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
    -H 'content-type:application/json'

# 3. Fee-payer balance:
solana balance "$FEE_PAYER" --url "$SOLANA_RPC_URL"
```

## Decision tree

- **RPC unhealthy:** switch to backup RPC URL (rolling env update +
  restart submitters). Certs still produced — they will land once RPC
  recovers.
- **Fee-payer empty:** top it up. Document where the spend went.
- **InsufficientSignatures in logs:** there is a bug in the cluster's
  signing or aggregation. Compare the signing set the cluster used vs
  the on-chain cluster_keys; check for cluster_keys rotation.

## When to wake the lead

Always — cert submission failures are user-visible.
