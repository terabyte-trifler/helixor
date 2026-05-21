# Runbook — Cluster below quorum

**Severity:** Page.
**Trigger:** `ClusterBelowQuorum` (< 3 nodes responding).

## What's happening

Fewer than 3 oracle nodes are reachable. With a threshold of 3-of-5, the
cluster can no longer assemble enough signatures to write a certificate.
**Cert writes are halted until quorum is restored.**

This is by design — refusing to write under-quorum is correct. Agents
will not see new scores until at least 3 nodes are up.

## Triage

```bash
# Which nodes are up?
for i in 0 1 2 3 4; do
  curl -s -o /dev/null -w "node-$i: %{http_code}\n" \
       http://oracle-node-$i:9090/health || echo "node-$i: unreachable"
done
```

## Decision tree

- **Two nodes down for clear, unrelated reasons:** see `node_down.md`
  for each, restart them. Cluster recovers once 3 are back.
- **All five down:** infrastructure outage (network partition, region
  failure, registry outage). Verify upstream, escalate to lead.
- **Three+ down but processes appear healthy:** network partition —
  the nodes don't see each other. See `partition.md`.

## When to wake the lead

Always. Below-quorum halts cert production; this is user-visible.

## Postmortem

Mandatory for any below-quorum > 5 minutes.
