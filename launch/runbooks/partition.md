# Runbook — Network partition

**Severity:** Page.
**Trigger:** Multiple `OracleNodeDown`-style alerts where the processes
appear healthy locally but unreachable from peers.

## What's happening

The 5 nodes are alive but cannot reach each other. Commit-reveal fails
(no quorum), no certs are written. Day-28 chaos test #3 covers this
exactly — partitioned nodes are timed out, surviving partitions reach
quorum if ≥ 3 nodes are connected.

## Triage

From each node, ping each peer:

```bash
for peer in oracle-node-{0,1,2,3,4}; do
  if [[ "$peer" != "$HOSTNAME" ]]; then
    timeout 3 grpcurl -plaintext "$peer:50051" \
        helixor.OracleCluster/Ping || echo "$peer UNREACHABLE"
  fi
done
```

Identify the partition boundary — likely a subnet or AZ failure.

## Decision tree

- **One AZ unreachable from another:** wait for upstream to recover OR
  move a node into the surviving AZ to restore quorum.
- **Routing change pushed:** rollback the change.
- **DNS issue:** flush caches, verify resolved peer IPs.

## When to wake the lead

Always. Partition = halted cluster.
