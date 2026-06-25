# Runbook — Oracle node down

**Severity:** Page (one node) → Page (cluster below quorum).
**Trigger:** Prometheus `OracleNodeDown` alert.

## What's happening

A cluster node has stopped responding to Prometheus scrapes for 5
minutes. The cluster tolerates ONE node down (Day 28 chaos test #1) —
threshold of 3-of-5 still satisfied with 4 surviving. Two down is a
quorum risk.

## Triage (60s)

```bash
# 1. Confirm the node is actually down vs scrape-only.
ssh oracle-node-<i>
sudo systemctl status phylanx-oracle-<i>
journalctl -u phylanx-oracle-<i> -n 200

# 2. Confirm cluster is producing certs without it.
curl -s http://api/health/cluster | jq '.recent_epochs'
# Look for `submitted_count == agent_count` and verified_nodes >= 4.

# 3. Check for byzantine pattern — has THIS node been flagged?
curl -s http://api/byzantine/strikes | jq ".summary[\"$NODE\"]"
```

## Decision tree

- **Process died, no Byzantine flags:** systemd will restart on-failure.
  If the restart loop is bounded out (StartLimitBurst exceeded), the
  node refused to start — see `journalctl` for the reason. **Common
  causes:** corrupted keypair file, lost gRPC port, OOM. Restore from
  backup keypair, restart, watch one full epoch complete.

- **Process keeps exiting with code 2:** the network guard refused start.
  The env file references mainnet without `PHYLANX_MAINNET_OK=1`. This
  is the **safety belt firing** — do NOT add the flag to make it stop.
  Confirm the env file is correct first. If the start *was* intentional,
  add the flag with a deliberate commit message naming the reason.

- **Node was flagged Byzantine before going down:** do NOT restart
  blindly. The node may have been killed by the on-call to PREVENT
  further damage. Confirm with #phylanx-ops before restarting.

- **Network partition (transport unreachable but process up):** see
  `partition.md`. Restart often does not help here; investigate
  upstream connectivity first.

## Recovery

```bash
# Standard restart.
sudo systemctl restart phylanx-oracle-<i>
sudo systemctl status phylanx-oracle-<i>
# Wait for the next epoch tick.
journalctl -u phylanx-oracle-<i> -f
```

## When to wake the lead

- Two nodes are down simultaneously — cluster at the quorum edge.
- The node's keypair is suspected compromised — rotate via Squads vote.
- Restart-after-recovery still produces wrong scores — Byzantine bug.

## Postmortem

File under `incidents/<YYYY-MM-DD>-node-<i>-down.md`. Include:
- Timeline (Prometheus + journal grep).
- Root cause (one sentence).
- Whether the cluster maintained quorum throughout (link the epoch report).
- Action items.
