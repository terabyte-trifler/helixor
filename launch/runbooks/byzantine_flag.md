# Runbook — Byzantine flag fired

**Severity:** Page (single flag) → Page (challenge filed at 3 strikes).
**Trigger:** Prometheus `ByzantineNodeDetected` alert.

## What's happening

A cluster node has been flagged Byzantine — its score deviated > 30%
from the cluster median for at least one agent. Day 26 detection caught
it; the median was taken WITHOUT this node's contribution; the cert was
still produced correctly.

This is the *expected* behavior of the cluster's BFT detection. The
question is: **why did the node deviate?** Possibilities (most to least
common):

1. **Detector regression** — a recent deploy of detection code changed
   how this node scores. Possibly only this node is on the new version,
   so it disagrees with the rest. Confirm by checking deployed versions.
2. **Stale baseline** — the node's `baseline_stats` for the agent is
   out-of-date vs the others. Check `agent_score_history` timestamps.
3. **Hardware fault** — corrupted memory, disk error. Smell-test the
   node host (`dmesg`, ECC counters, disk SMART).
4. **Actually adversarial** — the node was compromised. Rare but the
   reason the system exists.

## Triage (5 min)

```bash
# 1. Which agent caused the flag, and how big was the deviation?
curl -s http://api/byzantine/recent | jq '
  .flags[] | select(.epoch == <latest>) |
  {node, agent: .subject_agent, score: .accused_score,
   median: .cluster_median, deviation_pct: (.deviation * 100)}'

# 2. What did each node report for that agent? (Determinism check —
# honest nodes on the same input should produce IDENTICAL scores.)
curl -s "http://api/byzantine/per_node?epoch=$EPOCH&agent=$AGENT" | jq '
  .reveals[] | {node, score}' | sort

# 3. What scoring algorithm version is the cluster pinned to?
# (The on-chain OracleConfig + each node's env file pin this. The API
# reports the cluster's effective version; compare to each node's env.)
curl -s "http://api/version" | jq '{algo: .scoring_algo_version, weights: .scoring_weights_version}'
# Per-node env (run on each host):
ssh oracle-node-<i> -- grep SCORING_ phylanx.env
```

## Decision tree

- **All nodes on the same version, only this one diverges:** likely
  hardware or local corruption. STOP the node (`systemctl stop`), file
  a ticket with the deviating epoch+agent, ask the team to investigate
  before restarting. The cluster continues with 4.

- **Recent deploy, only this node has the new version:** rollback this
  node to the prior version. The flag fired because deploys went out
  of order, not because the node is bad.

- **Recent deploy, multiple nodes diverge with the same direction:** the
  NEW version is wrong, not the old one. Rollback ALL nodes to the prior
  version. File P0.

- **Strike count is at 2:** the next flag will trigger
  `challenge_oracle`. Decide NOW whether you want that to happen.
  If the node is genuinely faulty, let it. If false-positive, stop
  the node before strike 3.

## Strike count tracking

```bash
curl -s http://api/byzantine/strikes | jq
# {
#   "oracle-node-2": { "strikes": 2, "flagged_epochs": [128, 130],
#                      "challenged": false },
#   ...
# }
```

## When to wake the lead

- The byzantine flag is the same node 3+ epochs in a row → challenge
  imminent.
- Multiple nodes flagged in the same epoch → systemic problem, not
  per-node fault.
- The cluster median moved by > 100 (out of 1000) vs the prior epoch →
  the "honest" median may itself be wrong.

## Postmortem (mandatory for any challenge_oracle)

File under `incidents/<YYYY-MM-DD>-byzantine-<node>.md`. Mandatory
fields:
- Strikes timeline (epoch → score → median → deviation %).
- Root cause (and how it differs from "this node is malicious").
- Whether a challenge was filed and whether it should have been.
- The recovery action (rollback / stop / replace keypair).
