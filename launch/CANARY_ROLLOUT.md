# Helixor V2 — Canary Rollout Plan

The phased mainnet rollout. Each phase has explicit **entry criteria** to
advance and explicit **abort criteria** that send the rollout backward.
Nothing automatic — every transition is a deliberate human call.

---

## Phase 0 — Mainnet programs deployed, cluster NOT yet running

**Goal:** the on-chain programs exist, configs initialised, upgrade
authority on Squads. **No oracle nodes running yet** — nothing is
producing scores, nothing is being read by the API.

**Entry criteria:** LAUNCH_CHECKLIST section 1-4 ticked.

**What's live:** 3 programs on-chain (health-oracle, certificate-issuer,
slash-authority). Squads vault holds upgrade authority for all 3.

**Validation:**
- `audit/artifact_verification/verify_so_match.ts --cluster mainnet-beta`
  confirms deployed = local for all 3 programs.
- The `OracleConfig` / `IssuerConfig` / `SlashConfig` PDAs exist on-chain
  and reference the 5 mainnet cluster pubkeys.

**Abort criteria:** byte-mismatch in any program; misconfig in any
config PDA. Roll back via the Squads vault (3-of-5 vote to redeploy).

---

## Phase 1 — One mainnet node up

**Goal:** prove the operational stack works against mainnet RPC with a
single node, without yet committing to consensus.

**Entry criteria:** Phase 0 validated.

**Bring up:**
- One node, `oracle-node-0`, on mainnet.
- `HELIXOR_NETWORK=mainnet-beta`, `HELIXOR_MAINNET_OK=1` in the env file
  with a commit message naming the rollout phase.
- Other 4 nodes still off.

**What's live:**
- 1-node cluster, threshold (effectively) 1-of-1 — degenerate case.
- The on-chain `OracleConfig.cluster_keys` lists 5 keys; only 1 is
  reachable. Day-25 commit-reveal will time out the 4 missing peers
  every epoch. **Cert writes will FAIL** — that is expected for this
  phase.

**Goal during this phase is to validate:**
- Mainnet RPC connectivity, fee-payer SOL outflow, journald logs.
- The `network_guard` PRODUCTION-opt-in log line appears once at start.
- Metrics endpoint exposes the expected counters.
- The Prometheus stack scrapes mainnet successfully.
- Manual chaos: stop the node, restart, confirm guard fires once on
  start, runs cleanly thereafter.

**Duration:** ~24 hours.

**Exit criteria to Phase 2:** logs clean, metrics flowing, no
`ProductionRefusalTriggered` other than expected restarts. The node has
been running > 12 hours.

**Abort:** anything other than the expected timeout-failure pattern.
Stop the node, file a postmortem.

---

## Phase 2 — Three mainnet nodes up (cluster reaches threshold)

**Goal:** the cluster starts ACTUALLY producing certs on mainnet. This
is the first moment any score is anchored on-chain via the BFT path.

**Entry criteria:** Phase 1 validated.

**Bring up:** nodes 1 and 2 join. Cluster is now 3 of the configured 5.

**What's live:**
- 3 nodes, threshold 3-of-5 — exactly the minimum for cert writes.
- Cert writes BEGIN. The first 24-hour epoch produces certs.
- The 2 missing nodes (3, 4) are timed out every epoch — the cluster
  treats them as faulty. This is correct.

**What to watch:**
- First mainnet cert: agent_wallet, epoch, score, alert tier — confirmed
  via explorer.
- `helixor_epoch_seconds` histogram — baseline the production latency.
- No `ByzantineNodeDetected` (the 3 nodes should agree exactly).
- Cert sigs == 3 (the minimum); any cert with > 3 is a bug.

**Duration:** ~3 days.

**Exit criteria to Phase 3:** ≥ 3 consecutive 24-hour epochs complete
with all certs threshold-signed. No alerts other than the documented
missing-peer timeouts. The team has read every cert log entry.

**Abort:**
- Any cert write fails (other than known RPC blips with retry).
- Any `ByzantineNodeDetected` fires.
- Latency p95 > 60s.
**Action:** stop all nodes, file postmortem.

---

## Phase 3 — Five mainnet nodes up (full BFT)

**Goal:** the full 5-of-5 cluster is running. The cluster now tolerates
2 faults and is BFT-correct under the Day-28 chaos guarantees.

**Entry criteria:** Phase 2 validated.

**Bring up:** nodes 3 and 4 join, completing the 5-node cluster.

**What's live:**
- 5-node cluster, threshold 3-of-5.
- Per-cert sigs may now exceed 3 (typically 3 — the minimum needed —
  but up to 5 if assembly picks more).
- Day-28 fault tolerance is in effect: ANY single node down still
  produces certs.

**What to watch:**
- The cluster latency drops compared to Phase 2 (more parallel signers).
- 24/7 alerting active — pager rotation begins.

**Duration:** ~7 days.

**Exit criteria to Phase 4:** 7 consecutive 24-hour epochs clean.

**Abort:** as in Phase 2, plus any below-quorum alert. The cluster
should NEVER be below quorum in this phase.

---

## Phase 4 — Agent registration open

**Goal:** real users start registering agents and reading scores. The
cluster is now in production-use.

**Entry criteria:** Phase 3 validated.

**Open:**
- The agent-registration API endpoint.
- The score-read API endpoint (public).
- Documentation + onboarding flow live.

**What's live:** the full V2 product.

**What to watch:**
- Registration rate vs API capacity (API load test target: 10K read
  req/h sustained).
- Per-agent score distribution — is the protocol producing reasonable
  numbers on real agents?
- Indexer growth — projected size in 12 months.

**This is the actual launch.**

---

## Sequence summary

```
 Phase 0 → 1 → 2 → 3 → 4
 deploy   1 node  3 nodes  5 nodes  open
 (programs)       (writes  (full     (public)
                   begin)   BFT)
```

| Phase | Nodes | Cert writes | Duration | Exit gate |
|-------|-------|-------------|----------|-----------|
| 0     | 0     | no          | < 1 day  | Phase-0 validation |
| 1     | 1     | no          | ~1 day   | Mainnet stack works |
| 2     | 3     | yes         | ~3 days  | 3 epochs clean |
| 3     | 5     | yes (BFT)   | ~7 days  | 7 epochs clean, no alerts |
| 4     | 5     | yes (BFT)   | open     | — |

---

## How to revert from any phase

The Squads vault holds upgrade authority. To roll back the on-chain
programs, the 3-of-5 multisig signs an `upgrade` to the prior `.so`
hash recorded in `launch/deploy/manifest.json`. To roll back the
cluster, stop nodes in reverse phase order (5 → 3 → 1 → 0). The cluster
gracefully degrades — sustained quorum is the only requirement for the
remaining nodes to keep producing certs.
