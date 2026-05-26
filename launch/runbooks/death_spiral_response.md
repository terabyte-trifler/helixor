# Runbook — Protocol Death Spiral mitigation response

**Severity:** Critical (any PDS gate red means a mitigation against
the audit's catastrophic Scenario A — Protocol Death Spiral — has
either been removed from the tree or fired at runtime).
**Triggers:**
- `audit/death_spiral_check.py` gate fails in CI.
- Cluster pre-issue raises `ScoreSaturationError` (PDS-1) refusing to
  sign an epoch batch.
- SDK consumer (or cluster pre-issue) raises `ScoreVelocityError`
  (PDS-2) refusing a cert pair.
- Forensic / cluster operator raises `CorrelatedInflationError`
  (PDS-3) after seeing a rolling-window directional event or a
  mass-failure event.

## What's happening

The Protocol Death Spiral (audit Scenario A) is the 7-step
catastrophic-failure mode that compromises two oracle nodes, runs
VULN-03 slow-drift inflation for ~30 epochs, saturates the agent
universe in the GREEN tier, drains DeFi loan capacity, and detonates
correlated agent failures so every loan defaults simultaneously. The
three mitigations in `launch/design/death_spiral_resolution.md` are
the load-bearing reifications of the audit's claims that each
substrate of the spiral has a fail-closed defence. This runbook is
the playbook for reacting when one of them fires or regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code is
  not yet on mainnet. Block the merge and restore the anchor. DO NOT
  weaken the gate to make CI green.
- **Runtime fire** — the mitigation engaged and refused to commit /
  emit a cert / accept a cert pair. Mainnet is protected; investigate
  the population-level event before bringing the affected process
  back online.

---

## CI gate red — `audit/death_spiral_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which PDS family regressed.
python3 audit/death_spiral_check.py --json /tmp/pds.json
cat /tmp/pds.json | python3 -m json.tool | head -80

# 2. Each finding names the rule and the marker string the gate could
#    not find. The PDS-N tag tells you which family regressed.
```

### Decision tree

- **Marker file deleted** (`saturation_gate.py`, `score_velocity.py`,
  `correlated_inflation.py`): the closing PR removed a mitigation the
  audit assumes is present. RESTORE the file from `main`. The reviewer
  who approved the removal must justify the change in writing on the
  PR.
- **`verify_*` / `enforce_*` function disappeared**: a contract entry
  point is gone. Restore it. If the function was genuinely renamed in
  good faith, the audit gate's expected marker MUST be updated IN THE
  SAME PR and the PR description must call out the death-spiral
  closure impact.
- **PDS-1 threshold changed** (`HIGH_BAND_FLOOR`,
  `MAX_HIGH_BAND_MIGRATION_FRACTION`, `ABSOLUTE_HIGH_BAND_CEILING`,
  `VARIANCE_COLLAPSE_THRESHOLD`): a load-bearing audit floor moved.
  Restore the pinned value. If the change is intentional, update the
  audit gate's expected constant IN THE SAME PR; the PR description
  must explain why a tighter or looser floor better fits the live
  agent-population distribution (e.g. measured noise from devnet
  bake).
- **PDS-2 threshold changed** (`MAX_SCORE_DELTA_PER_EPOCH`,
  `MAX_SCORE_VELOCITY_PER_HOUR`, `ABSURD_VELOCITY_PER_HOUR`): a
  velocity cap moved. Restore the pinned value. CRITICAL CHECK:
  `MAX_SCORE_DELTA_PER_EPOCH` MUST equal
  `scoring/_gaming.MAX_SCORE_DELTA`. The gate's
  `scoring-gaming-cap-in-lockstep` rule exists exactly to catch the
  refactor where one is changed without the other; never make CI
  green by changing one of them in isolation.
- **PDS-3 threshold changed** (`CORRELATION_WINDOW`,
  `MAX_DIRECTIONAL_SHARE`, `MASS_FAILURE_DROP`,
  `MASS_FAILURE_AGENT_FRACTION`): a rolling-window or mass-failure
  threshold moved. Restore the pinned value. If a window length is
  genuinely being retuned (e.g. moving from 5 pairs to 7), the
  per-module property test
  `tests/oracle/test_pds3_correlated_inflation.py` and the audit
  gate must move in lockstep, with the rationale recorded on the PR.

### After every fix

```bash
python3 audit/death_spiral_check.py --json /tmp/pds.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_death_spiral_check.py -v
```

Both MUST be green before the PR is mergeable.

---

## Runtime fire — PDS-1 `ScoreSaturationError` on cluster pre-issue

### Triage (60s)

```bash
journalctl -u oracle-node@0 --since "10 min ago" | grep -A 20 "PDS-1"
# The exception's .report carries:
#   - epoch
#   - high_band_count, high_band_fraction, std_dev
#   - prior_high_band_fraction, migration_fraction
#   - reasons: ['MIGRATION_BURST', 'ABSOLUTE_CEILING', 'VARIANCE_COLLAPSE']
```

### Action

The cluster REFUSED to sign the cert batch because the agent
distribution saturated. This is the audit's step-3 fingerprint
(VULN-03 slow drift culminating in cross-agent migration into the
GREEN band). The cluster is protected — no inflated cert reaches the
chain. The job is now to identify whether this is a real attack OR a
genuine population shift the gate is rightly refusing:

1. Inspect `report.high_band_fraction` against the prior-day
   baseline (Prometheus
   `helixor_agent_score_band{band="HIGH"}`). A jump from ~30% to
   ~70% within ONE epoch with no announced market event is the
   poisoning fingerprint.
2. Cross-check against PDS-3's rolling-window report — if PDS-3
   already flagged `is_correlated=True` over the prior 5 epochs,
   this is by-construction the death spiral. Escalate to the
   incident lead and pull the upstream RPC fleet's evidence (the
   AW-01-EXT slot anchors on prior certs will name which RPCs the
   cluster trusted — that's the substrate to investigate).
3. If the population shift is honest (e.g. a real bullish event the
   cluster's signals reflect), the gate is being conservative on
   purpose. DO NOT lower `MAX_HIGH_BAND_MIGRATION_FRACTION` to make
   the cluster emit the cert. Instead, the operator-cluster decides
   to RE-RUN the epoch with a fresh upstream snapshot or to WAIT one
   epoch for the migration to stabilise under PDS-1's per-epoch cap.
   A legitimate bullish event spread across multiple epochs will not
   trip the migration cap once it's already in steady state.
4. If `report.std_dev` collapsed (variance fingerprint) but the
   migration fraction is small, this is the LATE-stage fingerprint
   (the agent universe converging on similar inflated values). This
   is structurally implausible and almost certainly indicates either
   upstream poisoning or a scoring-kernel bug — pull the AW-04
   `score_components_hash` from prior certs and re-run
   `verifyScoreComputation` on a sample to confirm the kernel still
   produces dim-additive output.

DO NOT remove the offending agents from the snapshot or lower the
thresholds to push the batch through. The gate is the last line of
defence before an inflated batch reaches the chain.

---

## Runtime fire — PDS-2 `ScoreVelocityError` on the SDK / pre-issue

### Triage (60s)

```bash
# SDK consumer side (DeFi integration):
# The exception's .report carries score_delta, elapsed_seconds,
# velocity_per_hour, and reasons.
# Example reasons:
#   EPOCH_DELTA_EXCEEDS_CAP, VELOCITY_EXCEEDS_CAP,
#   ABSURD_VELOCITY, PREVIOUS_AFTER_CURRENT
```

### Action

The cert pair (current, previous) failed the velocity contract. The
SDK consumer refused to make the loan decision. This is the audit's
step-4 defence — the consumer is supposed to be protected even if the
cluster is captured. The fix depends on the reason:

1. `EPOCH_DELTA_EXCEEDS_CAP` (delta > 200): the cluster emitted a
   cert pair whose score moved by more than the per-epoch clamp.
   This is by-construction a CLUSTER BUG (the internal
   `scoring/_gaming.MAX_SCORE_DELTA = 200` clamp should already have
   refused this) OR a regression: confirm
   `scoring/_gaming.MAX_SCORE_DELTA == 200` AND
   `score_velocity.MAX_SCORE_DELTA_PER_EPOCH == 200`. If the two are
   in lockstep, the violation is on the cluster side — file a P0,
   stop new loans against ALL certs from the affected cluster epoch
   until the internal clamp is restored.
2. `VELOCITY_EXCEEDS_CAP` (sustained 100+ points/hour): the cluster
   is moving its full per-epoch cap continuously. This is the
   slow-drift attack midway through. Re-pull the prior 5 epochs'
   certs and check PDS-3's rolling-window report — if PDS-3 also
   flags, this is the death spiral. If PDS-3 is clean, the velocity
   is a genuine signal change (possibly a sudden score collapse).
3. `ABSURD_VELOCITY` (500+ points/hour): no operational scenario
   produces this. Treat the cert as adversarial; refuse the loan
   regardless of other freshness signals. Log to the SDK consumer's
   incident channel.
4. `PREVIOUS_AFTER_CURRENT` (clock rewind): the previous cert's
   `issued_at` is AFTER the current cert's. Either the cluster
   produced two adjacent-epoch certs out of order (a serious
   sequencing bug) OR the consumer fetched the wrong PDA pair.
   Recompute `["cert", agent_wallet, epoch_le]` for both epochs and
   confirm `epoch_current == epoch_previous + 1`.

DO NOT increase the velocity caps to make the cert pair accepted.
The SDK gate exists to protect the consumer from a captured cluster
— making the gate looser silently aligns the consumer's risk with
the cluster's. Defence-in-depth requires the two sides to enforce
the same contract independently.

---

## Runtime fire — PDS-3 `CorrelatedInflationError` from forensic / cluster

### Triage (60s)

```bash
# Generated by the cluster operator's forensic / cross-epoch monitor.
# The exception's .report carries:
#   - For correlated movement:
#     window_size, mean_up_share, mean_down_share, direction,
#     is_correlated, evidence_hash (64 hex)
#   - For mass failure:
#     epoch, failed_agents, population_size, failure_fraction,
#     is_mass_failure, evidence_hash
```

### Action

PDS-3 fired BECAUSE either (a) the rolling window over the last 5
adjacent-epoch pairs went directionally one-way past 85%, or (b) 50%+
of the population took a 200+ point hit in one epoch. The first is
the slow-drift midway-through fingerprint; the second is the
terminal-detonation fingerprint.

1. **If `direction == "UP"` and `is_correlated`**: this is step 2-3 of
   the spiral mid-execution. PDS-1 has not yet fired (the per-epoch
   migration fraction is still below 40%), but the rolling window is
   already lit. The cluster should STOP signing new certs until the
   upstream RPC fleet is re-verified — the most likely root cause is
   shared upstream poisoning, NOT a single compromised node.
   Cross-check the AW-01-EXT slot anchors on the last 5 epochs' certs
   to identify which RPCs the cluster trusted; rotate any RPC whose
   `(slot, block_hash)` could not be independently re-verified from
   an out-of-band ledger.
2. **If `direction == "DOWN"` and `is_correlated`**: this is the
   recovery of a previously inflated population (the spiral's
   detonation phase) OR a real cross-market crash. The cluster
   should KEEP signing — a directionally-down event is reflecting
   reality, not creating loss. But the SDK PDS-2 cap will refuse
   adjacent-epoch pairs whose drop exceeds 200, so DeFi consumers
   will see velocity rejections; that is the INTENDED behaviour and
   protects new loans. Communicate to integration partners via the
   normal incident channel.
3. **If `is_mass_failure`**: this is the terminal-detonation
   fingerprint. The population is exhibiting a coordinated 200+
   point drop. This is rarely honest — the most likely root cause is
   either step 5 of the spiral (the attacker pulling the trigger) or
   a catastrophic systemic event (RPC fleet failure, scoring kernel
   bug). The cluster should HALT and the incident lead should be
   paged. The mass-failure evidence hash is forensic — preserve it.
4. **Evidence-hash discipline**: PDS-3's hash is COUNT-based and
   reproducible by any honest cluster member. Anyone disputing the
   finding must produce a window whose evidence hash differs; if
   they cannot, the finding is binding. This is what makes PDS-3
   useful AFTER the cluster has been compromised — even a captured
   cluster cannot rewrite the evidence hash for an already-emitted
   sequence of certs.

DO NOT relax `MAX_DIRECTIONAL_SHARE` or `MASS_FAILURE_AGENT_FRACTION`
in response to a fire. The thresholds are calibrated for the
attack-vs-honest-noise boundary; lowering them re-opens the substrate
the gate was designed to refuse.

---

## Verifying the response

After every fix, re-run the gate and tests locally:

```bash
python3 audit/death_spiral_check.py --json /tmp/pds.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_death_spiral_check.py -v
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest \
    helixor-oracle/tests/oracle/test_pds1_saturation_gate.py \
    helixor-oracle/tests/oracle/test_pds2_score_velocity.py \
    helixor-oracle/tests/oracle/test_pds3_correlated_inflation.py -v
```

All three MUST be green before the PR is mergeable. For a runtime
fire, the additional bar is that the cluster operator has documented
the root cause of the population-level event (poisoned RPC,
compromised node, honest market shift) in the incident channel — the
gate is the alarm, not the diagnosis.
