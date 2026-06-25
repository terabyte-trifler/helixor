# Runbook — Trust-assumption regression response

**Severity:** Critical (any TA gate red means a load-bearing audit
guarantee is no longer enforced).
**Triggers:**
- `audit/trust_assumption_check.py` gate fails in CI.
- Runtime `LibraryVerificationError` on oracle / API boot (TA-4).
- Runtime `UnverifiedStreamSourceError` on indexer boot (TA-2).
- Runtime `RpcDivergenceError` from the oracle's commit path (TA-8).
- A `DivergenceReport` is produced off-chain with a non-empty
  `divergent_nodes` set (TA-1).

## What's happening

One of the eight audit trust assumptions (TA-1..TA-8) has either had
its mechanical anchor removed from the tree, or has fired at runtime.
The mitigations in `launch/design/trust_resolution.md` are the load
bearing reifications of audit claims; this runbook is the playbook for
reacting when one of them triggers OR regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code is
  not yet on mainnet. Block the merge and restore the anchor.
- **Runtime fire** — the mitigation engaged and refused to start a
  process. Mainnet is protected; investigate the upstream cause before
  bringing the process back.

---

## CI gate red — `audit/trust_assumption_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which TA(s) regressed.
python3 audit/trust_assumption_check.py --json /tmp/ta.json
cat /tmp/ta.json | python3 -m json.tool | head -80

# 2. Look at the rule names — each maps to one line in
#    audit/trust_assumption_check.py that says exactly what marker
#    string the gate could not find.
```

### Decision tree

- **Marker file deleted** (e.g. `divergence.py`, `multi_rpc.py`,
  `squads_transition.rs`, `library_verification.py`,
  `tx_window_digest.py`): the closing PR removed a mitigation that the
  audit assumes is present. RESTORE the file from `main`. Reviewer who
  approved the removal must justify the change in writing on the PR.
- **Constant changed** (`MAX_AGE_SECONDS`, `MAINNET_MIN_RPC_ENDPOINTS`,
  `MIN_RPC_CONSENSUS_THRESHOLD`, `DEFAULT_SCORE_TOLERANCE`,
  `SQUADS_TRANSITION_DEADLINE_UNIX`): a load-bearing audit value has
  moved. Restore to the pinned value; if the change is intentional, the
  audit gate's expected value MUST be updated IN THE SAME PR and the
  PR description must call out the trust-assumption impact.
- **Library pin out of lockstep** (TA-4 manifest vs. `requirements.in`):
  ONE side was bumped without the other. Re-pin both to the same
  version; rerun `scripts/regen_requirements.sh` to refresh the hash
  lock; re-run the gate.
- **Squads UNIX vs. ISO drift**: the human-readable mirror was not
  updated alongside the unix value. Bring the two back into lockstep
  before merge.
- **Runner pre-flight missing** (TA-2 `assert_source_verified_for_cluster(source)`
  call): the indexer can now boot on mainnet with a single-endpoint
  source. RESTORE the call in `indexer/runner.py:__init__` before any
  release.

---

## Runtime fire — TA-2 `UnverifiedStreamSourceError` on indexer boot

### Triage (60s)

```bash
docker compose -f launch/deploy/docker-compose.indexer.yml logs indexer | tail -50
# Look for: "TA-2: cluster 'mainnet' requires a verified ConsensusStream"
echo "$PHYLANX_GEYSER_ENDPOINTS"
echo "$PHYLANX_SOLANA_CLUSTER"
```

### Action

The mitigation engaged — the indexer EXITED at boot rather than ingest
single-endpoint mainnet data. DO NOT downgrade the cluster env var.
Instead:

1. Verify `PHYLANX_GEYSER_ENDPOINTS` lists at least 3 independent
   endpoints (no duplicates, no shared upstream).
2. Verify the construction path goes through
   `build_production_geyser_config()` + `ConsensusStream`. A raw
   `YellowstoneStreamSource` is REFUSED on mainnet by design.
3. If a deploy script bypasses the factory, fix the script — do not
   "fix" the gate.

---

## Runtime fire — TA-4 `LibraryVerificationError` on oracle / API boot

### Triage (60s)

```bash
docker compose -f launch/deploy/docker-compose.api-ha.yml logs api-1 | tail -50
# Look for: "library_verification: cryptography version mismatch"
pip show cryptography solana solders grpcio | grep -E '^(Name|Version)'
```

### Action

The process EXITED rather than open a network port with an unverified
crypto library. Either:

1. The deploy host has a different library installed than the
   hash-locked `requirements.txt` declares — re-run
   `pip install --require-hashes -r requirements.txt` in a clean
   venv.
2. The pinned manifest (`EXPECTED_LIBRARY_VERSIONS`) was updated but
   `requirements.in` was not (or vice versa) — see the "Library pin out
   of lockstep" branch under the CI gate section. This is a CI gate
   regression that slipped to runtime; the immediate fix is to redeploy
   the previous image while the lockstep is restored.

---

## Runtime fire — TA-8 `RpcDivergenceError` from the oracle commit path

### Triage (60s)

```bash
# The exception's .report carries the per-endpoint outcome. The oracle
# logs it at ERROR before re-raising.
docker compose logs oracle | grep -A 20 "RpcDivergenceError"
```

### Action

K-of-N agreement was NOT reached for an oracle RPC read (slot,
blockhash, account state). The commit DID NOT submit — mainnet is
protected against the hostile-RPC scenario. Possible causes:

1. One endpoint is genuinely behind / forked. Inspect the
   per-endpoint values in `report.responses`; the outlier is the
   suspect.
2. Two of three endpoints share infrastructure (same upstream
   provider). Diversify — the SPOF-#8 / TA-8 floor requires
   INDEPENDENT endpoints.
3. Network partition affecting one provider. Wait it out, retry the
   commit. The cluster does not advance until quorum is restored.

DO NOT lower `MIN_RPC_CONSENSUS_THRESHOLD` to make the error go away.

---

## Off-chain fire — TA-1 `DivergenceReport` with non-empty divergent set

### Triage (60s)

```bash
# Look up the divergence_evidence_hash in the slashing log channel.
# The detector's hash is canonical — every honest cluster member
# computed the same one.
```

### Action

One or more cluster nodes diverged from the median by more than
`DEFAULT_SCORE_TOLERANCE = 50` for an epoch, OR disagreed with the
majority on the `immediate_red` bit. This is the slow-burn case TA-1
exists to surface:

1. Cross-check the per-node submissions in the slashing log — the
   detector is pure, so the same inputs produce the same evidence.
2. If the divergent node is in your operator set and has a benign
   cause (deploy mismatch, clock skew, slow Geyser), correct and
   redeploy. The challenge window is still open; no on-chain action
   yet.
3. If the divergent node is HOSTILE, the evidence hash is the input
   to a future `challenge_oracle` instruction. Stage the challenge
   transaction per the slash-authority docs.

---

## Verifying the response

After every fix, re-run the gate locally:

```bash
python3 audit/trust_assumption_check.py --json /tmp/ta.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_trust_assumption_check.py -v
```

Both MUST be green before the PR is mergeable.
