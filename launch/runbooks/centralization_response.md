# Runbook — Centralization regression response

**Severity:** Critical (any HCR gate red means a hidden-centralization
mitigation has either been removed from the tree or has fired at
runtime).
**Triggers:**
- `audit/centralization_check.py` gate fails in CI.
- Boot-time `ProviderDiversityError` on oracle production-config
  construction (HCR-1).
- Boot-time `RegionDiversityError` on cluster topology validation
  (HCR-2).
- `SharedStateDependencyError` raised by the in-process boot hook OR
  by the CI gate (HCR-3).
- `OperatorDiversityError` raised when loading the cluster operator
  manifest (HCR-4).

## What's happening

One of the four hidden-centralization mitigations (HCR-1..HCR-4) has
either had its mechanical anchor removed from the tree, or has fired at
runtime to refuse a non-diverse configuration. The mitigations in
`launch/design/centralization_resolution.md` are the load-bearing
reifications of audit claims about diversity of the underlying
substrate; this runbook is the playbook for reacting when one of them
triggers OR regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code is
  not yet on mainnet. Block the merge and restore the anchor.
- **Runtime fire** — the mitigation engaged and refused to start a
  process. Mainnet is protected; diversify the configuration before
  bringing the process back. Do NOT "fix" the gate.

---

## CI gate red — `audit/centralization_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which HCR(s) regressed.
python3 audit/centralization_check.py --json /tmp/hcr.json
cat /tmp/hcr.json | python3 -m json.tool | head -80

# 2. Look at the rule names — each maps to one line in
#    audit/centralization_check.py that says exactly what marker
#    string the gate could not find.
```

### Decision tree

- **Marker file deleted** (`provider_diversity.py`, `region_diversity.py`,
  `state_isolation.py`, `operator_manifest.py`): the closing PR removed
  a mitigation the audit assumes is present. RESTORE the file from
  `main`. The reviewer who approved the removal must justify the change
  in writing on the PR.
- **Diversity floor changed** (`MIN_DISTINCT_RPC_PROVIDERS`,
  `MIN_DISTINCT_REGIONS`, `MIN_DISTINCT_OPERATORS`,
  `MIN_DISTINCT_JURISDICTIONS`): a load-bearing audit floor has moved.
  Restore to the pinned `2`; if the change is intentional, the audit
  gate's expected value MUST be updated IN THE SAME PR and the PR
  description must call out the centralization-risk impact.
- **Cluster shape changed** (`DEFAULT_CLUSTER_SIZE`,
  `DEFAULT_CLUSTER_THRESHOLD`): the 3-of-5 default underpins the
  region N − K cap. If this changes, the per-region cap also changes;
  re-derive `max_per_region = N - K` and re-pin the audit constants in
  lockstep.
- **`KNOWN_PROVIDERS` shrunk**: a major Solana RPC provider (helius,
  quicknode, triton) has disappeared from the bucketing table. Without
  the bucket, two endpoints from that provider will classify as
  `unknown:<host>` separately and silently pass diversity. Restore the
  table entry.
- **`SIGNING_PATH_MODULES` shrunk**: a trust-bearing module
  (`oracle.cluster.signer`, `scoring.composite`, etc.) was removed from
  the contract. The gate has now stopped checking that module for
  forbidden imports. Restore the entry; if the module was genuinely
  removed from the codebase, the audit doc must be updated to explain
  the new trust path.
- **`SHARED_STATE_FORBIDDEN_IMPORTS` shrunk**: `aiokafka`, `redis`, or
  `confluent_kafka` is gone from the forbidden list. Restore them —
  these are the marquee shared-state clients HCR-3 exists to refuse.
- **`live-signing-path-isolated` failed**: a signing-path module
  ACTUALLY imports a shared-state client now. The report names the
  offending `(module, import)` pair. Move the import out — bus traffic
  must cross `oracle/cluster/kafka_ingest.py`, never reach a
  trust-bearing module directly.

---

## Runtime fire — HCR-1 `ProviderDiversityError` on oracle boot

### Triage (60s)

```bash
docker compose -f launch/deploy/docker-compose.oracle.yml logs oracle | tail -50
# Look for: "HCR-1: only 1 distinct RPC provider(s) across N endpoints"
echo "$PHYLANX_SOLANA_RPC_ENDPOINTS"
```

### Action

The mitigation engaged — the oracle EXITED at boot rather than commit
through a single-provider RPC fleet. DO NOT collapse the endpoint list
or lower `MIN_DISTINCT_RPC_PROVIDERS`. Instead:

1. Inspect the report's `provider_counts` — it lists every URL's
   classified bucket. Endpoints sharing a bucket are the
   centralization root cause.
2. Provision at least ONE endpoint at a different upstream provider
   (Helius + Triton + QuickNode is the canonical mainnet floor).
3. If the URL is from a provider not in `KNOWN_PROVIDERS`, classification
   will bucket it as `unknown:<host>` — that already satisfies
   diversity with any known-provider sibling; but consider adding the
   host suffix to `KNOWN_PROVIDERS` so future deploys benefit from
   correct bucketing.

---

## Runtime fire — HCR-2 `RegionDiversityError` on cluster topology

### Triage (60s)

```bash
docker compose logs oracle | grep "HCR-2"
# Look for: "HCR-2: region 'aws:us-east-1' hosts X of N nodes"
# OR        "HCR-2: only 1 distinct region(s)"
```

### Action

The cluster is configured such that losing one region collapses
threshold. DO NOT lower `MIN_DISTINCT_REGIONS` or `DEFAULT_CLUSTER_THRESHOLD`.
Instead:

1. Inspect the report's `region_counts`. If one region holds
   `> N - K` nodes (e.g. 3 of 5 in `us-east-1` with K=3), redistribute
   ONE node to a different region. The N − K cap is the load-bearing
   line — losing the most-populated region MUST leave at least K
   honest nodes.
2. If `distinct_regions == 1`, no amount of N nodes saves you — at
   least one node MUST move to a second region (different cloud,
   different country, ideally different cloud-provider too).
3. The region string is OPAQUE — `"aws:us-east-1"` and
   `"aws:us-east-1b"` are different regions to the gate. Be honest:
   if two "regions" share an underlying availability zone, they are
   one failure domain. Use distinct strings only when failure domains
   are genuinely independent.

---

## Runtime fire — HCR-3 `SharedStateDependencyError` on oracle boot

### Triage (60s)

```bash
docker compose logs oracle | grep -A 20 "HCR-3"
# The exception's .report lists (module, forbidden_import) tuples.
```

### Action

A signing-path module imports a shared-state client. This is a
structural regression — the import was added since the audit anchor
was committed, and either (a) the in-process boot hook caught it OR
(b) the CI gate caught it. The fix is identical for both:

1. Locate the offending module from the report. Run:
   `grep -n -E "^(import|from) (aiokafka|kafka|confluent_kafka|redis|aioredis|memcache|pymemcache|nats|asyncpg|psycopg2|psycopg|sqlalchemy)" phylanx-oracle/oracle/<module>.py`
2. Move the import OUT of the trust-bearing module. Bus traffic must
   cross `oracle/cluster/kafka_ingest.py` — never reach the signer,
   the scorer, or the slashing detector directly.
3. If the signing-path module genuinely needs data the bus carries,
   pass it through the `Broker` interface (the kafka_ingest bridge
   adapts to either an in-memory or confluent-adapter broker; the
   signing path consumes structured `AgentEpochInput` objects, not
   raw kafka records).
4. DO NOT remove the module from `SIGNING_PATH_MODULES` to make the
   gate green — that is the regression the gate exists to catch.

---

## Manifest fire — HCR-4 `OperatorDiversityError` on cluster boot

### Triage (60s)

```bash
# The cluster ships with a manifest file the boot sequence loads.
# The exception's .report carries the per-org and per-jurisdiction
# tallies.
cat /etc/phylanx/operator_manifest.json | python3 -m json.tool | head -40
```

### Action

The cluster's operator manifest declares a distribution that does NOT
survive HCR-4. The cluster REFUSES to commit. DO NOT lower the
diversity floors. Instead:

1. Inspect `report.org_counts` and `report.largest_org_count`. If one
   organisation owns ≥ threshold pubkeys, the social-not-technical
   3-of-5 risk is live. Recruit at least one operator from a separate
   organisation before redeploy.
2. If `report.distinct_jurisdictions < 2`, the cluster is reachable by
   a single legal-process compulsion. At minimum one operator MUST be
   in a different ISO-3166 jurisdiction — different country, not just
   different state.
3. If the manifest's `node_id` or `pubkey` is a duplicate, the
   construction-time check (`OperatorManifestError`) caught a
   bookkeeping error. The fix is editorial, not architectural.
4. Remember: HCR-4 enforces the MATH. The truthfulness of the
   declarations is the external auditor's job. A manifest passing the
   gate while one operator secretly runs two pubkeys is an
   audit-discipline failure, not a code failure.

---

## Verifying the response

After every fix, re-run the gate locally:

```bash
python3 audit/centralization_check.py --json /tmp/hcr.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_centralization_check.py -v
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest phylanx-oracle/tests/oracle/test_hcr1_provider_diversity.py \
                    phylanx-oracle/tests/oracle/test_hcr2_region_diversity.py \
                    phylanx-oracle/tests/oracle/test_hcr3_state_isolation.py \
                    phylanx-oracle/tests/oracle/test_hcr4_operator_diversity.py -v
```

All three MUST be green before the PR is mergeable.
