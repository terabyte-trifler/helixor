# Centralization Resolution — the four audit hidden-centralization risks

**Status:** IMPLEMENTED.
**Audit findings:** the 4-entry HIDDEN CENTRALIZATION RISKS inventory
from the launch-readiness audit (HCR-1..HCR-4).
**Owners:** platform engineering (HCR-1, HCR-2), oracle engineering
(HCR-3), protocol engineering (HCR-4).
**Related code / config:**
- `phylanx-oracle/oracle/provider_diversity.py` (HCR-1)
- `phylanx-oracle/oracle/region_diversity.py` (HCR-2)
- `phylanx-oracle/oracle/state_isolation.py` (HCR-3)
- `phylanx-oracle/oracle/operator_manifest.py` (HCR-4)
- `phylanx-oracle/tests/oracle/test_hcr1_provider_diversity.py`
- `phylanx-oracle/tests/oracle/test_hcr2_region_diversity.py`
- `phylanx-oracle/tests/oracle/test_hcr3_state_isolation.py`
- `phylanx-oracle/tests/oracle/test_hcr4_operator_diversity.py`
- `audit/centralization_check.py` + `audit/test_centralization_check.py`
  (mechanical regression gate)

---

## Why a unified centralization closure

The audit closed every NAMED single point of failure (the 9-entry SPOF
inventory) and every NAMED trust assumption (the 8-entry TA inventory).
What remained were four HIDDEN centralization risks — places where the
protocol's "no single point of trust" guarantee was real on paper but
collapsed under a SHARED-INFRASTRUCTURE attack. Each is a different
shape of "the threshold math is valid but the substrate underneath
isn't independent":

- **HCR-1**: every oracle node reads from the same RPC PROVIDER.
- **HCR-2**: every oracle node and the database live in the same CLOUD
  REGION.
- **HCR-3**: every signing-path module shares the same KAFKA / REDIS
  INSTANCE.
- **HCR-4**: every cluster pubkey is held by the same ORGANISATION.

Closing each one is a layered exercise: a deterministic helper in the
oracle codebase that REIFIES the diversity contract, a property test
that pins it, and a static-grep gate that catches accidental
regression at CI time. The audit gate at
`audit/centralization_check.py` is the mechanical proof; this doc is
the narrative for an external reviewer.

The discipline mirrors the SPOF and TA closures: every hidden
centralization risk is either ELIMINATED (the dependency is structurally
removed) or REIFIED (the diversity contract becomes a check the code
performs, not a thing the audit must trust).

---

## The HCR inventory

| #  | Hidden centralization risk                                       | Risk shape                  | Mitigation                                                                                                       | Gate                |
|----|------------------------------------------------------------------|-----------------------------|------------------------------------------------------------------------------------------------------------------|---------------------|
| 1  | RPC provider monoculture                                         | substrate-outage SPOF        | `verify_provider_diversity` + `KNOWN_PROVIDERS` host-suffix bucketing + `MIN_DISTINCT_RPC_PROVIDERS = 2`.        | HCR gate HCR-1      |
| 2  | Single cloud region for nodes + DB                               | substrate-outage SPOF        | `verify_region_diversity` enforces `max_per_region <= N - K` and `distinct_regions >= 2` on a 3-of-5 default.   | HCR gate HCR-2      |
| 3  | Shared Kafka/Redis SPOF reaching the signing path                | substrate-compromise reach   | `verify_signing_path_isolation` static-greps every trust-bearing module for `aiokafka`/`redis`/etc. imports.    | HCR gate HCR-3 + live re-verify |
| 4  | One operator holding ≥ threshold pubkeys                         | social-not-technical 3-of-5  | `verify_operator_diversity` rejects manifests where any org owns ≥ threshold pubkeys OR < 2 jurisdictions.       | HCR gate HCR-4      |

---

## How each fix works

### HCR-1 — RPC provider monoculture

The cluster's SPOF-#8 mitigation already required N ≥ 3 RPC endpoints
with K-of-N consensus. The HIDDEN centralization risk was that three
URLs could all be `*.helius-rpc.com`, `*.helius.xyz`, and
`backup.helius.io` — three endpoints, ONE upstream provider. A Helius
outage halts every "independent" endpoint at once.

`oracle/provider_diversity.py` reifies the diversity contract:

- `KNOWN_PROVIDERS` maps coarse host-suffix patterns to a bucket name
  (`helius`, `triton`, `quicknode`, `alchemy`, `ankr`, `blockdaemon`,
  `chainstack`, `syndica`, `getblock`, `extrnode`, `solana-labs`,
  `serum`). Unknown hosts bucket as `unknown:<host>` — strictly
  conservative: an unrecognised host is its own bucket, so a typo cannot
  silently merge two endpoints.
- `classify_provider(url)` uses longest-suffix match on `urlparse().host`
  so `mainnet.helius-rpc.com` and `devnet.helius-rpc.com` both bucket
  as `helius` regardless of subdomain.
- `verify_provider_diversity(endpoints, *, min_distinct=2)` raises
  `ProviderDiversityError` (with `.report` attached) if the endpoint
  list collapses below the floor. `MIN_DISTINCT_RPC_PROVIDERS = 2` is
  the pinned floor — the construction-time gate refuses a single-
  provider mainnet config.

The gate is a CONSTRUCTION-time check, not a runtime one: callers wire
it into the production config factory so a mainnet deploy with three
Helius URLs fails fast, before opening any sockets.

### HCR-2 — single-cloud-region monoculture

Even with N independent RPC providers, an oracle cluster that runs ALL
its compute and its database in `us-east-1` is a one-AWS-outage-from-
dead system. The cluster's 3-of-5 threshold math assumes losing one
node leaves four; if all five share a region, an `us-east-1` event
kills five at once.

`oracle/region_diversity.py` encodes the topology contract:

- `NodeLocation(node_id, region)` — `region` is an opaque string
  (`"aws:us-east-1"`, `"gcp:europe-west1"`) so the helper doesn't bake
  in a cloud taxonomy. The audit cares about INDEPENDENCE of failure
  domains, not the specific provider.
- `DEFAULT_CLUSTER_SIZE = 5`, `DEFAULT_CLUSTER_THRESHOLD = 3`,
  `MIN_DISTINCT_REGIONS = 2`.
- `verify_region_diversity(nodes, *, threshold=3, min_distinct_regions=2)`
  enforces TWO floors: (a) `distinct_regions >= 2` so a single-region
  cluster is rejected outright; (b) `largest_region_count <= N - K` so
  losing the most-populated region still leaves at least K honest nodes
  to sign — the K-of-N threshold survives a one-region outage by
  construction.

The N − K math is the load-bearing line: for the canonical 3-of-5
default, no region may host more than 2 nodes. Three nodes in
`us-east-1` is a HCR-2 violation even if the cluster also has two nodes
in `eu-west-1`.

### HCR-3 — shared Kafka / Redis reaching the signing path

SPOF-#5 closed the SHARED-INFRA-DOWN risk by making Kafka itself HA
(3 brokers, RF=3, `min.insync=2`). What HCR-3 closes is the COMPLEMENT:
even with an HA bus, the cluster's signing path MUST NOT transitively
trust the bus's contents. A determined attacker who compromises the
Kafka instance can corrupt every cluster member's input identically;
the "5 independent operators" defense collapses because they're all
reading from the same poisoned topic.

`oracle/state_isolation.py` reifies the layering contract:

- `SIGNING_PATH_MODULES` enumerates every trust-bearing module
  (`oracle.commit_baseline`, `oracle.epoch_runner`, the
  `oracle.cluster.*` threshold-signing modules, the `slashing.*`
  detectors, `scoring.composite`). Adding a module to this tuple is a
  deliberate act — the module is now in the trust path.
- `SHARED_STATE_FORBIDDEN_IMPORTS` enumerates the client libraries
  those modules MUST NOT import — `aiokafka`, `kafka`, `confluent_kafka`,
  `redis`, `aioredis`, `memcache`, `pymemcache`, `nats`, `asyncpg`,
  `psycopg2`, `psycopg`, `sqlalchemy`.
- `verify_signing_path_isolation(source_lookup)` walks the source of
  each signing-path module and raises
  `SharedStateDependencyError` (with per-(module, import) report
  attached) if any forbidden import is found.
- The check is INTENTIONALLY shallow — it greps top-level imports via a
  pre-compiled `^(?:from|import)` regex. A docstring or comment that
  MENTIONS `aiokafka` does NOT trigger; only an actual top-of-line
  import does.

The architectural invariant the gate enforces: ALL shared-bus traffic
crosses ONE bridge — `oracle/cluster/kafka_ingest.py`. Everything
downstream of that bridge operates on structured, in-memory
`AgentEpochInput` objects and never sees a raw client. HCR-3 catches
the accidental regression where a contributor adds `import aiokafka`
to `cluster/signer.py` because "the bus has a thing I need."

The audit gate goes one step further than the static grep: it actually
runs `verify_signing_path_isolation` against the live tree
(`_filesystem_source_lookup(REPO_ROOT)`). A regression on disk fails
the gate even if the constant strings are unchanged — i.e. the gate
catches "imports added to a module the contract already covers," which
is the real-world failure mode.

### HCR-4 — operator key monoculture

The threshold-signing math (3-of-5 on the cluster, M-of-N attestations
on slash-authority) assumes each key is held by an INDEPENDENT
party. If one organisation operates three of the five nodes — even
across three machines in three regions — that organisation can produce
a valid threshold signature unilaterally, and the protocol's "no single
point of trust" guarantee is fiction. This is fundamentally a SOCIAL
fact (who runs which key), but we reify it into an on-disk manifest the
cluster ships with and audit at boot.

`oracle/operator_manifest.py`:

- `OperatorAttestation(node_id, pubkey, operator_org, operator_contact,
  jurisdiction)` — each cluster operator declares their pubkey, their
  organisation, an identity binding (PGP fingerprint or contractually-
  recorded email), and an ISO-3166 alpha-2 jurisdiction code.
- `build_manifest(attestations, *, threshold)` validates the inputs:
  non-empty fields, unique `node_id`, unique `pubkey`, 2-letter alpha
  ISO codes, `threshold <= len(attestations)`. Malformed manifests are
  refused with `OperatorManifestError`.
- `verify_operator_diversity(manifest)` enforces THREE floors:
  1. `largest_org_count < manifest.threshold` — strict less-than, so no
     org can unilaterally produce a valid threshold signature.
  2. `distinct_orgs >= MIN_DISTINCT_OPERATORS = 2`.
  3. `distinct_jurisdictions >= MIN_DISTINCT_JURISDICTIONS = 2` — a
     single legal-process compulsion in one country does not reach
     every operator simultaneously.
- Jurisdiction codes are counted case-insensitively (uppercased) so
  `"us"` and `"US"` aggregate correctly; the construction-time check
  still enforces the 2-letter alpha shape.

What this file does NOT do: it does not verify the TRUTHFULNESS of the
attestations. An operator who signs the manifest claiming "Org A"
while secretly running Org B's node cannot be caught by code alone —
that is the job of the external audit retest. What HCR-4 enforces is
that the manifest itself is internally consistent: the math of "no
single org meets threshold" is verifiable from the declared file, so
the external auditor only needs to verify that the declarations match
reality, not also re-do the threshold arithmetic.

### Interaction with HCR-2

HCR-2 protects against REGION monoculture; HCR-4 protects against
ORG monoculture. The two are orthogonal — an attacker who collapses
either axis collapses the threshold:

- 5 nodes / 1 region / 5 orgs   → regional outage = cluster down
- 5 nodes / 5 regions / 1 org   → insider = unilateral cert
- 5 nodes / 3 regions / 3 orgs  → both gates green

---

## What the audit gate guarantees

`audit/centralization_check.py` runs four probes against the
as-shipped tree. It will fail the build if any of the following goes
wrong:

- A marker file is deleted (`provider_diversity.py`, `region_diversity.py`,
  `state_isolation.py`, `operator_manifest.py`).
- A load-bearing constant is changed without review
  (`MIN_DISTINCT_RPC_PROVIDERS=2`, `MIN_DISTINCT_REGIONS=2`,
  `DEFAULT_CLUSTER_SIZE=5`, `DEFAULT_CLUSTER_THRESHOLD=3`,
  `MIN_DISTINCT_OPERATORS=2`, `MIN_DISTINCT_JURISDICTIONS=2`).
- `KNOWN_PROVIDERS` drops coverage of any major Solana RPC provider
  (helius / quicknode / triton).
- `SIGNING_PATH_MODULES` no longer covers the cluster signer + scoring
  kernel — i.e. the contract has shrunk to where it does not cover the
  trust path.
- `SHARED_STATE_FORBIDDEN_IMPORTS` drops kafka or redis.
- `verify_signing_path_isolation` against the live tree reports a
  violation — i.e. a signing-path module gained an `import aiokafka`
  (or similar) since the contract was committed.
- A class or function the protocol depends on is renamed or deleted
  (`verify_provider_diversity`, `verify_region_diversity`,
  `verify_signing_path_isolation`, `verify_operator_diversity`,
  `OperatorAttestation`).

The gate is intentionally narrow at the contract layer — the DEEPER
validation lives in the per-module test suites under `audit/run_all.sh`
(65 tests across HCR-1..HCR-4). The audit gate is the canary that
catches a regression at the contract layer BEFORE it reaches the test
layer where it might be quietly skipped.
