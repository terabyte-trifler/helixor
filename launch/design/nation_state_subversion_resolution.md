# Nation-State Silent Subversion Resolution — audit Scenario B

**Status:** IMPLEMENTED.
**Audit finding:** Scenario B from the catastrophic-failure inventory
— "Nation-State Silent Subversion" — the 6-step attack chain in which
a state actor compromises a cloud provider hosting oracle nodes,
installs a hypervisor-level kernel module that exfiltrates Ed25519
private keys, accumulates K-of-N cluster keys, issues GREEN certs for
fresh state-controlled wallets, lets those wallets borrow against
maximum DeFi collateralisation over weeks, and triggers coordinated
market action.
**Owners:** oracle engineering (NSS-1, NSS-3), platform / ops
engineering (NSS-2).
**Related code / config:**
- `helixor-oracle/oracle/cloud_diversity.py` (NSS-1)
- `helixor-oracle/oracle/signer_enforcement.py` (NSS-2)
- `helixor-oracle/oracle/agent_age_gate.py` (NSS-3)
- `helixor-oracle/tests/oracle/test_nss1_cloud_diversity.py`
- `helixor-oracle/tests/oracle/test_nss2_signer_enforcement.py`
- `helixor-oracle/tests/oracle/test_nss3_agent_age_gate.py`
- `audit/nation_state_check.py` + `audit/test_nation_state_check.py`
  (mechanical regression gate)

---

## The attack the audit named

Scenario B is the SECOND failure mode that defeats Helixor without
defeating any of the per-key cryptography. Reproduced verbatim from
the audit:

1. A nation-state compromises a cloud provider that hosts a majority
   of Helixor oracle nodes. The compromise is operational — a
   national-security letter, a covert subpoena, or a kernel-level
   intrusion into the hypervisor fabric. The cluster threshold math
   (3-of-5) is still intact in the abstract, but the substrate on
   which the keys live is now hostile.
2. A kernel module on the hypervisor reads Ed25519 private keys out of
   the oracle process's memory the first time `sign()` is invoked.
   `InProcessSigner` was always vulnerable to this — the private key
   sat in plain memory pages reachable by ring-0 code. The exfiltrated
   keys travel out of the network via a covert channel that does not
   touch any Helixor-visible interface.
3. The attacker now holds three (or more) cluster signing keys —
   enough to win the 3-of-5 threshold without involving any honest
   node. From the on-chain consumer's perspective every certificate
   the attacker produces is INDISTINGUISHABLE from an honest
   certificate.
4. The attacker registers fresh wallets controlled by the state and
   issues GREEN-tier certs against them via the captured keys. The
   `certificate_issuer::issue_certificate` handler only checks
   `score >= 700 -> GREEN` — it does NOT gate on WHEN the agent was
   registered, so a wallet created at epoch N can hold a GREEN cert at
   epoch N+1. The SDK's `SafeCertReader` consumer-side gate refuses
   certs with fewer than `MIN_HISTORY_REQUIRED = 2` historical
   snapshots, but two epochs is four hours — well inside the "set up
   and borrow" window for a state actor.
5. The state-controlled agents now hold GREEN certs and accumulate
   large collateralised positions in DeFi protocols that read Helixor
   certs as the only signal. The positions are accumulated over
   weeks, so the on-chain footprint looks like a slow, distributed
   accretion rather than a single mover.
6. At a chosen moment the state coordinates simultaneous market action
   across every state-controlled agent. The positions, having been
   sized by trusting an inflated GREEN signal, unwind at scale and
   distort price across an entire DeFi sector — the state benefits
   regardless of which side of the unwind it sits on.

Each individual on-chain defence is intact end-to-end through this
chain. What is broken is the assumption that "cluster keys are
private" — the keys are private TO the threshold math but not to a
state with hypervisor access. The Silent Subversion chain therefore
needs THREE new mitigations at three different substrates of the
protocol, each fail-closed.

---

## Why a three-mitigation closure

The six steps cluster into three independent substrates:

| Substrate | Steps it spans | Why a single mitigation cannot reach it |
| --- | --- | --- |
| Cluster cloud-compute (boot-time topology) | steps 1, 2, 3 | If every cluster node sits on one cloud provider, ONE state-level legal or technical capture reaches all K-of-N keys. HCR-2 (region diversity) and HCR-4 (operator diversity) DO NOT close this — three AWS regions are three subpoenas to the same court. NSS-1 closes the substrate at the topology level: a cluster MUST be spread across ≥2 distinct cloud providers, and no more than `N - K = 2` nodes may share a provider. |
| Per-node key custody (process memory) | step 2 | Even on a diversified cluster, if any single node uses `InProcessSigner` on mainnet, a kernel-level intrusion on THAT host yields one of K keys. NSS-2 refuses to BOOT a mainnet oracle node whose signer is in-process — the substrate of the kernel-exfil attack is not present at all. An explicit env opt-in (`HELIXOR_INPROCESS_SIGNER_OK=1`) exists for documented HSM-outage scenarios and is logged at ERROR. |
| Cert issuance — agent-side history floor | steps 4, 5 | Suppose NSS-1 and NSS-2 BOTH fail: the cluster is captured. NSS-3 closes the OUTPUT step: the cluster (even if captured) will not stamp GREEN on a wallet whose `AgentRegistration` PDA is younger than `MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14 days` AND `MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168`. A state-controlled fresh wallet either ages publicly (visible to external observers) or never receives a GREEN cert. |

The three mitigations are orthogonal: each closes a substrate the
other two cannot reach. Defeating Silent Subversion requires
defeating all three simultaneously — and NSS-3 specifically remains
load-bearing even when NSS-1 and NSS-2 have failed, because the
external observability of "wallet registered N hours ago is asking
for GREEN" is a fingerprint visible from chain alone.

---

## The NSS inventory

| #   | Substrate                                    | Mitigation                                                                                                              | Pinned thresholds                                                                                                                                            | Gate           |
|-----|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| 1   | Cluster cloud-compute topology               | `verify_cloud_diversity(nodes, *, threshold, min_distinct_clouds)` — refuses to boot a cluster whose nodes concentrate on one cloud provider | `MIN_DISTINCT_CLOUD_PROVIDERS=2`, `DEFAULT_CLUSTER_SIZE=5`, `DEFAULT_CLUSTER_THRESHOLD=3` (max nodes/cloud = N−K = 2), `KNOWN_CLOUD_PROVIDERS` includes aws/gcp/azure/hetzner/self-hosted | NSS gate NSS-1 |
| 2   | Per-node signer custody                      | `enforce_production_signer(signer, *, service)` — refuses to start a mainnet oracle node with an `InProcessSigner`        | `HELIXOR_INPROCESS_SIGNER_OK=1` opt-in (logged at ERROR), classifier buckets `in-process` / `hsm` / `unknown` with `HSMSigner`-suffix subclass rule           | NSS gate NSS-2 |
| 3   | Cert issuance agent-history floor            | `enforce_agent_age_for_tier(context, *, current_unix, current_epoch, tier)` — refuses to stamp GREEN on a fresh wallet    | `MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14*24*3600` (14 days), `MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168` (14 days × 12 epochs/day @ 2h cadence), `GATED_TIER_GREEN = "GREEN"` | NSS gate NSS-3 |

---

## How each fix works

### NSS-1 — cluster cloud-provider diversity gate

The hardening rounds already shipped:

- HCR-2 — **region** diversity (no two cluster nodes in the same
  region of any provider).
- HCR-4 — **operator** diversity (no one operator owns more than a
  minority of the cluster).

What neither closes is **cloud-provider** diversity. Three different
regions of AWS, run by three different operators, look healthy under
HCR-2 + HCR-4 but are ONE court order to AWS away from coordinated
subpoena. NSS-1 is the missing third floor in the topology contract.

`oracle/cloud_diversity.py` reifies the cloud-diversity contract:

- `NodeCloud(node_id, cloud_provider)` and a pure
  `classify_cloud_provider(label)` helper. Labels are normalised
  (lowercase, whitespace-stripped) and the leading prefix before `:`
  is looked up against `KNOWN_CLOUD_PROVIDERS`. Unknown labels keep
  their FULL string under an `unknown:<label>` bucket so two distinct
  unknowns never silently merge. `awss` is NOT `aws` — a typo lands
  in its own bucket and the diversity math still treats it as a
  separate cloud (conservative: a fingerprinted-as-unknown bucket
  cannot be used to evade the per-provider cap by aliasing into a
  known one).
- `KNOWN_CLOUD_PROVIDERS` enumerates the marquee clouds and a long
  tail of credible alternates (`aws`, `gcp`, `azure`, `oci`, `ibm`,
  `alibaba`, `tencent`, `hetzner`, `ovh`, `digitalocean`, `vultr`,
  `linode`, `scaleway`, `fly`, `self-hosted`, `bare-metal`). The NSS
  audit gate cross-checks that the marquee three (`aws`, `gcp`,
  `azure`) are still present — a node mistakenly labelled `aws` while
  the list lost that entry would silently bucket as `unknown:aws` and
  the per-provider cap would not bind.
- `MIN_DISTINCT_CLOUD_PROVIDERS = 2` — at least two distinct clouds.
  A single-cloud cluster is refused regardless of region. This is
  the substrate of audit Scenario B step 1: one nation-state, one
  cloud, K-of-N keys.
- `DEFAULT_CLUSTER_SIZE = 5` and `DEFAULT_CLUSTER_THRESHOLD = 3` —
  the canonical mainnet topology. The per-cloud cap is computed as
  `N - K = 2`. Three nodes on one cloud = one court order reaches the
  threshold; the gate refuses.
- `verify_cloud_diversity(nodes, *, threshold, min_distinct_clouds)`
  returns a `CloudDiversityReport` describing every cloud's tally,
  the largest cloud, and the binding constraint. It raises
  `CloudDiversityError` (with the report attached) on a refusal. The
  diversity check runs at cluster boot, BEFORE any signing key is
  loaded — a non-diverse cluster never reaches the keys.
- Malformed manifests (empty node list, threshold out of range,
  duplicate node IDs, empty cloud labels) raise immediately so an
  operator that supplied a broken manifest sees the failure at boot,
  not after the first cert.

The diversity gate is INTENTIONALLY orthogonal to the operator and
region gates. A cluster can pass HCR-2 + HCR-4 + NSS-1 simultaneously
only if it actually spans at least two clouds AND at least two
regions AND at least two operators — the conjunction is what makes a
state-level capture costly.

### NSS-2 — mainnet HSM-only signing enforcement

VULN-25 already shipped the signer surface
(`oracle/cluster/signer.py`):

- `Signer` — narrow Protocol that every caller depends on.
- `InProcessSigner` — wraps a `NodeKeypair`; private key lives in
  process memory. Permitted for dev.
- `HSMSigner` — typed stub; subclasses route `sign` through an HSM
  (YubiHSM, AWS KMS, Cubist, Fireblocks MPC, etc.). The base class
  raises so a silent fallback to in-process is impossible.

What VULN-25 did NOT close is the OPERATIONAL question: nothing in
the codebase refuses an oracle process that boots with
`InProcessSigner` on mainnet. A misconfigured deploy — an env-var
typo, an old config file, a one-time HSM outage that was never reset
— ships an in-process key into production. NSS-2 closes the
operational hole.

`oracle/signer_enforcement.py` reifies the mainnet-HSM contract:

- `classify_signer(signer)` is structural: it reads
  `type(signer).__name__` against `KNOWN_IN_PROCESS_CLASS_NAMES`,
  then against `KNOWN_HSM_CLASS_NAMES`, then against the literal
  suffix `"HSMSigner"`. The suffix rule means a new subclass like
  `YubiHSMSigner(HSMSigner)` automatically inherits the `hsm` bucket
  without re-registration — the bucketing is conservative by default
  but extensible by naming convention.
- `verify_production_signer(signer, *, network_verdict, opted_in)` is
  the pure verifier — no logging, no env reads. It takes the network
  verdict from `oracle.network_guard.evaluate()` (so tests can pin
  it) and the opt-in flag, returns a `SignerEnforcementReport`
  describing the decision. The rule is one line: production network
  + non-HSM bucket + not opted in → `must_refuse=True`.
- `enforce_production_signer(signer, *, service)` is the impure
  wrapper called from the boot path. It runs `evaluate_network()` +
  `opted_in_to_inprocess_signer()` + the pure verifier, then logs at
  ERROR on a refusal (and raises `InsecureSignerError`), ERROR on the
  opt-in path (the operator MUST see the decision in the journal),
  WARNING on production + HSM (the healthy path), and INFO on
  non-production. The opt-in env var is
  `HELIXOR_INPROCESS_SIGNER_OK=1` — the value MUST be the literal
  `"1"`; any other value is treated as "not opted in." The opt-in
  bypass exists for documented HSM-outage scenarios only and the
  operator is required to record the justification in
  `audit/reports/inprocess_signer_optin.md`.
- `mainnet-beta` is the only production label the network guard
  recognises (matches `network_guard.PRODUCTION_NETWORKS`). `devnet`,
  `localnet`, and `testnet` all permit `InProcessSigner` so dev
  ergonomics are preserved.

The substrate of audit Scenario B step 2 is the existence of an
in-memory private key on a mainnet host. NSS-2 makes that substrate
absent — no key in memory, no kernel module to read.

### NSS-3 — cluster-side agent-registration-age floor for GREEN certs

VULN-23 (`helixor-sdk/src/lib/cert_reader.ts`) shipped the
consumer-side history floor `MIN_HISTORY_REQUIRED = 2` — the DeFi
reader refuses a cert with too few historical samples. Two epochs is
four hours at the canonical 2h cadence — INSIDE the "set up state
agent and borrow" window for a nation-state.

NSS-3 reifies the cluster-side counterpart on a different clock:
WALL-CLOCK registration age, not historical sample count.

`oracle/agent_age_gate.py` reifies the agent-age contract:

- `AgentAgeContext(agent_wallet, registered_at_unix,
  registered_at_epoch)` is the pure input — the registration
  timestamps the cluster reads from the on-chain `AgentRegistration`
  PDA.
- `MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14 * 24 * 3600` (14 days) — the
  headline NSS-3 floor. Calibrated for two properties: long enough
  that a coordinated state-controlled-agent setup is detectable by
  external observers (any agent that registers and immediately
  rankings GREEN is conspicuous); short enough that honest new
  entrants are not locked out of GREEN forever.
- `MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168` (14 days × 12 epochs/day at
  2h cadence) — the dual floor. Both seconds AND epochs must be
  satisfied. The seconds floor catches a cluster that BOOSTED its
  epoch rate (epochs accumulate fast but wall-clock doesn't); the
  epochs floor catches a cluster running SLOWER than canonical (wall-
  clock passes but on-chain history doesn't).
- `verify_agent_age_for_tier(context, *, current_unix, current_epoch,
  tier)` is pure: integer arithmetic on `(current_unix -
  registered_at_unix)` and `(current_epoch - registered_at_epoch)`.
  No clock, no I/O. Returns an `AgentAgeReport` carrying the age
  deltas, the floors, and reason codes.
- Only `GREEN` is gated. The tier string is normalised (lowercase,
  whitespace-stripped, uppercased) so `"  green  "` and `"GREEN"`
  reach the same verdict. `YELLOW` and `RED` are RISK signals, not
  collateral-grade endorsements — a fresh wallet may receive them.
- A future-dated registration (`age_seconds < 0`) appends
  `REASON_TIME_TRAVEL = "AGENT_REGISTERED_IN_FUTURE"` and clamps the
  age fields to zero. This catches clock-rewind / replay scenarios
  and surfaces them as a STRUCTURAL failure distinct from
  "too-young." The structural reason is set for ANY requested tier,
  so a time-travel registration is refused even for YELLOW.
- `enforce_agent_age_for_tier(...)` raises
  `InsufficientAgentAgeError` with the report attached. The
  cluster's pre-issue hook in `oracle/cluster/cert_signing.py` calls
  the `enforce_*` variant. The policy choice (downgrade-vs-defer) on
  a refusal lives at the call site — NSS-3 only answers the binary
  question: is this agent old enough for this tier?

### Interaction between the three mitigations

- **NSS-1 ↔ NSS-2**: NSS-1 makes the cluster expensive to capture by
  spreading the keys across providers. NSS-2 makes each KEY expensive
  to read once a provider IS captured (no in-memory keys to exfiltrate
  on mainnet). The two stack: an attacker needs to capture BOTH ≥2
  clouds AND escape the HSM boundary on each.
- **NSS-2 ↔ NSS-3**: NSS-2's failure mode is "the attacker holds
  K-of-N keys." NSS-3 is the LAST DEFENCE that survives that failure:
  even with all five cluster keys captured, the gate refuses to stamp
  GREEN on a fresh wallet. The attacker either ages the wallets
  publicly (visible) or never gets a GREEN cert.
- **NSS-3 ↔ VULN-23**: VULN-23's `MIN_HISTORY_REQUIRED = 2` is the
  CONSUMER-side gate; NSS-3 is the CLUSTER-side gate on a different
  clock. Defence-in-depth wants both sides to enforce the contract
  — a cluster captured by a state actor that ignored NSS-3 would
  still produce certs the consumer-side gate refuses. The NSS audit
  gate lights a SOFT finding if VULN-23's consumer-side gate
  disappears, recognising that NSS-3 alone is still load-bearing.
- **NSS-3 ↔ TA-6**: TA-6's 48-hour freshness contract is about CERT
  age. NSS-3 is about AGENT REGISTRATION age. The two clocks are
  independent — a cert can be fresh (TA-6 green) and the agent can
  still be too young (NSS-3 red).

---

## What the audit gate guarantees

`audit/nation_state_check.py` runs three probes (NSS-1..NSS-3)
against the as-shipped tree. The gate fails the build if any of the
following goes wrong:

- A marker file is deleted (`cloud_diversity.py`,
  `signer_enforcement.py`, `agent_age_gate.py`).
- A load-bearing function disappears (`classify_cloud_provider` /
  `verify_cloud_diversity`, `classify_signer` /
  `verify_production_signer` / `enforce_production_signer`,
  `verify_agent_age_for_tier` / `enforce_agent_age_for_tier`).
- A pinned threshold is silently changed
  (`MIN_DISTINCT_CLOUD_PROVIDERS=2`, `DEFAULT_CLUSTER_SIZE=5`,
  `DEFAULT_CLUSTER_THRESHOLD=3`, `ENV_INPROCESS_SIGNER_OK` env-var
  name, the three `SIGNER_BUCKET_*` literals, the `HSMSigner`-suffix
  rule, `MIN_AGENT_AGE_SECONDS_FOR_GREEN = 14*24*3600`,
  `MIN_AGENT_AGE_EPOCHS_FOR_GREEN = 168`, `GATED_TIER_GREEN`,
  `REASON_TIME_TRAVEL`).
- The marquee cloud-provider list lost `aws` / `gcp` / `azure`.
- The VULN-25 signer surface (`InProcessSigner` + `HSMSigner`)
  disappeared — without it the NSS-2 classifier has nothing to
  discriminate.
- The consumer-side VULN-23 `MIN_HISTORY_REQUIRED` marker disappeared
  (soft finding — NSS-3 alone is still load-bearing, but defence-in-
  depth is reduced).

The gate is intentionally narrow at the CONTRACT layer — the deeper
validation lives in the per-module property tests
(`tests/oracle/test_nss[1-3]_*.py`, 52 tests total). The audit gate
is the canary that catches a contract-layer regression BEFORE it
reaches the test layer where it might be quietly skipped or rewritten.
The `audit/test_nation_state_check.py` self-test pins the gate to
0 hard / 0 soft findings on the as-shipped tree.
