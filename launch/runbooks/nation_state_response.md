# Runbook — Nation-State Silent Subversion mitigation response

**Severity:** Critical (any NSS gate red means a mitigation against
the audit's catastrophic Scenario B — Nation-State Silent Subversion
— has either been removed from the tree or fired at boot / runtime).
**Triggers:**
- `audit/nation_state_check.py` gate fails in CI.
- Cluster bootstrap raises `CloudDiversityError` (NSS-1) refusing to
  start the cluster.
- Oracle node bootstrap raises `InsecureSignerError` (NSS-2) refusing
  to start the process.
- Cluster pre-issue raises `InsufficientAgentAgeError` (NSS-3)
  refusing to stamp a GREEN cert.

## What's happening

Nation-State Silent Subversion (audit Scenario B) is the 6-step
catastrophic-failure mode in which a state actor compromises a cloud
provider hosting oracle nodes, exfiltrates Ed25519 private keys via a
hypervisor kernel module, accumulates K-of-N cluster keys, issues
GREEN certs for state-controlled fresh wallets, lets the wallets
accumulate DeFi positions for weeks, and triggers coordinated market
action. The three mitigations in
`launch/design/nation_state_subversion_resolution.md` are the load-
bearing reifications of the audit's claims that each substrate of the
subversion chain has a fail-closed defence. This runbook is the
playbook for reacting when one of them fires or regresses.

The two failure shapes need different responses:

- **CI gate red** — a refactor has REMOVED a mitigation. The code is
  not yet on mainnet. Block the merge and restore the anchor. DO NOT
  weaken the gate to make CI green.
- **Boot / runtime fire** — the mitigation engaged and refused to
  start a node, boot the cluster, or sign a cert. Mainnet is
  protected; investigate the underlying topology / config /
  registration event before bringing the affected process back online.

---

## CI gate red — `audit/nation_state_check.py` failed

### Triage (60s)

```bash
# 1. Run the gate locally to see which NSS family regressed.
python3 audit/nation_state_check.py --json /tmp/nss.json
cat /tmp/nss.json | python3 -m json.tool | head -80

# 2. Each finding names the rule and the marker string the gate could
#    not find. The NSS-N tag tells you which family regressed.
```

### Decision tree

- **Marker file deleted** (`cloud_diversity.py`,
  `signer_enforcement.py`, `agent_age_gate.py`): the closing PR
  removed a mitigation the audit assumes is present. RESTORE the file
  from `main`. The reviewer who approved the removal must justify
  the change in writing on the PR.
- **`verify_*` / `enforce_*` function disappeared**: a contract entry
  point is gone. Restore it. If the function was genuinely renamed in
  good faith, the audit gate's expected marker MUST be updated IN THE
  SAME PR and the PR description must call out the Silent-Subversion
  closure impact.
- **NSS-1 threshold changed** (`MIN_DISTINCT_CLOUD_PROVIDERS`,
  `DEFAULT_CLUSTER_SIZE`, `DEFAULT_CLUSTER_THRESHOLD`): a load-bearing
  topology floor moved. Restore the pinned value. If the change is
  intentional (e.g. moving the canonical cluster to a 4-of-7
  topology), the audit gate's expected constants AND the per-cloud
  cap derivation (`max_per_cloud = N - K`) MUST be updated IN THE
  SAME PR; the PR description must explain why the new topology
  preserves single-court-order resistance.
- **NSS-1 marquee-cloud list regression**: the gate flags if `aws` /
  `gcp` / `azure` disappear from `KNOWN_CLOUD_PROVIDERS`. A node
  labelled with a missing marquee silently buckets as
  `unknown:<label>` and the per-provider cap may not bind correctly.
  Restore the entry.
- **NSS-2 env-var or bucket constant changed**
  (`PHYLANX_INPROCESS_SIGNER_OK`, `SIGNER_BUCKET_IN_PROCESS = "in-process"`,
  `SIGNER_BUCKET_HSM = "hsm"`, `SIGNER_BUCKET_UNKNOWN = "unknown"`):
  the boot-log and audit-report consumers grep these literals.
  Restore them. Never rename the env var — operators' opt-in scripts
  reference the name.
- **NSS-2 HSMSigner-suffix rule removed**: a new `YubiHSMSigner`
  subclass would silently fall through to the `unknown` bucket and
  be REFUSED on mainnet (the cluster would not boot at all). Restore
  the `endswith("HSMSigner")` rule. If a new HSM family genuinely
  cannot use the suffix convention, add the class name to
  `KNOWN_HSM_CLASS_NAMES` in the SAME PR.
- **NSS-2 VULN-25 signer-surface regression**: the gate checks that
  `oracle/cluster/signer.py` still defines both `InProcessSigner`
  AND `HSMSigner`. Without those, NSS-2 has nothing to discriminate.
  Restore the surface.
- **NSS-3 floor changed** (`MIN_AGENT_AGE_SECONDS_FOR_GREEN`,
  `MIN_AGENT_AGE_EPOCHS_FOR_GREEN`, `GATED_TIER_GREEN`,
  `REASON_TIME_TRAVEL`): a load-bearing audit floor moved. Restore
  the pinned value. If the 14-day floor is genuinely being retuned
  (e.g. measured cohort data suggests honest new entrants need to be
  unblocked sooner), the change MUST be discussed with the audit
  team BEFORE merging — the floor is calibrated for state-actor
  setup-and-borrow detectability, not honest-user ergonomics.
- **VULN-23 consumer-side `MIN_HISTORY_REQUIRED` disappeared** (soft
  finding): the consumer-side gate that complements NSS-3 has
  shifted. Investigate `phylanx-sdk/src/lib/cert_reader.ts`. NSS-3
  remains load-bearing alone, but defence-in-depth is reduced.

### After every fix

```bash
python3 audit/nation_state_check.py --json /tmp/nss.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_nation_state_check.py -v
```

Both MUST be green before the PR is mergeable.

---

## Boot fire — NSS-1 `CloudDiversityError` on cluster bootstrap

### Triage (60s)

```bash
journalctl -u phylanx-cluster-bootstrap --since "10 min ago" \
  | grep -A 20 "NSS-1"
# The exception's .report carries:
#   - cloud_counts: {"aws": 3, "gcp": 1, "hetzner": 1}
#   - threshold (K), max_nodes_per_cloud (N-K)
#   - largest_cloud, largest_cloud_count
#   - distinct_clouds
```

### Action

The cluster REFUSED to boot because the per-cloud cap or the
distinct-providers floor was violated. The cluster is protected — no
key is loaded into a non-diverse topology. The job is to fix the
operator manifest, not to lower the floor:

1. Inspect `report.cloud_counts`. If one provider holds more than
   `N - K` nodes, the cluster has the single-court-order capture
   substrate. Move at least one node off the over-represented
   provider. The replacement should land on a provider not yet
   represented; `KNOWN_CLOUD_PROVIDERS` enumerates the credible
   alternates.
2. If the issue is `distinct_clouds < MIN_DISTINCT_CLOUD_PROVIDERS`
   (the cluster is on ONE cloud regardless of regions), the topology
   was misdesigned. Three AWS regions do not satisfy NSS-1 — one
   subpoena reaches all three. Plan a second-cloud node BEFORE
   re-attempting the boot.
3. If a node was labelled with an unfamiliar cloud string that
   buckets as `unknown:<label>`, confirm the cloud actually IS new.
   If so, propose adding it to `KNOWN_CLOUD_PROVIDERS` in a separate
   PR — the canonical bucket prevents two operators independently
   labelling the same cloud with different strings and silently
   bypassing the diversity math.

DO NOT lower `MIN_DISTINCT_CLOUD_PROVIDERS` or raise the per-cloud
cap to push the cluster through bootstrap. The floor exists to
defeat single-court-order capture; weakening it re-opens audit
Scenario B step 1.

---

## Boot fire — NSS-2 `InsecureSignerError` on oracle node startup

### Triage (60s)

```bash
journalctl -u oracle-node@0 --since "10 min ago" | grep -A 10 "NSS-2"
# The exception's .report carries:
#   - signer_class_name (e.g. "InProcessSigner")
#   - signer_bucket ("in-process" / "unknown")
#   - network ("mainnet-beta" / "devnet" / ...)
#   - is_production, opted_in, must_refuse
```

### Action

The node REFUSED to start because `verify_production_signer` decided
the signer bucket is not safe for the detected network. The substrate
of audit Scenario B step 2 — an in-memory private key — is being
prevented from existing on a mainnet host. Fix the deploy, not the
gate:

1. **`signer_bucket == "in-process"` on `mainnet-beta`**: the deploy
   shipped an in-process keypair to mainnet. ROTATE the key, then
   re-deploy with an HSM-backed signer (`YubiHSMSigner`,
   `AWSKMSSigner`, `CubistSigner`, `FireblocksMPCSigner`, etc.). Do
   NOT just rotate without changing the signer surface — the
   previous key may have been exfiltrated already; treat it as burned.
2. **`signer_bucket == "unknown"` on `mainnet-beta`**: an unaudited
   signer subclass shipped. Inspect the class. If it is a legitimate
   HSM wrapper, rename it to end with `HSMSigner` (so the suffix rule
   buckets it correctly) OR add an explicit entry in
   `KNOWN_HSM_CLASS_NAMES` and merge with an audit-team sign-off.
   Re-deploy.
3. **HSM outage that requires a temporary in-process signer**: this
   is the documented opt-in path. Set
   `PHYLANX_INPROCESS_SIGNER_OK=1` in the affected node's
   environment AND record the justification in
   `audit/reports/inprocess_signer_optin.md` with the start / end
   timestamps. The boot path will log at ERROR, the operator sees it
   in the journal, and the audit trail is preserved. UNSET the env
   var as soon as the HSM is back; do not leave it set across deploys.
4. **`network == "devnet"` / `localnet`**: NSS-2 should NOT refuse on
   dev networks. If it did, something is wrong with the network
   detection. Check `PHYLANX_NETWORK` is set correctly and that
   `network_guard.evaluate()` returns the expected verdict. The
   bucket constants and env var should not be touched.

DO NOT set `PHYLANX_INPROCESS_SIGNER_OK=1` as a permanent workaround.
The opt-in path is logged at ERROR for a reason — it is a temporary,
auditable escape hatch, not a deploy-config setting.

---

## Runtime fire — NSS-3 `InsufficientAgentAgeError` on cluster pre-issue

### Triage (60s)

```bash
# The cluster pre-issue hook in oracle/cluster/cert_signing.py logs:
journalctl -u oracle-node@0 --since "10 min ago" | grep -A 10 "NSS-3"
# The exception's .report carries:
#   - agent_wallet
#   - tier_requested (e.g. "GREEN")
#   - agent_age_seconds, agent_age_epochs
#   - min_seconds_required, min_epochs_required
#   - reasons: ['AGENT_SECONDS_TOO_YOUNG', 'AGENT_EPOCHS_TOO_YOUNG',
#               'AGENT_REGISTERED_IN_FUTURE']
```

### Action

The cluster REFUSED to stamp GREEN on an agent whose registration is
younger than the 14-day / 168-epoch floor. The cluster is protected
— no fresh wallet receives a collateral-grade cert. The next move
depends on whether the agent is honest or adversarial:

1. **Honest new entrant**: the agent registered legitimately less
   than 14 days ago, the scoring engine genuinely awarded it a
   GREEN-tier composite. The cluster's policy at the call site
   (`oracle/cluster/cert_signing.py`) is to DOWNGRADE the cert to
   YELLOW and re-sign, OR to DEFER issuance until next epoch when
   the wallet has aged further. YELLOW does NOT mean the agent is
   risky; it means it does not yet carry the collateral-grade
   endorsement. The on-chain handler will continue accepting score
   ≥ 700 with tier == YELLOW (NSS-3 only gates the GREEN→COLLATERAL
   stamp). Communicate the timeline to the operator: 14 days, full
   stop. Do not exempt specific wallets.
2. **`REASON_TIME_TRAVEL` set**: the agent's
   `AgentRegistration.registered_at` timestamp is AFTER the current
   wall-clock. This is structurally suspect — either the cluster's
   clock drifted backward (check NTP + the upstream slot anchors),
   the on-chain registration was crafted with a future timestamp
   (replay / fabricated registration), or there is a serialisation
   bug. DO NOT issue a cert — investigate the registration PDA
   directly. The age fields are clamped to 0 in the report so
   downstream telemetry stays sane.
3. **Suspected state-controlled fresh wallet**: if multiple GREEN
   refusals fire across a short window for wallets that registered
   within the same epoch, this is the audit's Scenario B step 4
   fingerprint. Capture the wallet pubkeys to the incident log,
   cross-check against the cloud-diversity report (NSS-1) and the
   signer-enforcement journal (NSS-2) — a state actor's
   register-and-borrow operation is supposed to be visible from
   chain alone, and NSS-3's refusal is the alarm. Escalate to the
   audit lead; the SDK-side VULN-23 gate (consumer-side
   `MIN_HISTORY_REQUIRED`) should also be firing for the same
   wallets.

DO NOT lower `MIN_AGENT_AGE_SECONDS_FOR_GREEN` or
`MIN_AGENT_AGE_EPOCHS_FOR_GREEN` to unblock a specific honest entrant.
The floors are calibrated for state-actor detectability — lowering
them re-opens the substrate. The correct unblock is to defer
GREEN issuance until the wallet ages, not to reduce the floor for
everyone.

---

## Verifying the response

After every fix, re-run the gate and tests locally:

```bash
python3 audit/nation_state_check.py --json /tmp/nss.json && echo PASS
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest audit/test_nation_state_check.py -v
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -m pytest \
    phylanx-oracle/tests/oracle/test_nss1_cloud_diversity.py \
    phylanx-oracle/tests/oracle/test_nss2_signer_enforcement.py \
    phylanx-oracle/tests/oracle/test_nss3_agent_age_gate.py -v
```

All three MUST be green before the PR is mergeable. For a boot /
runtime fire, the additional bar is that the operator has documented
the root cause (manifest mistake, deploy misconfiguration, suspected
adversarial wallet) in the incident channel — the gate is the alarm,
not the diagnosis.
