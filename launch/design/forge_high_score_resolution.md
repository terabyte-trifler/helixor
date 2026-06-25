# Forge High-Score Cert Resolution — red-team Path 1

**Status:** IMPLEMENTED.
**Red-team finding:** Path 1 from the red-team attack tree (root:
"Drain DeFi Protocol Integrated with Phylanx") — "Forge High-Score
Cert" — three sub-leaves:

  1a. Compromise 3 oracle keys                          [HIGH EFFORT]
  1b. Exploit VULN-01 (signature verification bypass)   [MEDIUM EFFORT]
  1c. Exploit VULN-13 (replace all oracle keys)         [HIGH EFFORT]

**Owners:** oracle engineering (FHS-1, FHS-2, FHS-3); on-chain
anchors continue to be owned by the certificate-issuer (VULN-01) and
health-oracle (VULN-13) program teams.
**Related code / config:**
- `phylanx-oracle/oracle/key_rotation_cadence.py` (FHS-1)
- `phylanx-oracle/oracle/signer_provenance.py` (FHS-2)
- `phylanx-oracle/oracle/rotation_overlap_guard.py` (FHS-3)
- `phylanx-oracle/tests/oracle/test_fhs1_key_rotation_cadence.py`
- `phylanx-oracle/tests/oracle/test_fhs2_signer_provenance.py`
- `phylanx-oracle/tests/oracle/test_fhs3_rotation_overlap_guard.py`
- `audit/forge_high_score_check.py` +
  `audit/test_forge_high_score_check.py` (mechanical regression gate)
- On-chain anchors (UNCHANGED, cross-referenced by FHS-3 / VULN-01):
  - `phylanx-programs/programs/health-oracle/src/state/pending_oracle_rotation.rs`
    (`MIN_TIMELOCK_SECONDS = 48 * 60 * 60`)
  - `phylanx-programs/programs/certificate-issuer/src/signing.rs`
    (`verify_threshold_signatures` + `expected_digest` filtering)

---

## The attack the red team named

The attack tree's Path 1 is the FIRST of three drain paths and the
one whose substrate is the cluster's signing authority. Reproduced
verbatim from the tree:

```
ROOT: Drain DeFi Protocol Integrated with Phylanx
├── Path 1: Forge High-Score Cert
│   ├── 1a. Compromise 3 oracle keys                       [HIGH EFFORT]
│   ├── 1b. Exploit VULN-01 (sig verification bypass)      [MEDIUM EFFORT]
│   └── 1c. Exploit VULN-13 (replace all oracle keys)      [HIGH EFFORT]
```

Pre-FHS the cluster's signing authority was protected by the
K-of-N threshold itself (1a), the on-chain `verify_threshold_
signatures` + `expected_digest` filter (1b), and the 48-hour propose
/ attest / enact ceremony in `pending_oracle_rotation.rs` (1c).
Each of those defences is necessary but none of them sees the TIME
dimension of the attack:

- **1a residual.** A compromised key with permanent validity. An
  attacker who steals one key today can dwell silently for months
  waiting for two more compromises to align. K-of-N is a
  spot-in-time guarantee; it has no expiry on the individual key.
- **1b residual.** A threshold set whose K signatures all originate
  from the same physical machine. On-chain
  `verify_threshold_signatures` deduplicates by pubkey, so two
  signatures from the same physical host but two distinct cluster
  pubkeys both count toward the threshold — VULN-01's bypass
  signature is gone, but the equivalent compromise via a single
  host running two HSMs survives.
- **1c residual.** A rotation proposal that replaces ALL FIVE keys
  in one ceremony. An attacker with K=3 compromised keys can sign
  the propose tx, satisfying the on-chain N-of-M attestation gate.
  After the 48h timelock burns the cluster is wholesale
  attacker-controlled.

Path 1 therefore needs THREE new mitigations at three different
substrates of the cluster signing authority, each fail-closed and
each composable with the on-chain anchors that already ship.

---

## Why a three-mitigation closure

The three sub-leaves cluster into three independent substrates:

| Substrate | Sub-leaf it spans | Why a single mitigation cannot reach it |
| --- | --- | --- |
| Key dwell-time (calendar clock) | 1a | A K-of-N threshold is a spot-in-time guarantee — once an attacker has K compromises, the cluster is theirs forever unless the keys themselves age out. FHS-1 forces every cluster key to rotate inside MAX_KEY_AGE_SECONDS (90 days) regardless of whether it has signed anything; the WARN window (60 days) lights operator dashboards 30 days BEFORE the floor so a missed ceremony does not produce an outage. |
| Per-signer physical provenance (per-host clock) | 1b | The on-chain `verify_threshold_signatures` deduplicates by pubkey, so a single physical machine hosting two cluster HSMs produces two signatures under two distinct pubkeys and both count. FHS-2 refuses a threshold set whose K signatures share a host_id, exceed the per-region cap (2, mirroring NSS-1's N-K=2), or are missing the per-signer attestation — caught at the certificate-issuance layer BEFORE the threshold check runs. |
| Rotation diff shape (per-ceremony clock) | 1c | The on-chain 48h timelock bounds the WALL CLOCK of a rotation but says nothing about the SHAPE of the proposed key set. An attacker with K=3 compromised keys can propose a 5-key wholesale swap and satisfy the on-chain N-of-M gate. FHS-3 refuses any proposal whose `removed_size > MAX_KEYS_REPLACED_PER_ROTATION` (1) — at most ONE cluster key may change per ceremony. Combined with the 48h timelock, replacing all 5 keys takes a minimum of 5 × 48h = 10 days of public on-chain activity, every ceremony of which the honest operators of the remaining keys would refuse to attest. |

The three mitigations are orthogonal: each closes a substrate the
other two cannot reach. Defeating Path 1 requires defeating all
three AND surviving the on-chain VULN-01 and VULN-13 anchors AND
NSS-1 / NSS-2 (which constrain the cluster's NODE topology rather
than the per-signature substrate).

---

## The FHS inventory

| #   | Substrate                          | Mitigation                                                                                                                | Pinned thresholds                                                                                                                                                  | Gate           |
|-----|------------------------------------|---------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| 1   | Key dwell-time                     | `verify_key_rotation_cadence(cluster_keys, *, current_unix)` — emits per-key verdict (OK / WARN / OVERDUE) on calendar age | `MAX_KEY_AGE_SECONDS = 90*24*3600`, `WARN_KEY_AGE_SECONDS = 60*24*3600`, `CADENCE_FUTURE_TOLERANCE_SECONDS = 60`                                                    | FHS gate FHS-1 |
| 2   | Per-signer physical provenance     | `verify_signer_provenance(attestations)` — refuses K signatures sharing a host_id or over the per-region cap              | `MAX_SIGNERS_PER_HOST = 1`, `MAX_SIGNERS_PER_REGION = 2`, `MIN_DISTINCT_HOSTS = 3`                                                                                  | FHS gate FHS-2 |
| 3   | Rotation diff shape                | `verify_rotation_overlap(proposal)` — refuses a proposal whose `removed_size` exceeds the per-ceremony cap                | `MAX_KEYS_REPLACED_PER_ROTATION = 1`, `required_overlap = max(threshold - 1, 0)`                                                                                    | FHS gate FHS-3 |

---

## How each fix works

### FHS-1 — cluster-key rotation cadence floor

The K-of-N threshold is a spot-in-time guarantee. Without a hard
calendar floor, a compromised key dwells indefinitely. FHS-1
reifies the rotation cadence:

`oracle/key_rotation_cadence.py`:

- `ClusterKeySnapshot(pubkey, birth_unix)` is the pure input —
  every active cluster key's birth timestamp as recorded by the
  cluster bootstrap ceremony.
- `MAX_KEY_AGE_SECONDS = 90 * 24 * 3600` (90 days) — the hard
  rotation floor. Any key strictly older than this is OVERDUE and
  refused. The 90-day figure matches the NIST SP 800-57 Part 1
  cryptoperiod ceiling for high-impact signing keys.
- `WARN_KEY_AGE_SECONDS = 60 * 24 * 3600` (60 days) — the soft
  warning floor. A key in `[60d, 90d]` is WARN: the cluster is
  still accepted but operator dashboards light yellow 30 days
  before the hard floor so a missed ceremony cannot produce an
  outage.
- `CADENCE_FUTURE_TOLERANCE_SECONDS = 60` — a single epoch of
  clock skew. A key born ≤60s in the future is treated as
  zero-age (clock skew is real and benign). A key born >60s in
  the future is OVERDUE with `REASON_KEY_BIRTH_IN_FUTURE` — the
  birth field has been tampered with.
- `verify_key_rotation_cadence(cluster_keys, *, current_unix)` is
  pure; no logging, no I/O, no clock. Returns a
  `KeyRotationReport` carrying per-key verdicts, the warn floor,
  the max floor, and aggregate `overdue_keys` / `warning_keys`
  tuples.
- `enforce_key_rotation_cadence(...)` raises
  `KeyRotationOverdueError` on any OVERDUE key with the report
  attached. WARN does NOT refuse — the warning window exists
  precisely so operators have time to schedule the ceremony.

The boundary semantics are pinned by test: exactly
`MAX_KEY_AGE_SECONDS` old is WARN (still allowed), one second past
is OVERDUE. Exactly `WARN_KEY_AGE_SECONDS` old is OK, one second
past is WARN.

### FHS-2 — per-signer provenance attestation gate

FHS-1 closes calendar dwell-time. What it does NOT close is the
PER-MACHINE case: even with fresh keys, K of the K signatures on
a forged cert can originate from a SINGLE physical machine that
the attacker has compromised. The on-chain
`verify_threshold_signatures` deduplicates by pubkey, so two
signatures from the same machine under two distinct cluster
pubkeys both count toward the threshold — VULN-01's bypass is
gone but the equivalent physical-host compromise survives.

`oracle/signer_provenance.py`:

- `SignerAttestation(signer_pubkey, host_id, cloud_region)` is the
  pure input — one cluster signer's attested origin. `host_id` is
  the cluster-bootstrap-issued unique host fingerprint (machine
  serial number + boot-time TPM measurement), `cloud_region` is
  the deployment region in NSS-1's `provider:zone` format.
- `MAX_SIGNERS_PER_HOST = 1` — the pin. Two cluster signers
  CANNOT share a host_id. The on-chain pubkey deduplication is
  necessary but not sufficient: the per-host floor is what
  refuses two HSMs on the same physical machine.
- `MAX_SIGNERS_PER_REGION = 2` — mirror of NSS-1's per-cloud cap.
  For a 3-of-5 cluster (N=5, K=3) the maximum tolerable per-cloud
  load is `N - K = 2`. NSS-1 enforces this at cluster-boot time;
  FHS-2 enforces it at certificate-issuance time so a per-cloud
  blackbox provider compromise cannot mint a forged cert even
  during the brief window between bootcheck and the next
  cluster-topology audit.
- `MIN_DISTINCT_HOSTS = 3` — matches K. The threshold set
  attached to a cert MUST come from at least K distinct hosts.
  Any signer with a missing or empty host_id / cloud_region is
  refused with `REASON_MISSING_ATTESTATION`.
- `verify_signer_provenance(attestations)` is pure: builds host
  / region multisets, compares against the caps. Returns a
  `SignerProvenanceReport` carrying the distinct-hosts count,
  the per-host and per-region overload sets, the missing-
  attestation set, and reason codes.
- `enforce_signer_provenance(...)` raises
  `SignerProvenanceError` on refusal.

### FHS-3 — cluster-key rotation overlap guard

FHS-1 closes calendar dwell-time; FHS-2 closes per-signature
provenance. What neither closes is the ROTATION-DIFF case: an
attacker who has compromised K=3 of the 5 cluster keys can
propose a 5-key wholesale swap. They have enough signatures to
satisfy the on-chain N-of-M attestation gate; the 48h timelock
runs out; the cluster is wholesale attacker-controlled.

`oracle/rotation_overlap_guard.py`:

- `RotationProposal(current_keys, proposed_keys, threshold)` is
  the pure input — the cluster's current key set, the proposed
  new key set, and the cluster's K (so the verifier can derive
  the overlap floor from the threshold rather than pinning it
  absolutely).
- `MAX_KEYS_REPLACED_PER_ROTATION = 1` — the pinned contract: AT
  MOST ONE cluster key may be replaced per rotation ceremony,
  regardless of cluster size or threshold. The principle is
  "the cluster's identity is a slow-moving thing" — wholesale
  replacement is itself a red flag.
- `required_overlap = max(threshold - 1, 0)` — derived. For a
  3-of-5 cluster `required_overlap = 2`; for a 5-of-9 cluster
  `required_overlap = 4`. The intersection of `current_keys`
  and `proposed_keys` must be at least this large. This is the
  belt-and-braces with `MAX_KEYS_REPLACED_PER_ROTATION` for
  unusual cluster geometries (a cluster that grew by adding
  keys without removing any can still pass the overlap check
  even when `removed_size = 0`).
- Pathological proposals are refused upfront: empty
  `proposed_keys` (`REASON_NEW_KEYS_EMPTY`), duplicates inside
  `proposed_keys` (`REASON_NEW_KEYS_DUPLICATE`),
  `threshold <= 0` (`REASON_THRESHOLD_INVALID`).
- `verify_rotation_overlap(proposal)` is pure: set intersection
  / difference arithmetic. Returns a `RotationOverlapReport`
  carrying the sizes, the sorted removed / added tuples, the
  derived `required_overlap`, and reason codes.
- `enforce_rotation_overlap(...)` raises `RotationOverlapError`
  on refusal — the off-chain coordinator MUST NOT broadcast the
  propose-rotation tx, sparing the cluster the 48h timelock on a
  proposal that honest attesters would reject anyway.

### Interaction between the three mitigations and the on-chain anchors

- **FHS-1 ↔ FHS-3.** FHS-1 forces every cluster key to age out
  inside 90 days. Without FHS-3, the natural compliance path
  would be "rotate all five keys every 89 days in one ceremony"
  — which IS the wholesale-replacement attack. FHS-3 forces the
  rotation to be incremental: AT MOST ONE key per ceremony.
  Together they require 5 × 48h = 10 days of public on-chain
  activity to rotate the whole cluster, every step of which is
  attestable by the still-honest remaining keys.
- **FHS-2 ↔ NSS-1.** NSS-1 constrains the NODE topology of the
  cluster at boot time (no more than N-K=2 nodes in any one
  cloud). FHS-2 mirrors the same cap at the PER-SIGNATURE
  certificate-issuance time so a per-cloud blackbox provider
  compromise cannot mint a forged cert in the gap between
  cluster-boot audit and the next topology refresh.
- **FHS-1b ↔ VULN-01.** FHS-1b is the audit-gate label for the
  on-chain `verify_threshold_signatures` + `expected_digest`
  anchor in `certificate-issuer/src/signing.rs`. FHS-2 stands
  on top of this anchor — if a refactor removes the canonical
  threshold verifier, the FHS gate lights regardless of FHS-2's
  local state.
- **FHS-3 ↔ VULN-13.** FHS-3 is the OFF-CHAIN pre-flight; the
  ON-CHAIN anchor is `MIN_TIMELOCK_SECONDS = 48 * 60 * 60` in
  `pending_oracle_rotation.rs`. FHS-3 saves the cluster the 48h
  timelock burn on a proposal that the honest attesters would
  reject anyway. If a refactor lowers `MIN_TIMELOCK_SECONDS`
  the FHS gate lights regardless of FHS-3's local state.
- **FHS-1 ↔ TA-6 / SOL.** TA-6 (`MAX_AGE_SECONDS = 48 * 60 * 60`)
  is the certificate freshness ceiling; SOL is the staleness
  defence. FHS-1 is the KEY freshness ceiling — the two clocks
  do not interact directly, but a cluster that is operating
  under WARN keys is exactly the time to slow down high-stakes
  consumer activity. The runbook calls this out explicitly.

---

## What the audit gate guarantees

`audit/forge_high_score_check.py` runs four probes (FHS-1..FHS-3
plus the VULN-01 on-chain anchor; FHS-3 includes the VULN-13
cross-check internally) against the as-shipped tree. The gate
fails the build if any of the following goes wrong:

- A marker file is deleted (`key_rotation_cadence.py`,
  `signer_provenance.py`, `rotation_overlap_guard.py`).
- A load-bearing function disappears (`verify_key_rotation_cadence`
  / `enforce_key_rotation_cadence`, `verify_signer_provenance` /
  `enforce_signer_provenance`, `verify_rotation_overlap` /
  `enforce_rotation_overlap`).
- A pinned threshold is silently changed
  (`MAX_KEY_AGE_SECONDS = 90 * 24 * 3600`,
  `WARN_KEY_AGE_SECONDS = 60 * 24 * 3600`,
  `MAX_SIGNERS_PER_HOST = 1`,
  `MAX_SIGNERS_PER_REGION = 2`,
  `MIN_DISTINCT_HOSTS = 3`,
  `MAX_KEYS_REPLACED_PER_ROTATION = 1`).
- The status-label constants (`CADENCE_OK` / `CADENCE_WARN` /
  `CADENCE_OVERDUE`, `PROVENANCE_OK` / `PROVENANCE_REFUSED`,
  `OVERLAP_OK` / `OVERLAP_REFUSED`) or the reason codes
  (`REASON_WHOLESALE_REPLACEMENT`, `REASON_INSUFFICIENT_OVERLAP`)
  are renamed.
- The on-chain VULN-01 anchor drifts —
  `pub fn verify_threshold_signatures` disappears or
  `expected_digest` filtering is removed from
  `certificate-issuer/src/signing.rs`.
- The on-chain VULN-13 anchor drifts —
  `MIN_TIMELOCK_SECONDS = 48 * 60 * 60` disappears from
  `pending_oracle_rotation.rs` or the rotation module itself is
  removed.

The gate is intentionally narrow at the CONTRACT layer — the
deeper validation lives in the per-module property tests
(`tests/oracle/test_fhs[1-3]_*.py`, 43 tests total). The audit
gate is the canary that catches a contract-layer regression
BEFORE it reaches the test layer where it might be quietly
skipped or rewritten. The `audit/test_forge_high_score_check.py`
self-test pins the gate to 0 hard / 0 soft findings on the
as-shipped tree.
