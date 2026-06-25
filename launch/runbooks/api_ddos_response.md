# Runbook — API DDoS incident response

**Severity:** High but non-catastrophic. The `phylanx-api` read layer is
under a volumetric or application-layer flood. The on-chain certificate
state and the oracle cluster itself are unaffected; the failure mode is
that legitimate Verified Integrators cannot reach the read API.

**Triggers:**
- `phylanx.api.rate_limit` log volume spikes; 429 emission rate jumps
  more than 10x baseline across all replicas in
  `launch/deploy/nginx/api_upstream.conf`.
- `cluster_health` p95 latency Prometheus alert fires (`launch/monitoring/alerts.yml`).
- NGINX upstream pool starts ejecting replicas (`max_fails=3 fail_timeout=15s`
  threshold tripped on 2-of-3 replicas).
- On-call observes connection-pool saturation on the API replicas
  while the oracle cluster's `/metrics` continues to show healthy
  epoch progression.

## What's happening

Phylanx's threat model puts the read API in the load-shedding tier, not
the consensus tier. A flood at the API only degrades the convenience
layer — the on-chain `HealthCertificate` PDAs remain authoritative and
readable directly via any Solana RPC. The audit's incident-response
strategy is three concurrent moves:

  1. Shed the flood at the rate-limit layer (per-IP + per-key tiers
     already exist; tighten the public bucket).
  2. Tell Verified Integrators to switch to the **direct on-chain
     reader** path (DBP-3), which has no dependency on `phylanx-api`.
  3. Tighten cluster-health visibility so on-call has 3x faster signal
     on whether the cluster itself is being affected while the API is
     under load.

Every move below is mechanical: the substrate already exists. This
runbook is the *order* in which to fire them, and the threshold values
to use.

---

## Step 1 — Tighten rate limits and shed the flood

**Substrate:** the audit-mandated sliding-window limiter and the NGINX
upstream pool, both pre-wired and already running in production.

  - `phylanx-api/api/rate_limit.py` — VULN-09 sliding-window limiter:
    - `WINDOW_SECONDS = 60.0` (audit-mandated).
    - `DEFAULT_PUBLIC_RATE_LIMIT_PER_MIN = 100` per-IP.
    - Per-API-key cap baked into the `PHYLANX_API_KEYS` string
      (`phylanx-api/api/auth.py:65-90`).
    - Runtime knob: `PHYLANX_PUBLIC_RATE_LIMIT_PER_MIN` env var
      (`load_public_limit_from_env`, lines 180-189).
    - Trust-proxy knob: `PHYLANX_TRUST_PROXY=1` so the LEFTMOST
      `X-Forwarded-For` entry is used for IP extraction (required when
      behind NGINX).
  - `launch/deploy/nginx/api_upstream.conf`:
    - `least_conn` balance across 3 replicas.
    - `max_fails=3 fail_timeout=15s` removes a failing replica for 15s.
    - `client_max_body_size 64k` body cap rejects oversize payloads
      before they reach the API.
    - `proxy_next_upstream error timeout http_502 http_503 http_504`
      retries idempotent GETs against the next replica; POST/PUT/DELETE
      are NOT retried (matches the at-most-once write contract).

**Procedure (on-call, no Squads ceremony required):**

```bash
# A. Tighten the per-IP bucket from 100/min to 25/min on every replica.
#    `phylanx.api.rate_limit` reads PHYLANX_PUBLIC_RATE_LIMIT_PER_MIN at
#    startup, so this requires a rolling restart of the api-* services.
for replica in api-1 api-2 api-3; do
  ssh "$replica" "sudo systemctl set-environment PHYLANX_PUBLIC_RATE_LIMIT_PER_MIN=25"
  ssh "$replica" "sudo systemctl restart phylanx-api"
done

# B. Confirm the new ceiling is in effect.
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Host: api.phylanx.local' \
  http://nginx:8080/health  # repeat 30x in a tight loop
# Expect to see 429 appear after the 25th request from a single IP.

# C. If the attack continues, drop to 10/min and add a 503 sinkhole on
#    NGINX for any IP that has been 429-ed 10 times in the last minute.
#    Edit nginx.conf, reload with `nginx -s reload` (no downtime).
```

**Per-key tier overrides during IR:**

Partner-keyed clients should NOT be rate-limited the same as anonymous
traffic. The `PHYLANX_API_KEYS` env var supports five fields per key:
`key_id:secret:tier:limit_per_min:partner_wallet`. During an attack,
re-emit the env var with the legit-partner `limit_per_min` *raised*
(e.g. from 1,000/min to 5,000/min) so the partner traffic is not
collateral damage. Restart api-* to pick it up.

**Verify the limiter is engaged:**

```bash
# `phylanx.api.rate_limit` logs each 429 with the bucket id.
journalctl -u phylanx-api -f \
  | grep 'phylanx.api.rate_limit' \
  | grep ' 429 '
# Expect a steady stream from "ip:X.Y.Z.W" buckets and NONE from "key:*"
# buckets if the partner-tier overrides are working.
```

**What this does NOT do:**

- The in-process limiter is per-worker; multi-worker uvicorn converges
  to N * limit overall (acknowledged in `rate_limit.py:31-38`). A
  distributed Redis-backed limiter at the edge is on the roadmap but
  is NOT a blocker — the per-worker floor combined with NGINX's
  upstream-eject behaviour is the launch-gate posture.
- The 64KiB body cap is enforced by NGINX, not the application; an
  attacker that uses 63KiB bodies cannot be defended against at this
  layer. Step 2 is the answer to that case.

---

## Step 2 — Switch Verified Integrators to the direct on-chain reader

**Substrate:** the DBP-3 SafeCertReader path, which reads
`HealthCertificate` PDAs directly from Solana RPC and has NO dependency
on `phylanx-api`.

  - `launch/integrations/example_safe_partner/reader.ts` — the
    reference implementation. `SafePartnerReader` enforces the
    four-gate contract:
    - VULN-23 SafeCertReader freshness + velocity (48h, ±200/3 epochs).
    - SOL-3 per-operation age floors: LOAN_ISSUE 4h, LOAN_INCREASE 8h,
      LIQUIDATION_CHECK 12h, STATUS_READ 48h.
    - AW-01 input-provenance verification.
    - AW-01-EXT slot-anchor ledger re-verification.
  - `@phylanx/sdk` (default export) — wraps the on-chain reader and
    exposes only the safe surfaces. The `@phylanx/sdk/unsafe` subpath
    exposes raw primitives (`PhylanxChainClient`); a DBP-3 lint gate
    pins this partition so partners cannot accidentally import the
    unsafe surface.
  - `VerifiedConsumer` PDA at `[b"verified_consumer", partner_wallet]`
    continues to operate normally — the badge is on-chain, not in the
    API.

**Why this is safe:**

The on-chain epoch cadence is 2h (well under the SOL-3 LOAN_ISSUE 4h
floor), and FRP-3 `MAX_CERT_REISSUE_INTERVAL_SECONDS = 4 * 3600` is the
ceiling. So a partner reading the latest `HealthCertificate` PDA
directly will always see a cert that satisfies the per-operation
freshness floor — the API was a convenience layer, not a correctness
layer.

**Procedure (on-call → partner-notify channel):**

```text
A. Page the partner-notify channel (Slack #phylanx-integrators) with
   the templated message:

   ┌─────────────────────────────────────────────────────────────────┐
   │ Phylanx API is under load. The read API may return 429 or 503  │
   │ for the next N hours. Your on-chain reader path is unaffected. │
   │                                                                 │
   │ ACTION: switch from `https://api.phylanx.io/v1/cert/{agent}`   │
   │ to the on-chain reader. Reference implementation:              │
   │   launch/integrations/example_safe_partner/reader.ts           │
   │                                                                 │
   │ SDK switch (one line): `import { SafePartnerReader } from      │
   │ '@phylanx/sdk'` — uses RPC directly, no API dependency.        │
   │                                                                 │
   │ This is the *normal* DeFi-bypass path (DBP-3). The four gates   │
   │ — freshness, velocity, input-provenance, slot-anchor — are     │
   │ enforced client-side and are CHEAPER per call than the API.    │
   └─────────────────────────────────────────────────────────────────┘

B. Cross-post to status.phylanx.io with a one-line "Read API
   degraded; on-chain reader path is healthy" banner.

C. After the flood subsides, page the partners again with the
   "all-clear" message. Do NOT recommend they switch BACK to the API
   path — the on-chain reader is the safer default and partners that
   migrate during the incident should be encouraged to stay there.
```

**Verify partners migrated:**

```bash
# The API replicas' access logs include a "X-Phylanx-SDK" header
# emitted by the older API-path SDK. The on-chain reader does NOT emit
# this header. Count how many partner keys are still hitting the API.
journalctl -u phylanx-api --since '1 hour ago' \
  | grep -oP 'X-Phylanx-SDK: \S+' \
  | sort -u
# A shrinking set of distinct values = partners are migrating.
```

---

## Step 3 — Tighten cluster-health visibility during the attack

**Substrate:** the Prometheus scrape configuration. Cluster cadence
itself (2h epoch) is on-chain and CANNOT be changed during an IR — but
during an API DDoS, the cluster cadence does NOT need to change. What
DOES need to change is on-call's signal-to-noise: scrape the cluster
3x more frequently so any cluster-side degradation surfaces in seconds
rather than 30 seconds.

  - `launch/monitoring/prometheus.yml`:
    - Default `scrape_interval: 15s`.
    - Five oracle nodes scraped on the `oracle-node` job
      (`oracle-node-0:9090` ... `oracle-node-4:9090`).
    - Indexer and API also exported on `:9090`.
  - `launch/monitoring/alerts.yml` — every cluster-health alert in the
    file is keyed off the same scrape series, so tightening the
    scrape interval also tightens alert latency.

**What the on-chain cadence floor guarantees:**

The audit-mandated cluster liveness floors in
`launch/LAUNCH_CHECKLIST.md` are:
  - `WARN_QUIET_SECONDS = 2h` — cluster still healthy.
  - `SILENT_QUIET_SECONDS = 4h` — cluster is silent (paging event).

So even if the API is being DDoS'd, the cluster cadence stays at 2h
and the SOL-3 freshness floors continue to be satisfied for direct
on-chain readers (Step 2). The cluster's own attestation flow is not
on the API's critical path.

**Procedure (on-call, hot-reload, no restart):**

```bash
# A. Tighten the global scrape interval from 15s to 5s.
sudo sed -i 's/scrape_interval:     15s/scrape_interval:     5s/' \
  /etc/prometheus/prometheus.yml
sudo sed -i 's/evaluation_interval: 15s/evaluation_interval: 5s/' \
  /etc/prometheus/prometheus.yml

# B. Hot-reload Prometheus — no restart, no scrape gap.
curl -X POST http://prometheus:9090/-/reload

# C. Confirm the reload took.
curl -s http://prometheus:9090/api/v1/status/config \
  | jq -r '.data.yaml' \
  | grep scrape_interval
# Expect "scrape_interval: 5s"

# D. Tail the cluster-health series — every 5 seconds, every node.
watch -n 1 'curl -s http://prometheus:9090/api/v1/query \
  --data-urlencode "query=phylanx_cluster_quorum_size" \
  | jq -r ".data.result[] | .metric.instance + \" \" + .value[1]"'
# Expect 5 nodes all reporting quorum=5 (3-of-5 healthy ceiling).
```

**What this does NOT do:**

- It does NOT raise the on-chain cert-issuance cadence. The on-chain
  `OracleConfig.epoch_seconds` is fixed at 2h and changing it requires
  the VULN-13 48-hour timelock ceremony — wholly unsuitable for IR.
  The 2h cadence is already aligned with the SOL-3 LOAN_ISSUE 4h
  floor, so faster on-chain attestation is NOT needed for direct
  on-chain readers.
- It does NOT add new metrics. The scrape-interval bump is purely a
  visibility change; if a needed metric is missing it must be added
  via a normal deploy.

**Reset after the incident:**

```bash
# Revert Prometheus to 15s once the attack is over (the 5s scrape
# generates 3x the TSDB pressure long-term).
sudo sed -i 's/scrape_interval:     5s/scrape_interval:     15s/' \
  /etc/prometheus/prometheus.yml
sudo sed -i 's/evaluation_interval: 5s/evaluation_interval: 15s/' \
  /etc/prometheus/prometheus.yml
curl -X POST http://prometheus:9090/-/reload
```

---

## What to log in the postmortem

  - Peak `phylanx.api.rate_limit` 429 emission rate per replica and
    bucket-id histogram (which IPs / which keys).
  - NGINX upstream-eject events from `/var/log/nginx/error.log`
    (timestamps when `max_fails=3` tripped).
  - `phylanx_cluster_quorum_size` series for the full incident window
    — confirmation that the cluster never dropped quorum.
  - Partner-migration ratio: count of distinct `X-Phylanx-SDK`
    user-agents at attack start vs end.
  - Whether the partner-tier `limit_per_min` overrides in
    `PHYLANX_API_KEYS` had to be raised (and the value used).
  - Whether NGINX 503 sinkhole rules had to be added; if so, retain
    the regex and IP set in `incidents/`.

---

## Why this composition is sufficient — and what is NOT included

The runbook does NOT call for:

  - A new "API pause" admin instruction. The existing 429 + NGINX
    behaviour shed load deterministically; a global pause flag would
    create a new high-value target (whoever controls the flag).
  - A new on-chain "DDoS mode" cert-cadence bump. The on-chain
    cadence is intentionally slow (2h) and the SOL-3 floors are
    already aligned to that cadence; a faster cadence during IR would
    create a cliff when normal cadence resumes.
  - A new authority key for hot-reloading the rate limiter. The env
    var + systemctl-restart path is operator-of-record-only; no new
    key surface is introduced.

The runbook DOES rely on three additive items being on the roadmap
(not blockers, since the existing posture is sufficient):

  - A Redis-backed distributed limiter at the edge (acknowledged in
    `phylanx-api/api/rate_limit.py:31-38`).
  - A managed CDN layer (Cloudflare / CloudFront) in front of NGINX
    for true volumetric attacks; the current NGINX-only posture is
    adequate for application-layer floods up to the upstream's
    bandwidth ceiling.
  - A kill-switch / circuit-breaker for fail-closed under acute
    load. The current posture is fail-degraded (429s flow back to
    clients); Step 2 makes that acceptable since partners have a
    cheaper on-chain path to fall back on.
