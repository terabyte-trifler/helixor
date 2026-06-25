# Phylanx — Production-Readiness & Defensive-Engineering Review

**Date:** 2026-06-12 · **Scope:** full monorepo at `~/Documents/phylanx` (phylanx-api, phylanx-indexer, phylanx-oracle, phylanx-programs, phylanx-sdk, phylanx-validator, phylanx-web, launch/, audit/, scripts/) · **Method:** staff-level defensive code review; no offensive content. Subsystem reviews: API and infrastructure via deep-dive agents; programs, indexer/oracle, and TS packages via direct source review.

**Finding count:** 0 Critical · 7 High · 14 Medium · 18 Low

---

## 1. Executive Summary

Phylanx is an on-chain agent-health attestation protocol: a Python oracle cluster scores agents, reaches threshold consensus, and writes Ed25519-threshold-signed `HealthCertificate` PDAs via three Anchor programs; a FastAPI read layer, an SDK with a safe/unsafe split, and a Next.js frontend consume them; a slash-authority program makes the stake economically real.

The dominant theme is a **gap between paper posture and substrate**: the security design is genuinely strong and unusually well-audited for a solo pre-launch project (threshold signatures with digest binding, time-locked attested key rotations, write-once PDAs, hash-locked Python dependencies, 31 runbooks, an in-repo audit gate suite). But several load-bearing production components **do not exist yet**: the API's database adapter silently falls back to empty in-memory repos, the webhook dispatcher is a no-op, CI is documented but not wired at the repo root, the fresh-clone deploy path is broken by four missing files, DB migrations 0001–0005 are absent, the oracle node generates an ephemeral signing key at every boot, and the health-oracle program in this repo is a "delta package" that omits the deployed MVP instructions. Everything works on this one laptop; nothing yet proves it works anywhere else.

No Critical findings. The on-chain programs are the strongest layer reviewed. The highest-leverage fixes are: wire root CI (the gates already exist), repair the deploy path, land the Timescale adapter or fail loudly without it, implement persistent oracle key management, and consolidate the missing schema/program source.

---

## 2. Architecture Review

**Assessment.** The three-program split (health-oracle = registration/epochs, certificate-issuer = attestations, slash-authority = collateral) is clean separation of concerns with explicit trust boundaries. The certificate digest folds in input commitments (AW-01), Solana slot anchors verified against the SlotHashes sysvar (AW-01-EXT), baseline rotation nonces (AW-03), scoring-code provenance (AW-04), config-version snapshots (M-05), and diagnostic payloads (Day 38) — so the threshold signatures attest to the inputs and the code, not just the output. Off-chain, the indexer→eventbus→oracle pipeline uses idempotent Kafka producers (`acks=all`, `enable.idempotence`), an at-least-once consumer with retry counting and dead-letter routing, and a forgery-vs-poison distinction. The API is read-only with repository seams behind `typing.Protocol`. This is a sound architecture.

### Finding A-1 — health-oracle program is a "delta package"; deployed MVP source is not in this repo — **HIGH**
- **Files:** `phylanx-programs/programs/health-oracle/src/lib.rs:256-262, 279`
- **Description:** The file states "the Day 1-12 instructions (register_agent, update_score, get_health, ...) are already in the deployed MVP and are NOT redeclared in this delta package" and "Replace with the actual deployed program ID when merging into the real repo." The repo therefore does not contain the full source of the program it expects to run, and the declared program IDs are placeholders.
- **Impact:** Source-of-truth fragmentation. The audit gates, scoring-provenance hashes, and SDK verification all assume the published source tree matches the deployed binary — that claim cannot hold when part of the program lives elsewhere. A rebuild from this repo produces a different program than the deployed one.
- **Remediation:** Merge the MVP instructions into this repo (or vendor the deployed source at a pinned tag), make `declare_id!` values match the real deployments per network, and add an audit gate asserting `anchor build` output hash matches the deployed program account (verifiable with `solana program dump` + hash compare).

### Finding A-2 — No agent stake-withdrawal or top-up path; vault PDA squatting — **MEDIUM**
- **Files:** `phylanx-programs/programs/slash-authority/src/instructions/` (no `withdraw_stake`/`close_vault`/`add_stake` instruction exists); `open_vault.rs:24-43`
- **Description:** `EscrowVault` can only be opened and slashed. Staked SOL can never be withdrawn by the agent, and there is no top-up. Additionally, `open_vault` lets **any** signer create the vault for **any** `agent_wallet` (the staker is unconstrained), and the PDA is init-once — a third party can pre-create an agent's vault with `MIN_STAKE_LAMPORTS`, after which the agent can neither open their own vault with their intended stake nor add to it.
- **Impact:** Economically, stake is a one-way door (a product decision that should at least be documented as such); operationally, vault squatting lets an outsider pin an agent at minimum stake forever.
- **Remediation:** Add `add_stake` (anyone may top up; only `staked_lamports` increases) and a timelocked `withdraw_stake` (agent-signed, refused while any slash is Pending/Appealed, subject to a cooldown so a withdrawal cannot front-run an imminent slash). Constrain `open_vault` to `staker.key() == agent_wallet` or require the agent as co-signer.

### Finding A-3 — Permissionless singleton `initialize_config` (deployment front-run race) — **MEDIUM**
- **Files:** `certificate-issuer/src/instructions/initialize_config.rs:16-33` (admin is an unconstrained `Signer`); same pattern in slash-authority and health-oracle `initialize_*`
- **Description:** The first caller of `initialize_config` becomes `authority` and sets the cluster keys. Nothing binds the initializer to the program's upgrade authority. The window between `solana program deploy` and the init transaction is a race.
- **Impact:** A lost race means an attacker-owned config singleton on a fixed seed — unrecoverable without redeploying at a new program ID. `launch/deploy/deploy_programs.sh` mitigates by sequencing, but the guarantee is procedural, not on-chain.
- **Remediation:** Constrain the initializer to the upgrade authority: include the `ProgramData` account and `require!(program_data.upgrade_authority_address == Some(admin.key()))` (Anchor: `Account<'info, ProgramData>` + `constraint`). This converts the ops assumption into code.

### Finding A-4 — Oracle cluster transport: mTLS optional, peer identities harness-seeded — **MEDIUM**
- **Files:** `phylanx-oracle/oracle/cluster/run_cluster_node.py:79-113`
- **Description:** TLS material for gRPC peer transport is read from env and may be absent (`tls=None` → plaintext channel). Peer pubkeys are derived as `NodeKeypair.from_seed(pid, pid.encode())` — deterministic from the public node-id string — with a comment noting real deployments should learn peers from the on-chain `OracleConfig.oracle_keys`. That on-chain path is not implemented.
- **Impact:** As written this runner is a local harness. If reused beyond localnet, cluster traffic is unauthenticated/cleartext and any party can derive every peer's "identity" key. The codebase's own network-guard pattern (refuse outside localnet) is not applied here.
- **Remediation:** Make mTLS mandatory when `PHYLANX_NETWORK != localnet` (fail startup, exit 2 per existing convention); implement peer-key discovery from `OracleConfig`; add a guard that refuses `from_seed`-derived identities off-localnet.

---

## 3. Code Quality Review

**Assessment.** Quality is consistently high. Rust: workspace-wide `clippy::all = deny`, `overflow-checks = true` + `lto = "fat"` in release, checked arithmetic throughout, u128 intermediates for bps math with explicit terminal-tier rounding (`slash_record.rs:156-167`), pure extracted functions with unit and property tests (proptest reference-spec equivalence in `signing.rs:709-877`), and post-write invariant re-checks (M-12 alert-vector binding, M-11 lamport audit). Python: no `eval`/`pickle`/`yaml.load`/f-string SQL anywhere in indexer or oracle service code; parameterized queries only; frozen dataclasses with `__slots__`. TypeScript SDK: the `@phylanx/sdk` vs `@phylanx/sdk/unsafe` split forcing consumers to type "unsafe" to get raw cert reads is exemplary API design.

### Finding Q-1 — API: error-envelope contract not guaranteed for 422/500 — **LOW**
- **Files:** `phylanx-api/api/app.py:483-491`
- **Description/Impact:** Only `HTTPException` is mapped to the documented `{"error", "detail"}` envelope; `RequestValidationError` and unhandled exceptions return FastAPI/Starlette defaults, breaking clients written to the contract.
- **Remediation:** Register handlers for `RequestValidationError` and a catch-all `Exception` returning `ErrorResponse` with the traceback logged server-side only.

### Finding Q-2 — API: `to_epoch` unvalidated when `from_epoch` absent — **LOW**
- **Files:** `phylanx-api/api/app.py:697-701`
- **Remediation:** Move epoch params to `Query(ge=1)` constraints in the signature.

### Finding Q-3 — API: public leaderboard reads private internals (`registry._keys`, `counter._value`) — **LOW**
- **Files:** `phylanx-api/api/app.py:867-878`
- **Impact:** A `prometheus_client` upgrade can break a public endpoint at runtime; per-process counters make the ranking inconsistent across workers and reset on restart.
- **Remediation:** Public accessor on `ApiKeyRegistry`; own the counts in an app-owned structure mirrored into Prometheus.

### Finding Q-4 — API: evidence route can 500 on non-ASCII payload bytes; invariant unenforced — **LOW**
- **Files:** `phylanx-api/api/app.py:598`, `api/evidence_repo.py:100-128`
- **Remediation:** Enforce `payload_bytes.isascii()` in `EvidencePayloadRecord.__post_init__` so the route's documented invariant is real.

### Finding Q-5 — Demo boot script validates a stale server on port reuse — **LOW**
- **Files:** `phylanx-web/scripts/demo_boot.mjs`
- **Impact:** Second invocation can smoke-test the previous process while the new `next start` dies on EADDRINUSE — the exact failure the script exists to prevent.
- **Remediation:** Kill the PID-file process (or fail fast if the port answers) before spawning.

### Finding Q-6 — Dirty working tree holds demo-critical uncommitted code — **LOW**
- **Files:** 13 modified `phylanx-web` files; untracked `phylanx-web/components/ui/`, `phylanx-web/.npmrc`
- **Remediation:** Commit; add a clean-tree check to the demo script once CI exists.

---

## 4. Authentication Review

**Assessment.** The API's model is solid: hashed (SHA-256) key storage, full-registry walk with `hmac.compare_digest`, uniform 401s indistinguishable between missing and wrong keys, public-vs-operational endpoint split, and per-IP sliding-window rate limiting. On-chain, authentication is cryptographic (Ed25519 precompile threshold verification with digest binding and replay defense — reviewed line-by-line, no gaps found in `signing.rs`).

### Finding AU-1 — Oracle node signing key is ephemeral: regenerated at every boot — **HIGH**
- **Files:** `phylanx-oracle/oracle/cluster/run_cluster_node.py:95-97`; `oracle/cluster/identity.py:127-133`
- **Description:** A production node (no `--seed`) calls `NodeKeypair.generate()`. The node's pubkey must be one of the on-chain `OracleConfig.oracle_keys` / `IssuerConfig.cluster_keys` for its signatures to count, so a fresh key per boot means either every restart requires a 48h-timelocked on-chain key rotation, or the node's signatures never verify. There is no persistent-key load path (file, keystore, KMS, HSM) for the cluster signing identity — only `ORACLE_KEYPAIR_PATH` for the separate `commit_baseline` Solana wallet.
- **Impact:** The cluster cannot operate across restarts in production; conversely, whatever ad-hoc mechanism eventually fills this gap will be the single most security-critical key in the system, currently undesigned.
- **Remediation:** Add `PHYLANX_NODE_KEY_FILE` (0600, refusing group/world-readable) and/or systemd `LoadCredential` as the production source; document generation and rotation in a runbook; refuse `generate()` when `PHYLANX_NETWORK != localnet`. Longer term, an HSM/KMS-backed signer interface behind `NodeKeypair`.

### Finding AU-2 — `PHYLANX_API_KEYS` parser silently corrupts secrets containing `:` — **MEDIUM**
- **Files:** `phylanx-api/api/auth.py:238-253`
- **Impact:** A colon in the secret splits into wrong fields — clients get 401 on every call with both sides holding "the right key"; a fragment landing in the limit slot crashes startup with a bare `ValueError`.
- **Remediation:** Enforce a base64url/hex alphabet for secrets (reject `:` with a named error), or switch to `key=value;` format; wrap `int()` errors with env-var + line context.

### Finding AU-3 — No entropy floor on API/webhook secrets; env-only delivery — **LOW**
- **Files:** `phylanx-api/api/auth.py:102-105, 218-263`; `api/webhooks.py:130-162`
- **Remediation:** Minimum 32-char secret length in `ApiKey.from_secret`; support `*_FILE` / systemd `LoadCredential`; document `secrets.token_urlsafe(32)` as the recipe.

### Finding AU-4 — No audit trail of authenticated access — **LOW**
- **Files:** `phylanx-api/api/main.py:267` (`access_log=False`); `api/app.py:459-462`
- **Impact:** No record of which `key_id` read which operational endpoint, or source IPs behind 401 bursts — metrics give counts, not attribution.
- **Remediation:** One structured JSON log line per request (route, status, `key_id`, IP, latency) from the existing metrics middleware; WARNING on 401/429 bursts.

---

## 5. Authorization Review

**Assessment.** On-chain authorization is the strongest layer: separated role keys (executor/resolver/pauser — VULN-04), timelocked N-of-M-attested rotations where admin alone cannot enact and one honest key can veto (VULN-13, SPOF-#2), deprecated single-admin paths that hard-refuse (`update_authorities` → error 6088), bounded pause windows (H-04), treasury snapshot pinning so post-execute rotation cannot redirect settlements (H-03), settle-on-inactive-vault refusal (H-02), strict-majority threshold enforced at write time and re-checked at runtime (H-01), and a CPI allow-list with fail-closed introspection (VULN-16). API authorization is a simple two-tier key gate appropriate to a read-only service.

### Finding AZ-1 — Production deploy depends on procedural (not on-chain) initialization ordering — see A-3 (MEDIUM).

### Finding AZ-2 — `/metrics` unauthenticated and unmetered on the public port — **MEDIUM**
- **Files:** `phylanx-api/api/app.py:138, 914-920`; `api/main.py:34` (documented `PHYLANX_METRICS_PORT` is never read)
- **Impact:** Per-partner traffic volumes, per-route 401/429 counters, and production flags are world-readable — the same data class the service key-gates elsewhere; also a free request sink.
- **Remediation:** Serve metrics on a localhost/cluster-bound port (implement the documented env var) or key-gate `/metrics`.

### Finding AZ-3 — `trust_proxy` honors the leftmost (client-controlled) `X-Forwarded-For` entry — **MEDIUM**
- **Files:** `phylanx-api/api/rate_limit.py:148-167`; used at `api/app.py:411`
- **Impact:** Behind appending proxies (nginx/ALB/Cloudflare), the leftmost XFF entry is client-supplied: per-IP rate limits can be bypassed by rotating fake IPs, which also mints unbounded limiter buckets (see D-3).
- **Remediation:** Select the rightmost-untrusted entry via `PHYLANX_TRUSTED_PROXY_HOPS=n` (or trusted-CIDR list); extend `tests/test_vuln09_auth_and_ratelimit.py:428-448` with a spoofed-leftmost case.

---

## 6. Data Handling Review

**Assessment.** Strong fundamentals: parameterized SQL everywhere reviewed; no unsafe deserialization primitives in service code; canonical fixed-width serialization for everything signed; wallet validation as a tight base58 allowlist applied per-route and re-exported for repo-side defense in depth; on-chain handlers never trust caller-supplied hashes when they can recompute (`issue_certificate.rs:336-341`); deliberate cache-control tiering (`public` for scores, `no-store` for operational data).

### Finding D-1 — DB migrations 0001–0005 missing; indexer schema directory empty — **HIGH**
- **Files:** `phylanx-oracle/db/migrations/` (starts at `0006_baselines_v2.sql`, which `ALTER TABLE agent_baselines` — a table created by the absent earlier migrations); `phylanx-indexer/schema/` (empty directory)
- **Impact:** A fresh database cannot be bootstrapped from the repo. Combined with the compose file mounting the (nonexistent) schema dir (I-2), every fresh deployment starts schemaless and the indexer/oracle fail at first query. Disaster recovery from backups + migrations is impossible.
- **Remediation:** Recover or rewrite migrations 0001–0005 (a `pg_dump --schema-only` of the working dev DB, split into numbered files with `schema_version` inserts, is the fast path); add an audit gate that boots a scratch Postgres, runs all migrations in order, and asserts the app's expected tables/columns exist.

### Finding D-2 — Production database layer for the API is unimplemented; `DATABASE_URL` silently ignored — **HIGH**
- **Files:** `phylanx-api/api/main.py:149-181`
- **Description:** With `DATABASE_URL` set, `_build_repos()` logs a WARNING and returns empty in-memory repos; every data endpoint 404s while `/health` stays green.
- **Impact:** A production deploy "succeeds" into a silent total functional outage masked by liveness checks.
- **Remediation:** Land `api/_timescale.py` (psycopg3 + `psycopg_pool`, parameterized only, keep the `ensure_wallet_safe` defense-in-depth call); until then, **fail startup with exit 2** when `DATABASE_URL` is set but unusable, or surface `{"status": "degraded", "backend": "in-memory"}` from `/health`.

### Finding D-3 — Unbounded in-memory growth: rate-limiter buckets and webhook dedupe tracker never evicted — **MEDIUM**
- **Files:** `phylanx-api/api/rate_limit.py:110-136`; `api/webhooks.py:282-292`
- **Impact:** Memory grows with every distinct client IP ever seen; combined with AZ-3, an external party can mint buckets at line rate — a memory-exhaustion vector against the API process.
- **Remediation:** Delete empty buckets after pruning; periodic sweep dropping buckets older than the window; cap total buckets. Prune the tracker to the last k epochs per partner on insert.

### Finding D-4 — Webhooks configured via `PHYLANX_WEBHOOKS` are silently never delivered — **MEDIUM**
- **Files:** `phylanx-api/api/main.py:213-240`; `api/app.py:375-376`; `api/webhooks.py:250-261`
- **Impact:** The registry loads, triggers fire, the dedupe tracker marks `(partner, agent, epoch)` as sent — and `NullDispatcher` drops everything with no metric or log. Worse, dedupe-before-delivery means once a real dispatcher lands, a failed POST is never retried for that epoch.
- **Remediation:** Ship the httpx async dispatcher (timeout + 2-3 backoff retries), add `webhooks_dispatched_total{status}`, mark the tracker only after a terminal delivery outcome, and WARN at startup when webhooks are registered against `NullDispatcher`.

### Finding D-5 — Webhook registry accepts plain `http://` URLs — **LOW**
- **Files:** `phylanx-api/api/webhooks.py:111-115`
- **Remediation:** Require `https://` unless `PHYLANX_WEBHOOKS_ALLOW_INSECURE=1`.

### Finding D-6 — No CORS configuration despite browser consumers — **LOW**
- **Files:** `phylanx-api/api/app.py` (no `CORSMiddleware` anywhere); `api/safe_score.py:4-8` names browsers as consumers
- **Impact:** The web app pointed at the API via `NEXT_PUBLIC_API_URL` fails cross-origin reads — a frontend outage, not a security hole.
- **Remediation:** `CORSMiddleware` with `PHYLANX_CORS_ORIGINS` allowlist, GET-only, no credentials.

---

## 7. Infrastructure Review

**Assessment.** The `launch/` package is well beyond typical pre-launch maturity on paper: HA compose overlays (3-broker Kafka, Timescale primary/standby + WAL archive, 3-replica API behind nginx), hardened systemd units with bounded restart and loud-fail guard exits (`RestartPreventExitStatus=2`), 31 runbooks cross-linked from 9 page-severity alert rules, atomic Solana deploy with Squads multisig authority transfer, and an audit suite whose `spof_check.py` literally gates the compose topology. The reality gaps below are what keep it single-laptop.

### Finding I-1 — No CI exists, but the docs repeatedly claim it does — **HIGH**
- **Files:** no `.github/` at repo root; workflows stranded in `phylanx-integration/.github/workflows/gate.yml`, `phylanx-validator/.github/workflows/validation_short.yml`, `phylanx-plugin-elizaos/.github/workflows/ci.yml`; claims in `audit/README.md`, `audit/run_all.sh`, `phylanx-integration/README.md`
- **Impact:** GitHub Actions only discovers root-level workflows — none of these have ever run. The 1,300+ tests, audit sweeps, clippy/cargo-audit gates run only when a human remembers. Regressions land on `main` unchecked; the audit package's claims are unverifiable.
- **Remediation:** Create root `.github/workflows/`, merge the three subproject workflows (per-job `working-directory`, `paths:` filters), add the missing `audit.yml` running `audit/run_all.sh`'s CI-capable gates. Sanity check: the Actions tab shows a run on next push.

### Finding I-2 — Documented one-command stack boot fails on a fresh clone — **HIGH**
- **Files:** `launch/deploy/docker-compose.indexer.yml`; missing: `launch/deploy/schema/`, `launch/deploy/monitoring/prometheus.yml` (lives at `launch/monitoring/`), `launch/deploy/render_kafka_client_properties.sh` (referenced, never written), `launch/deploy/.env.example` (untracked)
- **Impact:** A clean clone gets a schemaless TimescaleDB (Docker creates an empty init dir), a crash-looping Prometheus (file mount becomes a directory), and a wedged indexer (Kafka healthcheck needs a hand-written gitignored secrets file). The "reproducible baseline" reproduces only on this laptop.
- **Remediation:** Fix the two mount paths (`../../phylanx-indexer/schema` — after D-1 fills it, `../monitoring/prometheus.yml`), write the 5-line render script, track `.env.example`, add `docker compose config -q` to CI.

### Finding I-3 — `.gitignore` excludes the `.env.example` templates the docs depend on — **MEDIUM**
- **Files:** `.gitignore` (`.env.*`, `.env.example`); untracked templates in phylanx-web, -integration, -validator, -e2e
- **Remediation:** `.env` / `.env.*` / `!.env.example`, then `git add -f` each template; keep `harden_secrets.ts` as the guard.

### Finding I-4 — No TLS anywhere in the HTTP serving path — **MEDIUM**
- **Files:** `launch/deploy/nginx/api_upstream.conf` (`listen 8080`, no ssl, no ACME tooling anywhere)
- **Remediation:** Caddy with automatic ACME in front of `api-lb` (lowest-ops), or document the cloud-LB TLS termination and pin `X-Forwarded-Proto` handling; add a `tls.md` runbook.

### Finding I-5 — API, API-metrics, and Prometheus published on all interfaces — **MEDIUM**
- **Files:** `launch/deploy/docker-compose.indexer.yml` (`"8080:8080"`, `"9095:9090"`, `"9091:9090"` while Postgres/Kafka are correctly `127.0.0.1:`-bound)
- **Impact:** Unauthenticated Prometheus UI (arbitrary TSDB queries) and the metrics surface are world-reachable on any host without a separate firewall — the exposure class the file's own VULN-17 comments warn about.
- **Remediation:** Prefix all three with `127.0.0.1:` in the dev file; document the production allowlist.

### Finding I-6 — Alert rules route to an Alertmanager that doesn't exist — **MEDIUM**
- **Files:** `launch/monitoring/prometheus.yml` (declares `alertmanager:9093`), no `alertmanager.yml`, no alertmanager service in any compose file
- **Impact:** All 9 page-severity rules (quorum loss, Byzantine flags, mainnet-refusal heartbeat) evaluate and go nowhere. Nobody is paged.
- **Remediation:** Add `alertmanager.yml` (severity=page → PagerDuty/Slack) and a pinned `prom/alertmanager` service; receiver secrets via env file.

### Finding I-7 — Backup/PITR is a local Docker volume: no base backups, retention, off-host copy, or restore drill — **MEDIUM**
- **Files:** `launch/deploy/docker-compose.timescale-ha.yml`; `launch/runbooks/spof_failover.md`
- **Impact:** Host loss takes primary, standby, and WAL archive together; `pg_receivewal` without scheduled base backups cannot deliver the claimed 7-day PITR window; an untested restore fails during the incident.
- **Remediation:** pgbackrest (or scheduled `pg_basebackup` + object-store sync) with retention; `scripts/restore_drill.sh` restoring to a scratch container with row-count comparison, wired into the audit suite.

### Finding I-8 — `phylanx-api.service` claims the oracle hardening profile but lacks most of it — **LOW**
- **Files:** `launch/deploy/systemd/phylanx-api.service` vs `oracle-node@.service` (missing `ReadOnlyPaths`, `SystemCallFilter`, `CapabilityBoundingSet=`, `ProtectProc`, `RestrictAddressFamilies`, …)
- **Remediation:** Copy the oracle unit's hardening block; consider a `systemd-analyze security` audit target.

### Finding I-9 — `launch/RUNBOOK.md` referenced from operator-facing refusal messages but absent — **LOW**
- **Files:** referenced by `deploy_programs.sh`, compose files, env examples, checklists; only `launch/runbooks/*.md` exist
- **Remediation:** Create it as an index over `launch/runbooks/` + the mainnet opt-in procedure.

### Finding I-10 — Localnet authority keypairs and dev credentials in plaintext on disk — **LOW**
- **Files:** `launch/deploy/keys/*.json` (10 role keypairs, 0600, untracked), `launch/deploy/.env` (`TIMESCALE_PASSWORD=phylanxdev`, `KAFKA_SASL_PASSWORD=phylanxdev`, untracked)
- **Description:** Git hygiene is verified clean across full history (only public keys tracked). The risk is drift: nothing marks these localnet-only, and the dev passwords would ride the same `.env` into any future network change.
- **Remediation:** README sentinel in `keys/`; a guard refusing `PHYLANX_NETWORK != localnet` when credentials match known dev defaults.

### Finding I-11 — Server hardening defaults: API binds `0.0.0.0`, no slowloris protection, per-worker limit multiplication — **LOW**
- **Files:** `phylanx-api/api/main.py:253-268`; `api/rate_limit.py:31-38`
- **Remediation:** Default bind `127.0.0.1`; document reverse-proxy timeout/size caps; startup WARNING that effective limits are `N × limit` when `PHYLANX_API_WORKERS > 1`; plan the Redis-backed limiter the module's comments already call "the real fix".

---

## 8. Dependency Review

**Assessment.** Python is the gold standard here: `requirements.in` → pip-compile `--generate-hashes`, installs with `--require-hashes`, a regeneration script, and a supply-chain audit gate (VULN-25). The TS packages don't meet the repo's own bar.

### Finding DEP-1 — phylanx-web runs a Next.js canary; README claims stable pinning — **MEDIUM**
- **Files:** `phylanx-web/package.json` (`"next": "16.3.0-canary.28"`, mixed `^` ranges on fontsource/react-is) vs root `README.md` ("Pinned exactly, no `^` or `~`", claims next 15.5.18)
- **Impact:** The demo-critical frontend floats on an unstable prerelease, off-posture for a repo with hash-locked Python deps; README is stale.
- **Remediation:** Pin to stable Next; update the README table; extend `audit/supply_chain_check.py` to flag `-canary`/`-rc` and `^`/`~` in package.json files.

### Finding DEP-2 — SDK floats `@solana/web3.js: ^1.95.0` — **MEDIUM**
- **Files:** `phylanx-sdk/package.json`
- **Impact:** The package that signs and submits transactions resolves any 1.x ≥1.95 at install time — exactly the dependency class with a history of supply-chain incidents, and a direct contradiction of the repo's pinning policy. The `"overrides": {"uuid": "14.0.0"}` entry also warrants verification that it resolves to an intended release.
- **Remediation:** Exact-pin web3.js (and commit the lockfile, which exists — also enforce `npm ci` in CI); cover the SDK in the supply-chain gate.

### Finding DEP-3 — `pyproject.toml` ranges drift from the hash-pinned lockfile; old uvicorn — **LOW**
- **Files:** `phylanx-api/pyproject.toml:10-16` vs `requirements.in:14-28`; `uvicorn==0.32.0` (h11-only build, late 2024)
- **Impact:** `pip install .` can resolve versions the audit never saw, silently bypassing the VULN-25 policy. (Positive: `h11==0.16.0` includes the CVE-2025-43859 fix.)
- **Remediation:** Generate pyproject pins from `requirements.in` or add a CI agreement check; bump uvicorn and re-compile hashes via `scripts/regen_requirements.sh`.

### Finding DEP-4 — Anchor 0.30.1 pinned — **LOW**
- **Files:** `phylanx-programs/Anchor.toml`
- **Description:** Pinned (good) but not current; review release notes before any mainnet deploy and re-run the audit gates after upgrading. Release profile (`overflow-checks`, `lto`, single codegen unit) is correct.

---

## 9. Production Readiness Assessment

| Dimension | State | Blocking gaps |
|---|---|---|
| On-chain programs | **Strong** | A-1 (delta package), A-3 (init race), A-2 (no unstake) |
| API service | Scaffolding | D-2 (no DB layer), D-4 (no webhook transport) |
| Oracle cluster | Harness-grade ops | AU-1 (ephemeral keys), A-4 (mTLS/peer discovery) |
| Data layer | Broken bootstrap | D-1 (missing migrations), I-7 (no real backups) |
| CI/CD | Absent | I-1 (workflows stranded in subdirectories) |
| Deploy reproducibility | Single-laptop | I-2, I-3 |
| Monitoring | Rules without delivery | I-6 (no Alertmanager) |
| Edge security | Missing | I-4 (no TLS), I-5 (port exposure), AZ-2/AZ-3 |
| Supply chain | Python excellent, TS lagging | DEP-1, DEP-2 |

**Verdict: not production-ready yet — but unusually close to it for the effort required.** The hard problems (consensus design, signature binding, authority ceremonies, audit tooling) are solved; what remains is mostly completing substrate the documentation already describes. The honest mock/demo banners, mainnet refusal gates, and fail-loud conventions show the right instincts — the task is making the paper claims enforced rather than aspirational. Estimated effort to clear all High findings: days-to-weeks, not months, because the enforcement mechanisms (audit gates, guard patterns) already exist and just need wiring.

---

## 10. Prioritized Improvement Plan

**P0 — this week (converts paper posture into enforced posture):**
1. **I-1** Root CI: move the three stranded workflows, add `audit.yml`. Everything below gets a regression guard for free.
2. **D-1 + I-2** Recover migrations 0001–0005, fix the two compose mount paths, write `render_kafka_client_properties.sh`, track `.env.example` (I-3). Acceptance: fresh clone → `docker compose up` → green healthchecks.
3. **D-2** Make a set-but-unusable `DATABASE_URL` fail startup (exit 2). One conditional; prevents the silent-404 outage class until the Timescale adapter lands.
4. **AU-1** Persistent oracle node key loading + refuse `generate()` off-localnet.

**P1 — before any externally-reachable deployment:**
5. **D-2 (full)** Land the Timescale adapter; **D-4** the webhook dispatcher.
6. **I-4/I-5/AZ-2** TLS at the edge, loopback-bind metrics/Prometheus, implement the metrics port.
7. **AZ-3 + D-3** Rightmost-XFF selection + limiter bucket eviction (these two compound).
8. **I-6** Alertmanager; **A-3** upgrade-authority-gated init; **A-4** mandatory mTLS off-localnet.

**P2 — before mainnet / external stake:**
9. **A-1** Consolidate health-oracle source; verifiable-build gate against deployed program hashes.
10. **A-2** `add_stake` + timelocked `withdraw_stake`; constrain `open_vault`.
11. **I-7** pgbackrest + scripted restore drill; **AU-2** key-format hardening; **DEP-1/DEP-2** TS pinning into the supply-chain gate.

**P3 — hygiene backlog:** Q-1..Q-6, AU-3, AU-4, D-5, D-6, I-8..I-11, DEP-3, DEP-4.

---

*Strengths worth preserving as the codebase grows: write-once epoch-keyed PDAs; digest-bound threshold signatures with property-tested verification; timelocked attested rotations with single-honest-key veto; encumber-then-settle slashing with dual timing gates and on-chain balance-audit events; the SDK's safe/unsafe entry-point split; hash-locked Python dependencies; fail-loud guard exits wired to systemd restart policy; and the self-auditing `audit/` gate suite — the rare codebase where the right fix is usually "wire up the gate that already exists."*
