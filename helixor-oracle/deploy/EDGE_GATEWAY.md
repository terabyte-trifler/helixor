# Helixor Edge Gateway Runbook

Goal: keep the API private to a trusted edge, terminate TLS before traffic
reaches the container, apply WAF rules at the edge, and enforce customer
quotas inside Helixor by API key.

## Required Production Shape

```
Internet
  -> Cloudflare WAF + TLS
  -> Fly / Render / AWS ALB HTTPS origin
  -> Helixor API container on :8001
  -> Redis for rate limits + score cache
  -> Postgres
```

The API container should not be exposed directly to the public internet.
Only the edge/load balancer should be able to reach it.

## Cloudflare

Use Cloudflare in front of any origin provider.

Minimum settings:
- DNS: `api.helixor.xyz` proxied through Cloudflare.
- SSL/TLS mode: `Full (strict)`.
- WAF managed rules: enabled.
- Bot Fight Mode or equivalent bot protection: enabled.
- Rate limiting rule for anonymous abuse before it reaches the origin.
- Firewall rule: block direct access to sensitive paths except trusted ops IPs:
  `/monitoring/*`, `/metrics`.

Suggested WAF custom rules:
- Challenge requests with missing or suspicious `User-Agent`.
- Block countries/ASNs only if they are clearly outside your user base.
- Block requests with body size above expected telemetry payload size.
- Log, then enforce, before tightening broad rules.

## Fly.io Origin

Fly gives you automatic TLS and anycast routing. Keep Postgres and Redis as
managed services or private-network services.

Environment variables required for API:
- `DATABASE_URL`
- `REDIS_URL`
- `HELIUS_API_KEY`
- `HELIUS_WEBHOOK_URL`
- `HELIUS_WEBHOOK_AUTH_TOKEN`
- `HEALTH_ORACLE_PROGRAM_ID`
- `ORACLE_KEYPAIR_PATH`
- `MONITORING_ADMIN_TOKEN`
- `API_CORS_ORIGINS`
- `TRUST_X_FORWARDED_FOR=true`
- `TRUSTED_PROXY_IPS=<Fly proxy/private proxy IPs if preserving client IP>`

Deploy command shape:

```bash
fly launch --dockerfile Dockerfile --no-deploy
fly secrets set DATABASE_URL=... REDIS_URL=... MONITORING_ADMIN_TOKEN=...
fly deploy
```

Run the API process with:

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8001
```

## Render Origin

Use a private Redis instance and managed Postgres. Render terminates TLS for
the public service.

Service settings:
- Environment: Docker.
- Health check path: `/health`.
- Start command: `uvicorn api.main:app --host 0.0.0.0 --port 8001`.
- Public service only for `api.main`; background workers should be private
  workers.
- Add Cloudflare in front of the Render hostname before production traffic.

## AWS ALB Origin

Use CloudFront or Cloudflare in front, then an internet-facing ALB, then ECS or
EKS tasks in private subnets.

Minimum AWS controls:
- ACM certificate on ALB listener `443`.
- HTTP `80` redirects to HTTPS.
- AWS WAF attached to ALB or CloudFront.
- Security group: ALB can reach API tasks on `8001`; public internet cannot.
- API tasks use ElastiCache Redis and RDS Postgres.
- Health check path: `/health`.
- Use rolling deploys with at least two API tasks.

## In-App Quotas

Helixor enforces the last-mile quota in Redis:
- anonymous callers: IP bucket
- valid operator keys: API-key-hash bucket
- tiers: `free`, `partner`, `team`

Default per-minute capacity:
- anonymous: `100`
- free key: `300`
- partner key: `10000`
- team key: `50000`

Set these with:
- `RATE_LIMIT_CAPACITY`
- `RATE_LIMIT_FREE_CAPACITY`
- `RATE_LIMIT_PARTNER_CAPACITY`
- `RATE_LIMIT_TEAM_CAPACITY`
- `API_KEY_TIER_CACHE_SECONDS`

Cloudflare/Fly/Render/AWS should still have coarse rate limits and WAF rules.
The API key quota is the application-level customer contract.

## Production Checklist

- `REDIS_URL` is set and `/metrics` shows Redis-backed cache available.
- Only edge/load balancer can reach the API container.
- TLS certificate is valid for `api.helixor.xyz`.
- WAF is enabled in log mode, then enforce mode.
- `/monitoring/*` requires `MONITORING_ADMIN_TOKEN`.
- `/metrics` is not publicly scraped unless protected by the edge.
- `TRUST_X_FORWARDED_FOR` is enabled only when the immediate proxy strips
  client-supplied `X-Forwarded-For`.
- Load test hits the public edge URL, not `localhost`.
