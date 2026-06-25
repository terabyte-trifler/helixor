# Runbook — Mainnet refusal triggered

**Severity:** Page.
**Trigger:** Prometheus `ProductionRefusalTriggered` alert.

## What's happening

A Phylanx service attempted to start against a mainnet RPC and the
network guard (`oracle/network_guard.py`) refused. The process exited
with code 2 and systemd is **not retrying** (the systemd unit has
`RestartPreventExitStatus=2`).

This is the **safety belt firing**. It exists to prevent an
accidentally-misconfigured service from talking to production. It is
working as designed.

## The two possible interpretations

1. **Misconfiguration** — the env file was wrong, the service was meant
   to start against devnet. The fix is to correct the env file. **Do
   not add `PHYLANX_MAINNET_OK=1` to make the alert go away.**
2. **Intentional mainnet start** — the operator is bringing up a new
   production node. The fix is to add `PHYLANX_MAINNET_OK=1` to that
   service's env file, with a commit message naming the reason.

## Triage (60s)

```bash
# 1. What was the service that refused?
curl -s http://prometheus:9090/api/v1/query?query=phylanx_production_refusal_total |
  jq '.data.result[] | {service: .metric.service, count: .value[1]}'

# 2. What did it think the network was?
ssh <host>
sudo cat /etc/phylanx/<service>.env | grep PHYLANX_NETWORK

# 3. Was this start intentional?
# Check the deploy log / chat for the last 60 min — was a mainnet
# rollout in progress?
```

## Decision tree

- **Env file says `mainnet-beta` but the rollout plan is for devnet:**
  MISCONFIG. Fix the env file. Do NOT add the opt-in flag.

- **Env file says `mainnet-beta`, rollout was for mainnet, no opt-in
  flag in env file:** INTENTIONAL but incomplete config. Add
  `PHYLANX_MAINNET_OK=1` to the env file with a deliberate commit
  message naming the reason ("mainnet canary stage 1 brings up first
  node"), restart.

- **Env file says devnet but service tried mainnet anyway:** BUG in the
  code — the network guard read the env correctly but something else
  is pointing at mainnet (e.g. SOLANA_RPC_URL hardcoded). File P0.

## Recovery

After the env file is fixed:

```bash
# The systemd unit's RestartPreventExitStatus=2 means manual restart
# is required — by design, so the operator confirms the fix.
sudo systemctl restart phylanx-oracle-<i>
sudo systemctl status phylanx-oracle-<i>
journalctl -u phylanx-oracle-<i> -n 50
# Expect: "network_guard: service ... starting against devnet (non-production)"
```

## What NOT to do

- ❌ Don't add `PHYLANX_MAINNET_OK=1` "just to make the alert go away."
  The alert exists FOR this case.
- ❌ Don't disable the guard in code. It's been built specifically as a
  last belt and audit teams check for its presence.
- ❌ Don't silence the alert. If it fires twice in a week, write a
  postmortem on the deploy process.

## Postmortem (mandatory)

Every refusal triggers a postmortem under
`incidents/<YYYY-MM-DD>-mainnet-refusal-<service>.md`:
- Was the start intentional?
- What changed in the deploy pipeline that allowed a misconfig through?
- What deploy-pipeline check would have caught this before systemd did?

The safety belt firing on the host is the LAST line of defense; the
goal is to never need it.
