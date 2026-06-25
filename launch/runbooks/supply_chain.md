# Runbook — Supply-chain hardening (VULN-25)

**Severity:** Pre-launch gate. Re-verify on every dependency upgrade.
**Trigger:** New `requirements.in` change, or `audit/supply_chain_check.py`
HARD finding.

## Why this exists

An oracle node's Ed25519 private key sits in process memory during
every signing operation. A supply-chain compromise of any direct OR
transitive Python dependency — `cryptography`, `solders`, `solana`,
`grpcio`, even something lower in the closure — gives the attacker
key-exfiltration on first `sign()` call. They then hold a valid
cluster key for the rest of the epoch.

The four layers of defence:

1. **Hash-locked dependencies** (`*.txt` produced from `*.in`).
2. **Narrow signing surface** (`oracle.cluster.signer.Signer`).
3. **Read-only filesystem** + dropped capabilities (systemd).
4. **Egress allowlist** (iptables/nftables — DNS allowlist not
   expressible in systemd alone).

## 1 — Regenerate the hash-locked `requirements.txt`

Run from the repo root, every time `phylanx-*/requirements.in`
changes:

```bash
# Install pip-tools once, then:
bash scripts/regen_requirements.sh
git add phylanx-*/requirements.{in,txt}
git commit -m "deps: regenerate hash-locked requirements"
```

The `.txt` files MUST be committed alongside the `.in`. The audit
scanner (`audit/supply_chain_check.py`) refuses any PR where a `.in`
was edited but the `.txt` was not regenerated (best-effort: the
scanner pins the `.in` shape; CI verifies install with
`--require-hashes`).

## 2 — Production install MUST use `--require-hashes`

In the deploy script (or `launch/deploy/deploy_programs.sh`), every
`pip install` for an oracle/api/indexer venv runs as:

```bash
/opt/phylanx/venv/bin/pip install \
    --require-hashes \
    --no-deps \
    -r /opt/phylanx/phylanx-oracle/requirements.txt
```

`--require-hashes` makes pip refuse the install if any package on
the wire has a different SHA256 than what was locked. `--no-deps`
prevents pip from quietly resolving an unlocked transitive package.

## 3 — Verify the lock at runtime

Add to the node's startup probe (called by the systemd unit's
`ExecStartPre=`):

```bash
/opt/phylanx/venv/bin/pip check
/opt/phylanx/venv/bin/python -c "import importlib.metadata as m; \
  print(sorted((d.name, d.version) for d in m.distributions()))"
```

Cross-check the printed list against
`phylanx-oracle/requirements.txt`. Any drift = abort start.

## 4 — Egress allowlist (per-node)

Set on each oracle host BEFORE enabling the systemd unit. Replace
the example IPs with your cluster's real RPC + indexer + Prometheus
endpoints:

```bash
# iptables: default-drop egress for the `phylanx` user, allow only
# the listed destinations. nftables variant in the appendix.
iptables -A OUTPUT -m owner --uid-owner phylanx -j PHYLANX_EGRESS
iptables -A PHYLANX_EGRESS -d <SOLANA_RPC_IP>     -p tcp --dport 443 -j ACCEPT
iptables -A PHYLANX_EGRESS -d <INDEXER_IP>        -p tcp --dport 8443 -j ACCEPT
iptables -A PHYLANX_EGRESS -d <PROMETHEUS_PUSH>   -p tcp --dport 9090 -j ACCEPT
iptables -A PHYLANX_EGRESS -d <PEER_NODE_IP_LIST> -p tcp --dport 50051 -j ACCEPT
iptables -A PHYLANX_EGRESS -j REJECT --reject-with icmp-admin-prohibited
```

A compromised dependency that tries to phone home to an attacker
C2 hits the REJECT rule and never escapes the box.

## 5 — Read-only root + tmpfs

Already wired in `launch/deploy/systemd/oracle-node@.service`:

```
ReadOnlyPaths=/opt/phylanx
ReadWritePaths=/var/lib/phylanx /var/log/phylanx
PrivateTmp=true
SystemCallFilter=@system-service
CapabilityBoundingSet=
```

Verification after deploy:

```bash
sudo systemd-analyze security oracle-node@0.service
# Expect "Overall exposure level for ... is X.Y SAFE" with score < 2.0.
```

## 6 — HSM (when ready)

`oracle.cluster.signer.HSMSigner` is the wire-up point. The base
class refuses to sign so a misconfigured production deploy that
"forgot" to subclass fails LOUDLY, never silently falling back to
in-process keys. Subclass for your chosen HSM (YubiHSM, AWS KMS,
Cubist, Fireblocks MPC) and pass an instance everywhere the cluster
runner currently passes a `NodeKeypair`.

## Appendix: nftables variant

```
table inet phylanx {
    chain output {
        type filter hook output priority 0;
        meta skuid phylanx jump phylanx_egress
    }
    chain phylanx_egress {
        ip daddr { <SOLANA_RPC_IP>, <INDEXER_IP>, <PEER_IPS> } accept
        reject with icmpx admin-prohibited
    }
}
```
