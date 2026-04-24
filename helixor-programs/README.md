# Helixor — AI Agent Trust Scoring

> **Register → Observe → Score → One operator uses it.**

One Solana program. One trust score (0-1000). One elizaOS operator reading it
before every financial action. That's the MVP.

---

## Day 1 Status

| Item | Status |
|------|--------|
| health_oracle program compiled + deployed | ✅ Day 1 |
| 3 instructions in IDL (register, getHealth, updateScore) | ✅ Day 1 |
| All state structs defined (AgentRegistration, TrustCertificate, OracleConfig) | ✅ Day 1 |
| All 10 error codes defined | ✅ Day 1 |
| CI pipeline (lint → build → test → deploy devnet) | ✅ Day 1 |
| `register_agent` full implementation | ⏳ Day 2 |
| `get_health()` CPI endpoint | ⏳ Day 3 |
| Helius webhook → PostgreSQL | ⏳ Day 4 |
| Baseline engine (3 signals) | ⏳ Day 5 |
| Scoring engine (0-1000) | ⏳ Day 6 |
| `update_score` + oracle epoch runner | ⏳ Day 7 |
| FastAPI REST + TypeScript SDK | ⏳ Day 8 |
| elizaOS plugin (the one operator) | ⏳ Day 9 |
| End-to-end validation | ⏳ Day 10 |
| One real agent continuously scored | ⏳ Day 11 |
| elizaOS operator gate live | ⏳ Day 12 |
| Hardening + bug fixes | ⏳ Day 13 |
| Devnet 48h validation | ⏳ Day 14 |
| Mainnet deploy | ⏳ Day 15 |

---

## Quick Start

```bash
# Prerequisites
rustup update stable
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --tag v0.30.1 --locked
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"

# One command does everything
cd helixor-programs
bash scripts/setup.sh
```

---

## The Loop

```
Day 2: operator registers their elizaOS agent wallet
         → AgentRegistration PDA created on-chain
         → 0.01 SOL escrow locked

Day 4-5: Helius webhooks stream every agent transaction → PostgreSQL
          Oracle computes 30-day behavioral baseline

Day 6-7: Python scoring engine runs every 24h
          3 signals → one 0-1000 score → written to TrustCertificate PDA

Day 8-9: elizaOS plugin reads score on startup
          Financial actions (swap, borrow, lend) blocked if score < 600

Day 15: One real operator, one real agent, in production on mainnet
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                 health-oracle (ONE program)               │
│                                                          │
│  register_agent() → AgentRegistration PDA                │
│  get_health()     → TrustCertificate PDA (read-only CPI) │
│  update_score()   → TrustCertificate PDA (oracle only)   │
└─────────────────────────────┬────────────────────────────┘
                              │
              ┌───────────────┴────────────────┐
              │                                │
   ┌──────────▼──────────┐        ┌────────────▼────────────┐
   │  Oracle (Python)     │        │  elizaOS Plugin          │
   │                      │        │                          │
   │  Helius webhooks     │        │  getScore()              │
   │  → PostgreSQL        │        │  requireMinScore(600)    │
   │  → 3-signal scorer   │        │  blocks financial actions│
   │  → update_score() CPI│        │                          │
   └──────────────────────┘        └──────────────────────────┘
```

---

## State Account Sizes

| Account | Seeds | Size | Created |
|---------|-------|------|---------|
| `AgentRegistration` | `["agent", agent_wallet]` | 8+82 = **90 bytes** | Day 2 |
| `TrustCertificate` | `["score", agent_wallet]` | 8+51 = **59 bytes** | Day 7 |
| `OracleConfig` | `["oracle_config"]` | 8+65 = **73 bytes** | Day 7 |
| `EscrowVault` | `["escrow", agent_wallet]` | System account | Day 2 |

---

## Trust Score

| Score | Alert | Protocol Behaviour |
|-------|-------|--------------------|
| 700–1000 | 🟢 GREEN | Full access |
| 400–699 | 🟡 YELLOW | Reduced access / operator warned |
| 0–399 | 🔴 RED | Access denied |
| — | ⚪ PROVISIONAL | < 24h since registration |

**Three scoring signals (V1):**
1. **Success rate** — 50% weight — % of transactions that succeeded
2. **Transaction consistency** — 30% weight — daily tx count vs baseline median
3. **SOL flow stability** — 20% weight — volatility of daily SOL movement

---

## Commands

```bash
anchor build                                          # Build
anchor test                                           # Run smoke tests (localnet)
anchor test --provider.cluster devnet --skip-deploy   # Test against devnet
cargo clippy -- -D warnings                           # Lint
cargo audit                                           # CVE scan
bash scripts/setup.sh                                 # Full devnet setup
```

---

*Helixor · April 2026 · MIT License*
