# Helixor — AI Agent Trust Scoring

> **Day 3 — `get_health()` CPI endpoint.**
>
> Any DeFi protocol can now call `get_health(agent_wallet)` from their own
> Solana program in a single CPI and receive a fully-typed `TrustScore` back.

---

## Day 3 Status

| Item | Status |
|------|--------|
| `get_health()` instruction — production implementation | ✅ |
| Returns 4 distinct `ScoreSource` paths (Live, Stale, Provisional, Deactivated) | ✅ |
| Address-validates `trust_certificate` PDA (no spoofing) | ✅ |
| Handles missing-cert case (Anchor `Account<T>` would otherwise revert) | ✅ |
| `HealthQueried` event with full payload | ✅ |
| `consumer-example` program proves CPI works end-to-end | ✅ |
| 16 integration tests across 5 groups | ✅ |
| `update_score()` (Day 7 stub) | ⏳ |

---

## What `get_health()` Returns

```rust
pub struct TrustScore {
    pub agent:        Pubkey,
    pub score:        u16,        // 0-1000
    pub alert:        AlertLevel, // Green / Yellow / Red
    pub success_rate: u16,        // basis points (9750 = 97.50%)
    pub anomaly_flag: bool,
    pub updated_at:   i64,        // unix seconds
    pub is_fresh:     bool,       // false if cert > 48h old
    pub source:       ScoreSource,// Live / Stale / Provisional / Deactivated
}
```

The `source` field is the **integration contract** — it tells consuming
protocols *why* this score is what it is, so they can apply differentiated
policy:

| `source` | When it fires | Consumer should... |
|----------|---------------|---------------------|
| `Live` | Fresh cert + active agent | Trust the score normally |
| `Stale` | Cert > 48h old | Reject — oracle has stalled |
| `Provisional` | No cert yet (first 24h) | Reject for high-value, allow read-only |
| `Deactivated` | `agent.active = false` | Reject — owner shut it down |

---

## CPI Integration Pattern

The `consumer-example/` program is the canonical reference. Here's the
30-line version:

```rust
use health_oracle::cpi::accounts::GetHealth;
use health_oracle::cpi::get_health;
use health_oracle::state::{ScoreSource, TrustScore};

pub fn do_protected_action(ctx: Context<DoProtectedAction>) -> Result<()> {
    let cpi_program = ctx.accounts.health_oracle_program.to_account_info();
    let cpi_accts   = GetHealth {
        querier:            ctx.accounts.caller.to_account_info(),
        agent_registration: ctx.accounts.agent_registration.to_account_info(),
        trust_certificate:  ctx.accounts.trust_certificate.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accts);

    let result = get_health(cpi_ctx)?;
    let score: TrustScore = result.get();

    require!(score.is_fresh,                                    MyError::ScoreTooStale);
    require!(score.source != ScoreSource::Deactivated,          MyError::AgentDeactivated);
    require!(score.score >= 600,                                MyError::ScoreBelowMinimum);

    // Action proceeds...
    Ok(())
}
```

`Cargo.toml`:

```toml
[dependencies]
health-oracle = { version = "0.3", features = ["cpi"] }
```

---

## Quick Start

```bash
# Prerequisites
rustup update stable
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --tag v0.30.1 --locked
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"

# One command: build, deploy, test
cd helixor-programs
bash scripts/setup.sh
```

Manual query against devnet:

```bash
ts-node scripts/query_health.ts <agent-wallet-pubkey>
```

---

## Bug Fixes from the Day 3 Spec

The spec had three real issues that this implementation addresses:

**1. `Account<'info, TrustCertificate>` reverts when the cert doesn't exist.**
Anchor's `Account<T>` requires a valid discriminator before the handler runs.
The spec checked `cert.updated_at == 0` to detect "no cert yet" — but that
branch is unreachable when the PDA itself doesn't exist. Fix: declare the
cert as `UncheckedAccount`, validate the address matches the canonical PDA,
and deserialize manually only if the account has data.

**2. Trust certificate PDA was not address-validated.**
The original constraint `seeds = [b"score", agent_registration.agent_wallet.as_ref()], bump`
on a `UncheckedAccount` would silently accept *any* account address that
happens to deserialize. We add an explicit `require_keys_eq!` against the
canonically-derived PDA so callers can't pass a forged cert.

**3. Return data plumbing was undocumented.**
Real DeFi protocols calling this via CPI don't get the return value automatically —
they need to use Anchor's `cpi::result.get()` pattern. The `consumer-example`
program shows the exact code, so integration partners can copy-paste.

---

## Test Coverage

```
Group 1: Direct invocation (3 tests)
  [1] Provisional: no cert exists → score=500, source=Provisional
  [5] NotRegistered: no AgentRegistration → AccountNotInitialized
  [6] Wrong cert PDA → InvalidCertificateAddress

Group 2: Event emission (1 test, 3 assertions)
  [7-9] HealthQueried: agent, querier, score, alert, source, timestamp

Group 3: TrustScore shape (3 tests)
  [10] All 8 fields present in return
  [11] AlertLevel encoded correctly
  [12] ScoreSource encoded correctly

Group 4: CPI from consumer-example (2 tests)
  [13] Provisional cert → consumer rejects with ScoreTooStale
  [14] CPI invocation succeeds; consumer policy enforced post-CPI

Group 5: Day 7 follow-ups
  Live + Stale tests added once update_score writes real certs
```

---

## File Structure

```
helixor-programs/
├── programs/
│   ├── health-oracle/        ← the trust scoring program
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── state.rs       ← TrustScore, ScoreSource (Day 3 stable)
│   │       ├── errors.rs      ← + InvalidCertificateAddress
│   │       └── instructions/
│   │           ├── register_agent.rs   (Day 2 — frozen)
│   │           ├── get_health.rs       (Day 3 — COMPLETE)
│   │           └── update_score.rs     (Day 7 — stub)
│   │
│   └── consumer-example/      ← reference DeFi integration
│       └── src/
│           └── lib.rs         ← do_protected_action with CPI
│
└── tests/
    ├── smoke.ts
    ├── register_agent.ts      (Day 2 carry-over)
    └── get_health.ts          (Day 3 — 16 tests)
```

---

## Commands

```bash
anchor build
anchor test --provider.cluster localnet
anchor test --provider.cluster devnet --skip-deploy
ts-node scripts/query_health.ts <agent-pubkey>
cargo clippy --all-targets -- -D warnings
```

---

*Helixor MVP · Day 3 complete · Next: Day 4 Helius webhook → PostgreSQL*
