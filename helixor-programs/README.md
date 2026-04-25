# Helixor — AI Agent Trust Scoring

> **Day 2 — register_agent + AgentRegistration PDA + escrow transfer.**

One Solana program. One trust score. One elizaOS operator who reads it before
every financial action. That's the MVP.

---

## Day 2 Status

| Item | Status |
|------|--------|
| `register_agent` instruction — full implementation | ✅ |
| `AgentRegistration` PDA (83 bytes, 7 fields) | ✅ |
| `EscrowVault` (SystemAccount PDA) | ✅ |
| Native SOL escrow transfer via CPI | ✅ |
| `AgentRegistered` event with full payload | ✅ |
| 5 input validations | ✅ |
| 14 integration tests | ✅ |
| `get_health()` (Day 3 stub) | ⏳ |
| `update_score()` (Day 7 stub) | ⏳ |

---

## What `register_agent` Does

```
Owner calls register_agent({ name: "MyAgent" })
  │
  ├── Validate name not empty (NameEmpty)
  ├── Validate name ≤ 64 bytes (NameTooLong)
  ├── Validate agent_wallet ≠ owner (AgentSameAsOwner)
  │
  ├── Init AgentRegistration PDA   seeds: ["agent", agent_wallet]
  │     agent_wallet, owner_wallet, registered_at, escrow_lamports,
  │     active=true, bump, vault_bump
  │
  ├── Init EscrowVault PDA         seeds: ["escrow", agent_wallet]
  │     SystemAccount, 0 bytes, program-controlled
  │
  ├── CPI system::transfer(owner → escrow_vault, 10_000_000)
  │
  └── emit!(AgentRegistered {
        agent, owner, name, escrow_lamports,
        registration_pda, vault_pda, timestamp
      })
```

---

## Quick Start

```bash
# 1. Prerequisites
rustup update stable
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --tag v0.30.1 --locked
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"

# 2. Setup + build + deploy + test in one command
cd helixor-programs
bash scripts/setup.sh
```

Expected output: `14 passing` for `register_agent.ts` and `5 passing` for `smoke.ts`.

---

## Manual Test

```bash
# Register a real test agent on devnet
ts-node scripts/register_test_agent.ts --agent-number 1 --name "MyFirstAgent"

# View on Solana Explorer (link printed by the script)
```

---

## Account Sizes

| Account | Seeds | Size | Day |
|---------|-------|------|-----|
| `AgentRegistration` | `["agent", agent_wallet]` | 8 + 83 = **91 bytes** | Day 2 |
| `EscrowVault` | `["escrow", agent_wallet]` | 0 + rent_exempt | Day 2 |
| `TrustCertificate` | `["score", agent_wallet]` | 8 + 51 = **59 bytes** | Day 7 |

---

## Test Coverage

```
Group 1: Happy path (5 tests)
  [1] AgentRegistration PDA contains all expected fields
  [2] Escrow vault holds exactly MIN_ESCROW lamports
  [3] Owner balance decreased by (escrow + rent + fee)
  [4] AgentRegistered event emitted with complete payload
  [5] vault_bump in registration PDA matches derived bump

Group 2: Boundary values (3 tests)
  [6] Name exactly 64 bytes accepted
  [7] Name of 1 byte accepted
  [8] UTF-8 emoji name respects byte limit (16× 🤖 = 64 bytes)

Group 3: Error paths (4 tests)
  [9]  Empty name → NameEmpty (6001)
  [10] Name 65 bytes → NameTooLong (6000)
  [11] agent_wallet == owner → AgentSameAsOwner (6003)
  [12] Underfunded owner → system transfer fails

Group 4: PDA correctness (2 tests)
  [13] Two distinct agents get distinct PDAs
  [14] Re-registration of same agent reverts (init constraint)
```

---

## Why These Design Choices

**Native SOL, not USDC** — Avoids SPL token program dependency, USDC mint
setup, and ATA creation. MVP escrow is functionally identical at 0.01 SOL.

**SystemAccount escrow PDA, not TokenAccount** — Simpler. Anchor's `init`
creates it for free; our CPI just funds it. Future versions can add an SPL
vault alongside without touching this one.

**Stored vault_bump in registration** — Saves CU on future withdrawal
instructions (no re-derivation needed).

**Event includes PDAs** — Off-chain indexer registers the Helius webhook
without follow-up RPC calls. Zero round-trips after the registration tx.

**`init` (not `init_if_needed`) on registration** — Anchor's `init`
constraint reverts if the PDA already exists. This prevents
double-registration without an explicit check.

---

## Commands

```bash
anchor build                                    # Build
anchor test --provider.cluster localnet         # Run all tests on localnet
anchor test --provider.cluster devnet --skip-deploy   # Test against devnet
cargo clippy -- -D warnings                     # Lint
cargo fmt --all                                 # Format
cargo audit                                     # CVE scan
ts-node scripts/register_test_agent.ts --agent-number 1 --name "MyAgent"
```

---

*Helixor MVP · Day 2 complete · Next: Day 3 get_health()*
