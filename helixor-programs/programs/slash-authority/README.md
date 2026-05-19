# slash-authority

Helixor V2's third Anchor program manages staked SOL collateral, tiered slashing, appeals, deferred settlement, and oracle watchdog challenges.

## Verification Status

The local Rust, Solana, and Anchor toolchain is available and has been used for this program. This code is not just written to compile; it has compiled and passed local validator tests.

Verified locally:

```bash
cd helixor-programs
cargo test -p slash-authority
anchor test
```

Current coverage includes:

- `execute_slash` encumbering funds without moving lamports immediately.
- `appeal_slash` moving a pending slash into review.
- `resolve_appeal` overturning or upholding an appeal.
- `settle_slash` moving deferred funds after appeal resolution/window close.
- `challenge_oracle` recording verified conflicting-score challenges and pending off-chain evidence challenges.

Devnet note: the Day 20 `slash_authority` program was deployed and smoke-tested on devnet. Day 21 changes alter the account layout and instruction set, so devnet should be upgraded before claiming Day 21 is live there.
