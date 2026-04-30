# Regression tests

One file per fixed bug. Pattern: `R{date}_{short_slug}.test.ts`.

## Adding a regression test

When a bug is found in production:

1. **Reproduce it** in a regression test that fails on the buggy code path
2. **Name it** `R{YYYY-MM-DD}_{slug}.test.ts`
3. **Document** the bug at the top of the file: what was broken, what fixed it
4. **Land the fix** in the same PR — the test goes from failing to passing

The regressions suite then runs in CI alongside the main tests. We never
remove regression tests — old ones remain valuable as armor against
regressions of regressions.

## Naming examples

```
R2026-04-29_baseline_emoji_byte_count.test.ts
R2026-05-03_score_clamp_overflow_at_1001.test.ts
R2026-05-12_pool_exhausted_on_concurrent_writes.test.ts
```

## Running

```bash
npm run test:regressions          # all regressions
npx vitest tests/integration/regressions/R2026-04-29_*.test.ts  # one
```
