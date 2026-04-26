# Day 6 Installation — Building on Day 5

This zip contains only the **new files** for Day 6. Drop them into your
existing Day 5 `helixor-oracle/` directory.

## What's in this zip

```
scoring/
├── window.py                 ← NEW: 7-day window stats
├── engine.py                 ← NEW: pure scoring math
├── score_repo.py             ← NEW: async DB layer
└── score_engine.py           ← NEW: orchestrator

db/migrations/
└── 0003_scores.sql           ← NEW: agent_scores + history

tests/scoring/
├── test_engine.py            ← NEW: 40+ unit tests
├── test_window.py            ← NEW: window stat tests
└── test_score_engine.py      ← NEW: 11 integration tests

scripts/
└── compute_score.py          ← NEW: Day 6 CLI

README.md                     ← UPDATED for Day 6
```

## What to do

1. Unzip into your existing `helixor-oracle/` directory.
2. Run the migration:
   ```bash
   docker compose exec -T postgres psql -U helixor -d helixor < db/migrations/0003_scores.sql
   ```
3. Run the Day 6 setup script:
   ```bash
   bash scripts/setup.sh
   ```

## Dependencies

Day 6 reuses the same `requirements.txt` as Days 4-5. No new packages.

## Compatibility

`scoring/engine.py` imports from `scoring/signals.py` (Day 5) and
`scoring/window.py` (Day 6). `scoring/score_engine.py` imports from
`scoring/baseline_engine.py` (Day 5) and `scoring/repo.py` (Day 5).

`tests/scoring/test_score_engine.py` reuses the `db_pool` and
`seeded_agent` fixtures from `tests/conftest.py` — no changes needed there.
