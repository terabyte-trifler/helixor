# Day 5 Installation — Building on Day 4

This zip contains only the **new files** for Day 5. Drop them into your
existing Day 4 `helixor-oracle/` directory.

## What's in this zip

```
scoring/
├── __init__.py
├── signals.py
├── repo.py
├── baseline_engine.py
└── scheduler.py

db/migrations/
└── 0002_baselines.sql

tests/scoring/
├── __init__.py
├── test_signals.py
└── test_baseline_engine.py

scripts/
├── __init__.py
├── compute_baseline.py
└── seed_baseline_test_data.py

docker-compose.yml      ← REPLACES Day 4's version (adds baseline_scheduler)
README.md               ← documents Day 5 additions
```

## What to do

1. Unzip into your existing `helixor-oracle/` directory.
2. Replace `docker-compose.yml` with the new one (adds `baseline_scheduler`).
3. Run the migration:
   ```bash
   docker compose exec -T postgres psql -U helixor -d helixor < db/migrations/0002_baselines.sql
   ```
   Or restart Postgres — the migration is mounted into the entrypoint folder
   and will run automatically on a fresh database.
4. Run the Day 5 setup script:
   ```bash
   bash scripts/setup.sh
   ```

## Dependencies

Day 5 reuses the same `requirements.txt` as Day 4. No new packages.

## Compatibility

`scoring/repo.py` and `scoring/baseline_engine.py` import from `indexer/db.py`
and `indexer/config.py` — both already exist from Day 4.

`tests/scoring/test_baseline_engine.py` reuses the `db_pool` and
`seeded_agent` fixtures from `tests/conftest.py` — no changes needed there.
