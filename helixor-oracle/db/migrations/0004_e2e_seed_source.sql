-- Day 10: allow end-to-end harness to seed synthetic transactions.

BEGIN;

ALTER TABLE agent_transactions
  DROP CONSTRAINT IF EXISTS agent_transactions_source_check;

ALTER TABLE agent_transactions
  ADD CONSTRAINT agent_transactions_source_check
  CHECK (source IN ('webhook', 'backfill', 'replay', 'e2e_seed'));

INSERT INTO schema_version(version, description)
VALUES (4, 'Allow e2e_seed transaction source for Day 10 harness')
ON CONFLICT (version) DO NOTHING;

COMMIT;
