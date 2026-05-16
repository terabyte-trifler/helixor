"""
tests/baseline/test_migration.py — static checks on 0006_baselines_v2.sql.

These don't need a live database — they verify the migration file itself is
well-formed, idempotent, and contains the safety constructs the design requires.
A full apply-against-Postgres test belongs in the integration suite (Day 13-style).
"""

from __future__ import annotations

from pathlib import Path

import pytest

MIGRATION = Path(__file__).parents[2] / "db" / "migrations" / "0006_baselines_v2.sql"


@pytest.fixture(scope="module")
def sql() -> str:
    assert MIGRATION.exists(), f"migration not found at {MIGRATION}"
    return MIGRATION.read_text()


def test_registers_schema_version_6(sql):
    assert "schema_version" in sql
    assert "(6," in sql
    assert "ON CONFLICT (version) DO NOTHING" in sql

def test_adds_v2_columns_to_agent_baselines(sql):
    for col in (
        "feature_means", "feature_stds", "stats_hash",
        "feature_schema_version", "feature_schema_fingerprint",
        "scoring_schema_fingerprint",
        "baseline_algo_version", "txtype_distribution",
        "action_entropy", "success_rate_30d",
        "transaction_count", "days_with_activity", "is_provisional",
    ):
        assert col in sql, f"migration must reference column {col}"

def test_uses_if_not_exists_for_idempotency(sql):
    # Re-running the migration must be safe.
    assert "ADD COLUMN IF NOT EXISTS" in sql
    assert "CREATE TABLE IF NOT EXISTS" in sql
    assert "CREATE INDEX IF NOT EXISTS" in sql

def test_array_length_check_constraints(sql):
    # The 100-element contract is enforced at the DB level.
    assert "array_length(feature_means, 1) = 100" in sql
    assert "array_length(feature_stds, 1) = 100" in sql
    assert "array_length(txtype_distribution, 1) = 5" in sql

def test_stats_hash_length_constraint(sql):
    assert "char_length(stats_hash) = 64" in sql

def test_scoring_schema_fingerprint_length_constraint(sql):
    assert "agent_baselines_scoring_fp_len" in sql
    assert "char_length(scoring_schema_fingerprint) = 64" in sql

def test_history_table_is_append_only(sql):
    # The append-only trigger must exist.
    assert "reject_baseline_history_mutation" in sql
    assert "BEFORE UPDATE OR DELETE ON agent_baseline_history" in sql
    assert "append-only" in sql.lower()

def test_history_baseline_algo_version_added_for_mvp_upgrade(sql):
    # Fresh MVP tables used algo_version; v2 must add/backfill baseline_algo_version
    # before indexing it.
    assert "ADD COLUMN IF NOT EXISTS baseline_algo_version" in sql
    assert "COALESCE(baseline_algo_version, algo_version, 1)" in sql

def test_history_dedup_constraint(sql):
    # Re-running the same computation must not append a duplicate history row.
    assert "agent_baseline_history_dedup" in sql
    assert "UNIQUE (agent_wallet, stats_hash, window_end)" in sql

def test_legacy_rows_tagged_as_v1(sql):
    # Pre-existing MVP baselines get baseline_algo_version = 1 so the backfill finds them.
    assert "SET baseline_algo_version = 1" in sql

def test_constraints_added_not_valid_for_fast_migration(sql):
    # CHECK constraints use NOT VALID so the migration is fast on a large table.
    assert "NOT VALID" in sql
