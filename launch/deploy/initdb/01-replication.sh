#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE USER ${POSTGRES_REPLICATION_USER:-phylanx_replicator}
    WITH REPLICATION LOGIN PASSWORD '${POSTGRES_REPLICATION_PASSWORD}';
EOSQL

cat >> "$PGDATA/pg_hba.conf" <<-EOF
host replication ${POSTGRES_REPLICATION_USER:-phylanx_replicator} 0.0.0.0/0 scram-sha-256
host all         ${POSTGRES_REPLICATION_USER:-phylanx_replicator} 0.0.0.0/0 scram-sha-256
EOF
