"""
helixor-api — the read-side FastAPI service.

This package is the cached, accelerated read path. The on-chain SDK
(helixor-sdk) is the authoritative read; this service reads the same
HealthCertificate data from the indexer's TimescaleDB hypertables and
serves it at high throughput.

ARCHITECTURE
------------
    Solana chain
       ↑ writes (Day 27 threshold-signed certs)
       │
       ├─→ indexer (Day 17) → TimescaleDB hypertables
       │                          │
       │                          └─→ helixor-api ←── HTTP clients
       │                                              (10K req/h target)
       │
       └─→ helixor-sdk (Day 19)   ←── on-chain clients (authoritative)

NO DUPLICATE DATA ACCESS
------------------------
Every read route wraps the existing `TransactionRepository` protocol
(helixor-oracle/db/repository.py) — InMemoryTransactionRepo in tests,
TimescaleTransactionRepo in prod. This service owns no schema and no
SQL; it is a thin shape adapter from the existing read layer to JSON.
"""

from __future__ import annotations

__version__ = "0.1.0"
