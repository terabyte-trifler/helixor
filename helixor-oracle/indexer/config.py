"""
indexer/config.py — type-safe configuration loaded from environment.

All env vars are validated at startup. If something's wrong (missing required
key, malformed URL), the process refuses to start instead of crashing on
the first request.
"""

from __future__ import annotations

import re

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = Field(
        ...,
        description="PostgreSQL connection URL: postgresql://user:pw@host:port/db",
    )

    # Connection pool sizing for asyncpg
    db_pool_min: int = Field(default=2,  ge=1, le=20)
    db_pool_max: int = Field(default=10, ge=2, le=100)

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_url: str | None = Field(
        default=None,
        description="Optional Redis URL for shared API rate limiting and score cache.",
    )
    redis_prefix: str = Field(
        default="helixor",
        min_length=1,
        max_length=64,
        description="Key prefix for Redis-backed Helixor API data.",
    )
    rate_limit_capacity: int = Field(default=100, ge=1, le=100_000)
    rate_limit_refill_per_second: float = Field(default=100 / 60, gt=0, le=10_000)
    rate_limit_free_capacity: int = Field(default=300, ge=1, le=1_000_000)
    rate_limit_partner_capacity: int = Field(default=10_000, ge=1, le=1_000_000)
    rate_limit_team_capacity: int = Field(default=50_000, ge=1, le=5_000_000)
    api_key_tier_cache_seconds: int = Field(default=300, ge=1, le=86_400)
    score_cache_ttl_seconds: int = Field(default=60, ge=1, le=86_400)
    negative_cache_ttl_seconds: int = Field(default=30, ge=1, le=3_600)

    # ── Helius ────────────────────────────────────────────────────────────────
    helius_api_key: SecretStr = Field(
        ...,
        description="Helius API key — used for webhook registration + RPC backfill",
    )

    helius_webhook_url: str = Field(
        ...,
        description="Public URL Helius will POST to (e.g. https://oracle.helixor.xyz/webhook)",
    )

    helius_webhook_auth_token: SecretStr = Field(
        ...,
        description="Shared secret. Helius sends this in Authorization header. We verify before processing.",
    )

    # ── Solana ────────────────────────────────────────────────────────────────
    solana_rpc_url: str = Field(
        default="https://api.devnet.solana.com",
        description="Solana RPC for backfill + agent sync",
    )

    health_oracle_program_id: str = Field(
        ...,
        description="Helixor health-oracle program ID — for AgentRegistered event sync",
    )
    oracle_keypair_path: str = Field(
        ...,
        description="Filesystem path to the oracle node keypair JSON used for update_score submissions",
    )

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = Field(default=8000, ge=1024, le=65535)
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")

    # ── Operational ───────────────────────────────────────────────────────────
    # Maximum tx age accepted in webhook (rejects replay attacks of old data)
    max_webhook_tx_age_seconds: int = Field(default=3_600, ge=60)

    # Public API hardening
    api_cors_origins: str = Field(
        default="http://localhost:3000,http://127.0.0.1:3000",
        description="Comma-separated browser origins allowed to call authenticated API routes.",
    )
    monitoring_admin_token: SecretStr | None = Field(
        default=None,
        description="Bearer token required for /monitoring/* operator endpoints.",
    )
    trust_x_forwarded_for: bool = Field(
        default=False,
        description="Only enable when a trusted proxy strips client-supplied X-Forwarded-For.",
    )
    trusted_proxy_ips: str = Field(
        default="127.0.0.1,::1",
        description="Comma-separated proxy IPs allowed to supply X-Forwarded-For.",
    )

    # Reconciler — runs periodically to detect drift between Helius + DB
    reconciler_interval_seconds: int = Field(default=300, ge=60)

    @field_validator("database_url")
    @classmethod
    def _validate_db_url(cls, v: str) -> str:
        if not re.match(r"^postgres(ql)?://", v):
            raise ValueError("database_url must start with postgresql:// or postgres://")
        return v

    @field_validator("redis_url")
    @classmethod
    def _validate_redis_url(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not v.startswith(("redis://", "rediss://")):
            raise ValueError("redis_url must start with redis:// or rediss://")
        return v

    @field_validator("helius_webhook_url")
    @classmethod
    def _validate_webhook_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("helius_webhook_url must be http:// or https://")
        if v.endswith("/"):
            raise ValueError("helius_webhook_url should not end with /")
        return v

    @property
    def database_url_safe(self) -> str:
        """Database URL with password masked — safe to log."""
        return re.sub(r"://[^:]+:[^@]+@", "://***:***@", self.database_url)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.api_cors_origins.split(",") if o.strip()]

    @property
    def trusted_proxy_ip_set(self) -> set[str]:
        return {ip.strip() for ip in self.trusted_proxy_ips.split(",") if ip.strip()}


settings = Settings()  # type: ignore[call-arg]
