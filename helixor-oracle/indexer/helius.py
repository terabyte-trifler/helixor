"""
indexer/helius.py — async Helius API client.

Wraps:
  - POST   /v0/webhooks                     — register webhook
  - PUT    /v0/webhooks/{webhookID}         — update accountAddresses list
  - DELETE /v0/webhooks/{webhookID}         — remove
  - GET    /v0/webhooks                     — list (used by reconciler)

Why a custom client instead of using requests + sync calls:
  1. Async — doesn't block the FastAPI event loop
  2. Retries — Helius API has occasional 5xx; we retry with backoff
  3. Timeouts — never wait forever for a slow call
"""

from __future__ import annotations

import asyncio
import structlog
from typing import Any

import httpx

from indexer.config import settings

log = structlog.get_logger(__name__)

HELIUS_API_BASE = "https://api.helius.xyz"


class HeliusError(Exception):
    """Raised on persistent Helius API failures."""
    pass


class HeliusClient:
    """Single shared instance, used by webhook_registrar and reconciler."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=10.0, pool=5.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        max_retries: int = 3,
    ) -> Any:
        """One HTTP request with exponential backoff on 5xx + transient errors."""
        api_key = settings.helius_api_key.get_secret_value()
        url     = f"{HELIUS_API_BASE}{path}?api-key={api_key}"

        last_error: Exception | None = None
        for attempt in range(max_retries):
            try:
                resp = await self._client.request(method, url, json=json_body)

                # 4xx — caller error, don't retry
                if 400 <= resp.status_code < 500:
                    log.error(
                        "helius client error",
                        status=resp.status_code,
                        body=resp.text[:500],
                    )
                    raise HeliusError(f"{method} {path} → {resp.status_code}: {resp.text[:200]}")

                # 5xx — transient, retry
                if resp.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"server error {resp.status_code}",
                        request=resp.request, response=resp,
                    )

                return resp.json() if resp.text else None

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPStatusError) as e:
                last_error = e
                wait = 2 ** attempt  # 1s, 2s, 4s
                log.warning(
                    "helius retry",
                    attempt=attempt + 1, max_retries=max_retries,
                    error=str(e), wait_seconds=wait,
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(wait)

        raise HeliusError(f"{method} {path} failed after {max_retries} retries: {last_error}")

    # ── Public API ────────────────────────────────────────────────────────────

    async def create_webhook(
        self,
        agent_wallet: str,
    ) -> str:
        """Register a webhook for a single agent. Returns webhookID."""
        result = await self._request(
            "POST",
            "/v0/webhooks",
            json_body={
                "webhookURL":       settings.helius_webhook_url,
                "transactionTypes": ["Any"],
                "accountAddresses": [agent_wallet],
                "webhookType":      "enhanced",
                "authHeader":       settings.helius_webhook_auth_token.get_secret_value(),
            },
        )
        webhook_id = result.get("webhookID")
        if not webhook_id:
            raise HeliusError(f"Helius response missing webhookID: {result}")
        return webhook_id

    async def list_webhooks(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/v0/webhooks") or []

    async def delete_webhook(self, webhook_id: str) -> None:
        await self._request("DELETE", f"/v0/webhooks/{webhook_id}")

    async def update_webhook_addresses(
        self,
        webhook_id: str,
        addresses: list[str],
    ) -> None:
        """Atomically replace the address list on an existing webhook."""
        await self._request(
            "PUT",
            f"/v0/webhooks/{webhook_id}",
            json_body={
                "webhookURL":       settings.helius_webhook_url,
                "transactionTypes": ["Any"],
                "accountAddresses": addresses,
                "webhookType":      "enhanced",
                "authHeader":       settings.helius_webhook_auth_token.get_secret_value(),
            },
        )
