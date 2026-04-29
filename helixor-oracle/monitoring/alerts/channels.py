"""
monitoring/alerts/channels.py — alert delivery channels.

Each channel implements `async send(decision)` and returns True on success.

Supported:
  - LogChannel       (always — structured log line)
  - TelegramChannel  (when HELIXOR_TELEGRAM_BOT_TOKEN + HELIXOR_TELEGRAM_CHAT_ID set)
  - StdoutChannel    (fallback for local dev)

Delivery is best-effort. Failures are logged but never raised — a flaky
Telegram API shouldn't take down the monitoring service.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx
import structlog

from monitoring.alert_state import AlertDecision

log = structlog.get_logger(__name__)


SEVERITY_EMOJI = {
    "info":     "ℹ️",
    "warning":  "⚠️",
    "critical": "🚨",
}


class Channel(ABC):
    name: str

    @abstractmethod
    async def send(self, decision: AlertDecision) -> bool: ...


# ─────────────────────────────────────────────────────────────────────────────
# Log channel — always on, lightweight, no external dependencies
# ─────────────────────────────────────────────────────────────────────────────

class LogChannel(Channel):
    name = "log"

    async def send(self, d: AlertDecision) -> bool:
        log.warning(
            "monitoring_alert",
            severity=d.severity,
            title=d.title,
            body=d.body,
            is_new=d.is_new,
            is_resolution=d.is_resolution,
            fire_count=d.fire_count,
        )
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Stdout (developer ergonomics)
# ─────────────────────────────────────────────────────────────────────────────

class StdoutChannel(Channel):
    name = "stdout"

    async def send(self, d: AlertDecision) -> bool:
        emoji = SEVERITY_EMOJI.get(d.severity, "•")
        prefix = ("RESOLVED" if d.is_resolution
                  else "NEW"   if d.is_new
                  else f"REPEAT×{d.fire_count}")
        print(f"\n{emoji} [{d.severity.upper()}] [{prefix}] {d.title}\n  {d.body}\n")
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — official Bot API. Uses long-lived token + numeric chat ID.
# Setup: https://core.telegram.org/bots#how-do-i-create-a-bot
# ─────────────────────────────────────────────────────────────────────────────

class TelegramChannel(Channel):
    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id   = chat_id

    @classmethod
    def from_env(cls) -> "TelegramChannel | None":
        token   = os.environ.get("HELIXOR_TELEGRAM_BOT_TOKEN")
        chat_id = os.environ.get("HELIXOR_TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            return None
        return cls(bot_token=token, chat_id=chat_id)

    async def send(self, d: AlertDecision) -> bool:
        emoji = SEVERITY_EMOJI.get(d.severity, "•")
        prefix = ("✅ RESOLVED" if d.is_resolution
                  else "🆕 NEW"   if d.is_new
                  else f"🔁 REPEAT ({d.fire_count}×)")
        text = (
            f"{emoji} *Helixor* — {prefix}\n"
            f"*{d.title}*\n\n"
            f"`{d.body}`"
        )

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                r = await http.post(url, json={
                    "chat_id":    self.chat_id,
                    "text":       text,
                    "parse_mode": "Markdown",
                })
            if r.status_code == 200:
                return True
            log.error("telegram_alert_failed",
                      status_code=r.status_code, body=r.text[:200])
            return False
        except Exception as e:
            log.error("telegram_alert_exception", error=str(e))
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Multi-delivery — fan out to all configured channels, collect outcomes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DeliveryReport:
    delivered_to: tuple[str, ...]
    failed:       tuple[str, ...]


class MultiChannel:
    def __init__(self, channels: list[Channel]):
        self.channels = channels

    @classmethod
    def from_env(cls) -> "MultiChannel":
        channels: list[Channel] = [LogChannel(), StdoutChannel()]
        tg = TelegramChannel.from_env()
        if tg:
            channels.append(tg)
            log.info("telegram_channel_enabled")
        return cls(channels)

    async def deliver(self, decision: AlertDecision) -> DeliveryReport:
        delivered: list[str] = []
        failed:    list[str] = []
        for ch in self.channels:
            try:
                ok = await ch.send(decision)
                (delivered if ok else failed).append(ch.name)
            except Exception as e:
                log.error("channel_send_threw", channel=ch.name, error=str(e))
                failed.append(ch.name)
        return DeliveryReport(tuple(delivered), tuple(failed))
