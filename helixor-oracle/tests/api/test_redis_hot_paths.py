from __future__ import annotations

import time

import pytest

from api import redis_client
from api.rate_limit import _consume_redis
from api.schemas import ScoreResponse
from api.service import ScoreService


class FakeRedis:
    def __init__(self):
        self.values: dict[str, str] = {}
        self.expires: dict[str, int] = {}
        self.eval_calls = 0

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.values[key] = value
        self.expires[key] = ttl

    async def delete(self, key: str) -> None:
        self.values.pop(key, None)

    async def exists(self, key: str) -> int:
        return 1 if key in self.values else 0

    async def eval(self, *args):
        self.eval_calls += 1
        return 1


@pytest.fixture
def fake_redis(monkeypatch):
    client = FakeRedis()
    monkeypatch.setattr(redis_client, "_redis", client)
    yield client
    monkeypatch.setattr(redis_client, "_redis", None)


@pytest.mark.asyncio
async def test_score_cache_round_trips_through_redis(fake_redis):
    service = ScoreService()
    response = ScoreResponse(
        agent_wallet="AGENT11111111111111111111111111111111111111",
        score=850,
        alert="GREEN",
        source="live",
        success_rate=97.0,
        anomaly_flag=False,
        updated_at=int(time.time()),
        is_fresh=True,
        breakdown=None,
        served_at=int(time.time()),
        cached=False,
    )

    await service._redis_set_score(response.agent_wallet, response)
    cached = await service._redis_get_score(response.agent_wallet)

    assert cached is not None
    assert cached.agent_wallet == response.agent_wallet
    assert cached.score == 850
    assert fake_redis.expires["helixor:score:AGENT11111111111111111111111111111111111111"] == 60


@pytest.mark.asyncio
async def test_negative_cache_marks_unknown_agent(fake_redis):
    service = ScoreService()
    agent = "UNKNOWN111111111111111111111111111111111111"

    await service._redis_set_missing(agent)

    assert await service._redis_has_missing(agent) is True
    assert fake_redis.expires[f"helixor:score_missing:{agent}"] == 30


@pytest.mark.asyncio
async def test_rate_limit_uses_redis_bucket(fake_redis):
    allowed = await _consume_redis("203.0.113.10")

    assert allowed is True
    assert fake_redis.eval_calls == 1
