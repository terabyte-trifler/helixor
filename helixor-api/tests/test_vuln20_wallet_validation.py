"""
tests/test_vuln20_wallet_validation.py — pin tests for the wallet
validator and its wiring into the API.

WHAT THIS COVERS
----------------
  1. The pure validator (`is_valid_wallet`, `validate_wallet`,
     `ensure_wallet_safe`) — accepts well-shaped base58, rejects every
     known SQLi shape.
  2. The API — every route that accepts a wallet (`/agents/{wallet}/...`,
     `/byzantine/per_node?agent=...`, `/challenges?node=...`) returns
     HTTP 400 on a malformed wallet.

WHY 400 AND NOT 404
-------------------
404 would say "we looked, the agent isn't here." That leaks server-side
state. The validator returns 400 — "the request itself is malformed" —
before the repo is ever queried.
"""

from __future__ import annotations

from urllib.parse import quote

import pytest
from fastapi import HTTPException

from api.validation import (
    BASE58_ALPHABET,
    MAX_WALLET_LENGTH,
    MIN_WALLET_LENGTH,
    WalletValidationError,
    ensure_wallet_safe,
    is_valid_wallet,
    validate_wallet,
)


# A representative well-shaped wallet — 44 chars, only base58.
GOOD_WALLET = "GgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGgGg"
assert len(GOOD_WALLET) == 44


# =============================================================================
# Pure predicate
# =============================================================================

class TestIsValidWallet:

    def test_accepts_44_char_base58(self):
        assert is_valid_wallet(GOOD_WALLET)

    def test_accepts_32_char_lower_bound(self):
        assert is_valid_wallet("1" * MIN_WALLET_LENGTH)

    def test_rejects_31_char_below_bound(self):
        assert not is_valid_wallet("1" * (MIN_WALLET_LENGTH - 1))

    def test_rejects_45_char_above_bound(self):
        assert not is_valid_wallet("1" * (MAX_WALLET_LENGTH + 1))

    def test_rejects_empty(self):
        assert not is_valid_wallet("")

    def test_rejects_non_string(self):
        assert not is_valid_wallet(None)            # type: ignore[arg-type]
        assert not is_valid_wallet(12345)            # type: ignore[arg-type]
        assert not is_valid_wallet(b"x" * 44)        # type: ignore[arg-type]

    @pytest.mark.parametrize("ch", ["0", "O", "I", "l"])
    def test_rejects_ambiguous_chars(self, ch):
        """The Bitcoin base58 alphabet excludes 0/O/I/l on purpose."""
        wallet = ch + ("1" * (MIN_WALLET_LENGTH - 1))
        assert not is_valid_wallet(wallet)

    @pytest.mark.parametrize(
        "payload",
        [
            "'; DROP TABLE agent_transactions; --",            # classic
            "' OR '1'='1",                                      # tautology
            "agentA' UNION SELECT pg_sleep(5)--",               # union+sleep
            "agentA\x00",                                       # NUL splice
            "agentA;agentB",                                    # statement chain
            "agentA\n--",                                       # comment line
            "agentA\\",                                         # backslash escape
            "agentA/*",                                         # block comment
            "agentA\" OR 1=1 \"",                               # double quote
            "agent A",                                          # space
        ],
    )
    def test_rejects_sql_injection_shapes(self, payload):
        assert not is_valid_wallet(payload)

    def test_alphabet_constant_is_a_set_not_a_string(self):
        """`in` on a string is O(n); the implementation MUST use a set."""
        assert isinstance(BASE58_ALPHABET, frozenset)


# =============================================================================
# validate_wallet — FastAPI-style
# =============================================================================

class TestValidateWallet:

    def test_returns_wallet_unchanged_on_success(self):
        assert validate_wallet(GOOD_WALLET) == GOOD_WALLET

    def test_raises_http_400_on_bad(self):
        with pytest.raises(HTTPException) as exc:
            validate_wallet("'; DROP TABLE t; --")
        assert exc.value.status_code == 400
        # The error message names what's wrong — useful for legit clients
        # without leaking server state.
        assert "base58" in str(exc.value.detail).lower() \
            or "wallet" in str(exc.value.detail).lower()


# =============================================================================
# ensure_wallet_safe — library-side
# =============================================================================

class TestEnsureWalletSafe:

    def test_returns_none_on_good(self):
        assert ensure_wallet_safe(GOOD_WALLET) is None

    def test_raises_wallet_validation_error_on_bad(self):
        with pytest.raises(WalletValidationError):
            ensure_wallet_safe("'; DROP TABLE t; --")

    def test_does_not_raise_http_exception(self):
        """The library path must NOT raise HTTPException — it's not a
        FastAPI handler context. Tests pin this to catch a future
        refactor that conflates the two."""
        try:
            ensure_wallet_safe("bad")
        except WalletValidationError:
            pass
        except HTTPException:  # pragma: no cover — pin
            pytest.fail("ensure_wallet_safe leaked an HTTPException")


# =============================================================================
# API wiring — every wallet-bearing route must 400 on a bad wallet
# =============================================================================

# Common SQLi shapes the API must reject at the boundary.
_BAD_WALLETS = [
    "'; DROP TABLE agent_transactions; --",
    "' OR '1'='1",
    "x" * 100,                              # length overflow
    "x" * 10,                               # length underflow
    "agentA OR 1=1",                        # space + keyword
    "agentA\x00",                           # NUL
]


class TestApiRoutesRejectBadWallet:

    @pytest.mark.parametrize("bad", _BAD_WALLETS)
    def test_agent_health_400(self, client, bad):
        # quote() handles NULs / spaces / quotes; the validator runs
        # AFTER FastAPI's URL decoding, which is the realistic flow.
        r = client.get(f"/agents/{quote(bad, safe='')}/health")
        assert r.status_code == 400, r.text

    @pytest.mark.parametrize("bad", _BAD_WALLETS)
    def test_agent_health_at_epoch_400(self, client, bad):
        r = client.get(f"/agents/{quote(bad, safe='')}/health/29")
        assert r.status_code == 400, r.text

    @pytest.mark.parametrize("bad", _BAD_WALLETS)
    def test_agent_history_400(self, client, bad):
        r = client.get(f"/agents/{quote(bad, safe='')}/history")
        assert r.status_code == 400, r.text

    @pytest.mark.parametrize("bad", _BAD_WALLETS)
    def test_byzantine_per_node_400(self, client, bad):
        r = client.get(
            f"/byzantine/per_node?epoch=28&agent={quote(bad, safe='')}",
        )
        assert r.status_code == 400, r.text

    @pytest.mark.parametrize("bad", _BAD_WALLETS)
    def test_challenges_400(self, client, bad):
        r = client.get(f"/challenges?node={quote(bad, safe='')}")
        assert r.status_code == 400, r.text

    def test_known_good_wallet_still_works(self, client):
        # `agentA` from the conftest fixture is not a real wallet, but
        # the API previously accepted any string; this test ensures the
        # validator doesn't accidentally break a route for a known-good
        # base58 wallet that the conftest doesn't populate. We use a
        # synthetic base58 wallet — no fixture data is needed, just the
        # 404 path (wallet shape is fine, but no score recorded).
        r = client.get(f"/agents/{GOOD_WALLET}/health")
        assert r.status_code == 404, r.text


# =============================================================================
# Repository-side guard (defense in depth)
# =============================================================================

class TestRepositoryGuard:
    """The Timescale repo must refuse a bad wallet even though %s binding
    is safe. This pins the defense-in-depth guard."""

    def test_fetch_transactions_refuses_bad_wallet(self):
        pytest.importorskip(
            "db.timescale_repo",
            reason="helixor-oracle not on sys.path; run with PYTHONPATH=.:../helixor-oracle",
        )
        from db.timescale_repo import (
            TimescaleTransactionRepo, WalletValidationError as RepoErr,
        )
        from db.repository import TransactionQuery
        from datetime import datetime, timezone

        class _RecordingConn:
            calls: list = []
            def execute(self, sql, params):
                self.calls.append((sql, params))
                return []

        conn = _RecordingConn()
        repo = TimescaleTransactionRepo(conn)
        q = TransactionQuery(
            agent_wallet="'; DROP TABLE x; --",
            window_start=datetime(2026, 5, 1, tzinfo=timezone.utc),
            window_end=  datetime(2026, 5, 2, tzinfo=timezone.utc),
        )
        with pytest.raises(RepoErr):
            repo.fetch_transactions(q)
        assert conn.calls == [], "the repo must NOT issue a query for a bad wallet"

    def test_fetch_daily_rollup_refuses_bad_wallet(self):
        pytest.importorskip(
            "db.timescale_repo",
            reason="helixor-oracle not on sys.path; run with PYTHONPATH=.:../helixor-oracle",
        )
        from db.timescale_repo import (
            TimescaleTransactionRepo, WalletValidationError as RepoErr,
        )
        from datetime import datetime, timezone

        class _RecordingConn:
            calls: list = []
            def execute(self, sql, params):
                self.calls.append((sql, params))
                return []

        conn = _RecordingConn()
        repo = TimescaleTransactionRepo(conn)
        with pytest.raises(RepoErr):
            repo.fetch_daily_rollup(
                "agentA OR 1=1",
                datetime(2026, 5, 1, tzinfo=timezone.utc),
                datetime(2026, 5, 2, tzinfo=timezone.utc),
            )
        assert conn.calls == []
