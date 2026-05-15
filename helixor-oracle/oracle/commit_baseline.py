"""
oracle/commit_baseline.py — submit a BaselineStats commitment on-chain.

PRODUCTION CODE PATH. This runs on the oracle node every epoch after
baseline computation. Its responsibilities, in order:

  1. Load the oracle keypair from ORACLE_KEYPAIR_PATH (env), never inline.
  2. Build the commit_baseline instruction with the exact correct accounts
     in the exact correct order.
  3. Sign + send the transaction with retry + confirmation.
  4. Read the on-chain AgentRegistration back and assert byte-match with what
     was submitted. Half-submitted state is the worst failure mode.

If step 4 fails, this raises CommitVerificationError — the caller must NOT
treat the commit as durable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

import structlog
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed
from solana.rpc.core import RPCException
from solana.rpc.types import TxOpts
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction

from baseline import BASELINE_ALGO_VERSION, BaselineStats, stats_hash_to_bytes
from oracle.serialization import (
    AGENT_PDA_SEED,
    COMMIT_BASELINE_DISCRIMINATOR,
    ORACLE_CONFIG_PDA_SEED,
    CommitterKind,
    decode_agent_registration_v2,
    encode_commit_baseline_args,
)

log = structlog.get_logger(__name__)


# =============================================================================
# Errors
# =============================================================================

class CommitBaselineError(Exception):
    """Base class for commit_baseline submission errors."""


class CommitVerificationError(CommitBaselineError):
    """The transaction confirmed but the on-chain state does NOT match.

    This is the dangerous case. The caller must not mark the commit as durable
    and must investigate (rare; indicates a serious RPC inconsistency or a bug).
    """


class StaleNonceError(CommitBaselineError):
    """The computed nonce is not strictly greater than on-chain.

    Almost always means a concurrent committer wrote between our nonce read
    and our submit. Caller should re-fetch + retry.
    """


# =============================================================================
# Config
# =============================================================================

@dataclass(frozen=True, slots=True)
class CommitConfig:
    program_id:    Pubkey
    rpc_url:       str
    keypair_path:  Path
    committer_kind: CommitterKind = CommitterKind.ORACLE
    # Retry knobs
    send_max_attempts:    int = 4
    send_retry_base_ms:   int = 500
    confirm_timeout_s:    float = 60.0
    verify_max_attempts:  int = 5

    @classmethod
    def from_env(cls) -> "CommitConfig":
        program = os.environ.get("HELIXOR_PROGRAM_ID")
        rpc     = os.environ.get("SOLANA_RPC_URL")
        kp_path = os.environ.get("ORACLE_KEYPAIR_PATH")
        if not (program and rpc and kp_path):
            missing = [k for k, v in (
                ("HELIXOR_PROGRAM_ID", program),
                ("SOLANA_RPC_URL", rpc),
                ("ORACLE_KEYPAIR_PATH", kp_path),
            ) if not v]
            raise CommitBaselineError(f"missing required env: {', '.join(missing)}")
        return cls(
            program_id   = Pubkey.from_string(program),
            rpc_url      = rpc,
            keypair_path = Path(kp_path),
        )


# =============================================================================
# PDA derivation
# =============================================================================

def derive_agent_registration_pda(program_id: Pubkey, agent_wallet: Pubkey) -> tuple[Pubkey, int]:
    """The AgentRegistration PDA for a given agent."""
    return Pubkey.find_program_address(
        [AGENT_PDA_SEED, bytes(agent_wallet)],
        program_id,
    )


def derive_oracle_config_pda(program_id: Pubkey) -> tuple[Pubkey, int]:
    """The singleton OracleConfig PDA."""
    return Pubkey.find_program_address(
        [ORACLE_CONFIG_PDA_SEED],
        program_id,
    )


# =============================================================================
# Submitter
# =============================================================================

@dataclass(frozen=True, slots=True)
class CommitResult:
    """Result of a successful commit_baseline submission + on-chain verification."""
    tx_signature:   str
    agent_wallet:   str
    baseline_hash:  bytes
    commit_nonce:   int
    committer:      Pubkey
    committed_at:   int      # unix seconds (from on-chain Clock at handler time)


async def submit_baseline_commitment(
    config:        CommitConfig,
    baseline:      BaselineStats,
) -> CommitResult:
    """
    Submit `baseline.stats_hash` on-chain for `baseline.agent_wallet`.

    The function is idempotent at the (agent, hash) level if the off-chain
    caller refrains from bumping the nonce when the current on-chain hash
    already matches. We DO detect that case explicitly here and skip the
    submit when the hash hasn't changed.

    Raises:
      StaleNonceError            — concurrent committer; caller can retry
      CommitVerificationError    — confirmed but on-chain state doesn't match
      CommitBaselineError        — any other submit / RPC failure
    """
    if not baseline.is_compatible_with_current_engine():
        raise CommitBaselineError(
            f"refusing to commit incompatible baseline (algo v{baseline.baseline_algo_version}, "
            f"schema fp {baseline.feature_schema_fingerprint[:12]}...); "
            f"current engine is v{BASELINE_ALGO_VERSION}"
        )

    keypair      = _load_keypair(config.keypair_path)
    agent_pubkey = Pubkey.from_string(baseline.agent_wallet)
    hash_bytes   = stats_hash_to_bytes(baseline.stats_hash)

    agent_pda, _      = derive_agent_registration_pda(config.program_id, agent_pubkey)
    oracle_cfg_pda, _ = derive_oracle_config_pda(config.program_id)

    async with AsyncClient(config.rpc_url) as client:
        # ── 1. Read current state to compute next nonce + early-skip ────────
        current = await _fetch_registration(client, agent_pda)
        if (
            current.baseline_committed
            and current.baseline_hash == hash_bytes
            and current.baseline_algo_version == baseline.baseline_algo_version
        ):
            log.info(
                "commit_baseline_skip_idempotent",
                agent=baseline.agent_wallet[:12],
                reason="on-chain hash already matches",
                commit_nonce=current.commit_nonce,
            )
            return CommitResult(
                tx_signature="",   # no transaction sent
                agent_wallet=baseline.agent_wallet,
                baseline_hash=hash_bytes,
                commit_nonce=current.commit_nonce,
                committer=current.baseline_committer,
                committed_at=current.baseline_committed_at,
            )

        next_nonce = current.commit_nonce + 1

        # ── 2. Build the instruction ────────────────────────────────────────
        ix_data = COMMIT_BASELINE_DISCRIMINATOR + encode_commit_baseline_args(
            baseline_hash=hash_bytes,
            baseline_algo_version=baseline.baseline_algo_version,
            commit_nonce=next_nonce,
            committer_kind=config.committer_kind,
        )

        ix = Instruction(
            program_id=config.program_id,
            accounts=[
                AccountMeta(pubkey=agent_pda,        is_signer=False, is_writable=True),
                AccountMeta(pubkey=oracle_cfg_pda,   is_signer=False, is_writable=False),
                AccountMeta(pubkey=keypair.pubkey(), is_signer=True,  is_writable=False),
            ],
            data=ix_data,
        )

        # ── 3. Send with retry + confirmation ───────────────────────────────
        tx_sig = await _send_and_confirm(client, keypair, ix, config)

        # ── 4. Read-back verification: byte-match on-chain ↔ submitted ─────
        verified = await _verify_committed(
            client, agent_pda, hash_bytes,
            baseline.baseline_algo_version, next_nonce,
            keypair.pubkey(),
            max_attempts=config.verify_max_attempts,
        )

        log.info(
            "commit_baseline_ok",
            agent=baseline.agent_wallet[:12],
            tx=tx_sig[:16],
            commit_nonce=next_nonce,
            hash=hash_bytes.hex()[:16],
        )

        return CommitResult(
            tx_signature=tx_sig,
            agent_wallet=baseline.agent_wallet,
            baseline_hash=hash_bytes,
            commit_nonce=next_nonce,
            committer=keypair.pubkey(),
            committed_at=verified.baseline_committed_at,
        )


# =============================================================================
# Helpers — keypair, RPC, send/confirm/verify
# =============================================================================

def _load_keypair(path: Path) -> Keypair:
    """Load a Solana keypair from a JSON byte array (the standard Solana CLI format)."""
    import json
    try:
        raw = path.read_text()
    except FileNotFoundError as e:
        raise CommitBaselineError(f"keypair file not found at {path}") from e
    try:
        nums = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CommitBaselineError(f"keypair file is not valid JSON: {e}") from e
    if not isinstance(nums, list) or len(nums) != 64:
        raise CommitBaselineError(
            f"keypair file must be a JSON array of 64 bytes, got {type(nums).__name__} of len "
            f"{len(nums) if hasattr(nums, '__len__') else '?'}"
        )
    return Keypair.from_bytes(bytes(nums))


async def _fetch_registration(client: AsyncClient, agent_pda: Pubkey):
    """Fetch + decode the current AgentRegistration."""
    resp = await client.get_account_info(agent_pda, commitment=Confirmed)
    if resp.value is None:
        raise CommitBaselineError(
            f"AgentRegistration PDA {agent_pda} not found — agent not registered?"
        )
    return decode_agent_registration_v2(bytes(resp.value.data))


async def _send_and_confirm(
    client: AsyncClient,
    payer:  Keypair,
    ix:     Instruction,
    config: CommitConfig,
) -> str:
    """Build, sign, send + confirm a single-instruction transaction with retry."""
    last_err: Exception | None = None
    for attempt in range(config.send_max_attempts):
        try:
            recent = await client.get_latest_blockhash(commitment=Confirmed)
            blockhash: Hash = recent.value.blockhash
            msg = MessageV0.try_compile(
                payer=payer.pubkey(),
                instructions=[ix],
                address_lookup_table_accounts=[],
                recent_blockhash=blockhash,
            )
            tx = VersionedTransaction(msg, [payer])

            send_resp = await client.send_transaction(
                tx,
                opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed),
            )
            sig = str(send_resp.value)
            await client.confirm_transaction(
                send_resp.value, commitment=Confirmed,
                sleep_seconds=0.5,
                last_valid_block_height=recent.value.last_valid_block_height,
            )
            return sig

        except RPCException as e:
            # Anchor's custom error 6020 = NonMonotonicNonce → caller should refetch + retry.
            msg = str(e)
            if "6020" in msg or "NonMonotonicNonce" in msg:
                raise StaleNonceError(msg) from e
            last_err = e
        except Exception as e:  # noqa: BLE001 — retry transport-level failures
            last_err = e

        backoff = config.send_retry_base_ms * (2 ** attempt) / 1000
        log.warning("commit_baseline_retry",
                    attempt=attempt + 1, backoff_s=backoff, error=str(last_err)[:200])
        await asyncio.sleep(backoff)

    raise CommitBaselineError(
        f"failed to send/confirm after {config.send_max_attempts} attempts: {last_err}"
    ) from last_err


async def _verify_committed(
    client:                AsyncClient,
    agent_pda:             Pubkey,
    expected_hash:         bytes,
    expected_algo_version: int,
    expected_nonce:        int,
    expected_committer:    Pubkey,
    *,
    max_attempts:          int,
) -> "DecodedRegistration":
    """
    Read the AgentRegistration back and assert byte-match. RPC consistency
    means we may need to retry a couple of times; that's expected.
    """
    last_decoded = None
    for attempt in range(max_attempts):
        decoded = await _fetch_registration(client, agent_pda)
        last_decoded = decoded
        match = (
            decoded.baseline_committed
            and decoded.baseline_hash == expected_hash
            and decoded.baseline_algo_version == expected_algo_version
            and decoded.commit_nonce == expected_nonce
            and decoded.baseline_committer == expected_committer
        )
        if match:
            return decoded
        await asyncio.sleep(0.3 * (attempt + 1))

    raise CommitVerificationError(
        f"on-chain registration does NOT match submitted commit after {max_attempts} reads. "
        f"on-chain: nonce={last_decoded.commit_nonce}, "
        f"hash={last_decoded.baseline_hash.hex()[:16]}..., "
        f"committer={last_decoded.baseline_committer}; "
        f"expected: nonce={expected_nonce}, hash={expected_hash.hex()[:16]}..., "
        f"committer={expected_committer}"
    )


# Forward-declare for type checking
from oracle.serialization import DecodedRegistration  # noqa: E402  (used in type hints above)
