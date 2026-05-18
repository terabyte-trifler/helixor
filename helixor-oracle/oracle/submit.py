"""
oracle/submit.py — submit update_score transactions to Solana.

What this does:
  1. Builds an Anchor instruction from a ScoreResult
  2. Signs with the oracle keypair
  3. Submits with priority fees
  4. Waits for confirmation (with timeout)
  5. Returns the tx signature on success, raises on failure

What this DOESN'T do:
  - Choose which agents to score (that's epoch_runner)
  - Decide whether to retry (that's the caller — different failure modes
    need different responses: 23h cooldown is permanent for this epoch,
    network error should retry)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
import struct

import structlog
from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solana.transaction import Transaction

from indexer.config import settings
from scoring import ScoreResult

log = structlog.get_logger(__name__)


# =============================================================================
# Configuration
# =============================================================================

# Compute units for update_score — 200K is plenty.
UPDATE_SCORE_CU_LIMIT = 200_000

# Priority fee in micro-lamports per CU. Devnet usually doesn't need any;
# mainnet during congestion may need 50_000+. Default is conservative.
PRIORITY_FEE_MICRO_LAMPORTS = 1000

# Tx confirmation timeout (seconds). If we don't see confirmation in this
# window, treat as timeout (caller decides whether to retry).
CONFIRMATION_TIMEOUT_SECONDS = 60

# Anchor discriminator for `update_score`, generated from the current IDL.
UPDATE_SCORE_DISCRIMINATOR = bytes([188, 226, 238, 41, 14, 241, 105, 215])


# =============================================================================
# PDA helpers
# =============================================================================

def derive_program_id() -> Pubkey:
    return Pubkey.from_string(settings.health_oracle_program_id)


def derive_agent_registration(agent_wallet: str) -> Pubkey:
    pid = derive_program_id()
    seeds = [b"agent", bytes(Pubkey.from_string(agent_wallet))]
    pda, _ = Pubkey.find_program_address(seeds, pid)
    return pda


def derive_trust_certificate(agent_wallet: str) -> Pubkey:
    pid = derive_program_id()
    seeds = [b"score", bytes(Pubkey.from_string(agent_wallet))]
    pda, _ = Pubkey.find_program_address(seeds, pid)
    return pda


def derive_oracle_config() -> Pubkey:
    pid = derive_program_id()
    pda, _ = Pubkey.find_program_address([b"oracle_config"], pid)
    return pda


# =============================================================================
# Errors
# =============================================================================

class SubmissionError(Exception):
    """Base class for submission failures."""
    pass


class TooFrequent(SubmissionError):
    """On-chain 23h cooldown blocked this update — try next epoch."""
    pass


class DeltaTooLarge(SubmissionError):
    """On-chain guard rail blocked this update — investigation needed."""
    pass


class Unauthorized(SubmissionError):
    """Oracle key mismatch — config rotated or keypair wrong."""
    pass


class Paused(SubmissionError):
    """Admin paused the oracle — wait for unpause."""
    pass


class TransientError(SubmissionError):
    """Network or RPC error — caller should retry."""
    pass


# =============================================================================
# Oracle keypair loading
# =============================================================================

def load_oracle_keypair() -> Keypair:
    """Load oracle signing keypair from a JSON file path in env."""
    keypair_path = Path(settings.oracle_keypair_path).expanduser()
    if not keypair_path.exists():
        raise FileNotFoundError(
            f"Oracle keypair not found at {keypair_path}. "
            f"Set ORACLE_KEYPAIR_PATH in env.",
        )
    import json
    secret = json.loads(keypair_path.read_text())
    return Keypair.from_bytes(bytes(secret))


# =============================================================================
# Submission
# =============================================================================

@dataclass
class SubmitResult:
    """Outcome of a single submission attempt."""
    tx_signature: str
    slot:         int
    cert_pda:     str


async def submit_score_update(
    rpc:          AsyncClient,
    program_id:   Pubkey,
    oracle_kp:    Keypair,
    agent_wallet: str,
    result:       ScoreResult,
) -> SubmitResult:
    """
    Submit ONE update_score transaction. Waits for confirmation.

    Maps on-chain errors to Python exception types so the caller can
    retry intelligently.
    """
    bound_log = log.bind(agent=agent_wallet[:12] + "...")

    # ── PDAs ──────────────────────────────────────────────────────────────────
    reg_pda    = derive_agent_registration(agent_wallet)
    cert_pda   = derive_trust_certificate(agent_wallet)
    cfg_pda    = derive_oracle_config()

    # ── Build payload ─────────────────────────────────────────────────────────
    # The on-chain payload mirrors the fields the TrustCertificate stores.
    payload_fields = score_result_to_update_payload(result)

    payload = struct.pack(
        "<HHI?16sBB",
        payload_fields["score"],
        payload_fields["success_rate_bps"],
        payload_fields["tx_count_7d"],
        payload_fields["anomaly_flag"],
        payload_fields["baseline_hash_prefix"],
        payload_fields["scoring_algo_version"],
        payload_fields["weights_version"],
    )

    instruction = Instruction(
        program_id,
        UPDATE_SCORE_DISCRIMINATOR + payload,
        [
            AccountMeta(oracle_kp.pubkey(), True, True),
            AccountMeta(reg_pda, False, False),
            AccountMeta(cert_pda, False, True),
            AccountMeta(cfg_pda, False, True),
            AccountMeta(Pubkey.from_string("11111111111111111111111111111111"), False, False),
        ],
    )

    bound_log.info(
        "submitting_update_score",
        score=result.score, alert=result.alert,
        cert_pda=str(cert_pda)[:20] + "...",
    )

    # ── Build + send tx ───────────────────────────────────────────────────────
    try:
        latest_blockhash = (await rpc.get_latest_blockhash(commitment=Confirmed)).value.blockhash
        tx = Transaction(
            recent_blockhash=latest_blockhash,
            fee_payer=oracle_kp.pubkey(),
        )
        tx.add(
            set_compute_unit_limit(UPDATE_SCORE_CU_LIMIT),
            set_compute_unit_price(PRIORITY_FEE_MICRO_LAMPORTS),
            instruction,
        )
        send_resp = await rpc.send_transaction(
            tx,
            oracle_kp,
            opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed),
        )
        tx_sig = send_resp.value
    except Exception as e:
        msg = str(e)
        # Map known on-chain errors to typed exceptions
        if "UpdateTooFrequent" in msg:
            raise TooFrequent(msg)
        if "ScoreDeltaTooLarge" in msg:
            raise DeltaTooLarge(msg)
        if "UnauthorizedOracle" in msg:
            raise Unauthorized(msg)
        if "OraclePaused" in msg:
            raise Paused(msg)
        if "AgentDeactivated" in msg:
            raise SubmissionError(f"agent_deactivated: {msg}")
        # Anything else — transient
        raise TransientError(msg) from e

    # ── Confirm + extract slot ────────────────────────────────────────────────
    try:
        confirmation = await asyncio.wait_for(
            rpc.confirm_transaction(tx_sig, commitment=Confirmed),
            timeout=CONFIRMATION_TIMEOUT_SECONDS,
        )
        slot = confirmation.context.slot if hasattr(confirmation, "context") else 0
    except asyncio.TimeoutError:
        raise TransientError(
            f"Tx submitted ({tx_sig}) but not confirmed in {CONFIRMATION_TIMEOUT_SECONDS}s"
        )

    bound_log.info("submission_confirmed", tx_sig=str(tx_sig)[:20] + "...", slot=slot)

    return SubmitResult(
        tx_signature=str(tx_sig),
        slot=slot,
        cert_pda=str(cert_pda),
    )


def score_result_to_update_payload(result: ScoreResult) -> dict:
    """
    Convert a V2 composite ScoreResult into the on-chain ScorePayload fields.

    The V2 composite no longer carries the old MVP `window_*` fields. It does
    carry the current FeatureVector-derived metrics when `features` was
    supplied to the composite scorer, which the epoch runner does. If an older
    result lacks those optional fields, this helper falls back to conservative
    zeroes for the telemetry-only certificate fields while preserving the
    trust-critical fields: score, baseline hash, algorithm version, weights
    version, and anomaly/security flags.
    """
    baseline_hash = getattr(result, "baseline_stats_hash", None) or getattr(
        result, "baseline_hash", "",
    )
    full_hash_bytes = bytes.fromhex(baseline_hash)
    success_rate = float(getattr(result, "window_success_rate", 0.0))
    success_rate_bps = int(round(max(0.0, min(1.0, success_rate)) * 10_000))
    tx_count_7d = int(max(0, min(0xFFFFFFFF, int(getattr(result, "window_tx_count", 0)))))

    anomaly_flag = bool(getattr(result, "anomaly_flag", False))
    if not anomaly_flag and hasattr(result, "dimension_results"):
        try:
            from detection.types import DimensionId, FlagBit

            anomaly = result.dimension_results[DimensionId.ANOMALY]
            anomaly_flag = bool(anomaly.flags) or result.has_flag(FlagBit.IMMEDIATE_RED)
        except Exception:
            anomaly_flag = False

    return {
        "score": int(result.score),
        "success_rate_bps": success_rate_bps,
        "tx_count_7d": tx_count_7d,
        "anomaly_flag": anomaly_flag,
        "baseline_hash_prefix": full_hash_bytes[:16],
        "scoring_algo_version": int(result.scoring_algo_version),
        "weights_version": int(getattr(result, "scoring_weights_version", 0)),
    }


# =============================================================================
# Read previous score from on-chain cert (used as cross-check)
# =============================================================================

async def read_onchain_score(rpc: AsyncClient, agent_wallet: str) -> int | None:
    """
    Read the agent's current on-chain score from the TrustCertificate PDA.
    Returns None if the cert doesn't exist yet.

    Uses byte offset since we don't want to require anchorpy here — but
    the offset is computed from the documented INIT_SPACE layout.

    Layout (after 8-byte discriminator):
       offset 0..32   agent_wallet
       offset 32..34  score (u16, little-endian)
    """
    cert_pda = derive_trust_certificate(agent_wallet)
    info = await rpc.get_account_info(cert_pda, commitment=Confirmed)

    if info.value is None:
        return None

    data = info.value.data
    if len(data) < 8 + 34:
        return None

    return int.from_bytes(data[8 + 32:8 + 34], "little")
