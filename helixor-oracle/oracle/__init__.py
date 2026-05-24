"""
helixor-oracle / oracle — public package exports.

Keep this package initializer deliberately light. Day 30's mainnet
refusal gate is imported as `oracle.network_guard` by multiple services
before they are allowed to touch RPC, keypairs, or submission code. If
`__init__` eagerly imports the on-chain submitter, the guard drags in
Solana/structlog dependencies and can fail before it gets to refuse
mainnet. Public exports below are loaded lazily on first access.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORTS: dict[str, tuple[str, str]] = {
    # commit_baseline.py
    "submit_baseline_commitment": ("oracle.commit_baseline", "submit_baseline_commitment"),
    "CommitConfig": ("oracle.commit_baseline", "CommitConfig"),
    "CommitResult": ("oracle.commit_baseline", "CommitResult"),
    "CommitBaselineError": ("oracle.commit_baseline", "CommitBaselineError"),
    "StaleNonceError": ("oracle.commit_baseline", "StaleNonceError"),
    "CommitVerificationError": ("oracle.commit_baseline", "CommitVerificationError"),
    "derive_agent_registration_pda": ("oracle.commit_baseline", "derive_agent_registration_pda"),
    "derive_oracle_config_pda": ("oracle.commit_baseline", "derive_oracle_config_pda"),
    # serialization.py
    "AGENT_PDA_SEED": ("oracle.serialization", "AGENT_PDA_SEED"),
    "AGENT_REGISTRATION_DISCRIMINATOR": (
        "oracle.serialization",
        "AGENT_REGISTRATION_DISCRIMINATOR",
    ),
    "COMMIT_BASELINE_DISCRIMINATOR": (
        "oracle.serialization",
        "COMMIT_BASELINE_DISCRIMINATOR",
    ),
    "MIGRATE_REGISTRATION_DISCRIMINATOR": (
        "oracle.serialization",
        "MIGRATE_REGISTRATION_DISCRIMINATOR",
    ),
    "ORACLE_CONFIG_PDA_SEED": ("oracle.serialization", "ORACLE_CONFIG_PDA_SEED"),
    "CommitterKind": ("oracle.serialization", "CommitterKind"),
    "DecodedRegistration": ("oracle.serialization", "DecodedRegistration"),
    "decode_agent_registration_v2": ("oracle.serialization", "decode_agent_registration_v2"),
    "encode_commit_baseline_args": ("oracle.serialization", "encode_commit_baseline_args"),
    # epoch_runner.py
    "run_epoch": ("oracle.epoch_runner", "run_epoch"),
    "score_agent": ("oracle.epoch_runner", "score_agent"),
    "AgentEpochInput": ("oracle.epoch_runner", "AgentEpochInput"),
    "AgentEpochResult": ("oracle.epoch_runner", "AgentEpochResult"),
    "EpochReport": ("oracle.epoch_runner", "EpochReport"),
    "make_onchain_submitter": ("oracle.epoch_runner", "make_onchain_submitter"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        module_name, attr_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value
