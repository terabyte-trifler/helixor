"""
helixor-oracle / oracle — on-chain interaction layer.

Public API (Day 3):
    submit_baseline_commitment(config, baseline) -> CommitResult
    CommitConfig
    CommitterKind
    decode_agent_registration_v2(data) -> DecodedRegistration
    derive_agent_registration_pda(program_id, agent) -> (pda, bump)
    derive_oracle_config_pda(program_id)             -> (pda, bump)
    CommitBaselineError, StaleNonceError, CommitVerificationError
"""

from oracle.commit_baseline import (
    CommitBaselineError,
    CommitConfig,
    CommitResult,
    CommitVerificationError,
    StaleNonceError,
    derive_agent_registration_pda,
    derive_oracle_config_pda,
    submit_baseline_commitment,
)
from oracle.serialization import (
    AGENT_PDA_SEED,
    AGENT_REGISTRATION_DISCRIMINATOR,
    COMMIT_BASELINE_DISCRIMINATOR,
    MIGRATE_REGISTRATION_DISCRIMINATOR,
    ORACLE_CONFIG_PDA_SEED,
    CommitterKind,
    DecodedRegistration,
    decode_agent_registration_v2,
    encode_commit_baseline_args,
)

__all__ = [
    "submit_baseline_commitment",
    "CommitConfig",
    "CommitResult",
    "CommitterKind",
    "CommitBaselineError",
    "StaleNonceError",
    "CommitVerificationError",
    "derive_agent_registration_pda",
    "derive_oracle_config_pda",
    "decode_agent_registration_v2",
    "encode_commit_baseline_args",
    "DecodedRegistration",
    "AGENT_PDA_SEED",
    "ORACLE_CONFIG_PDA_SEED",
    "COMMIT_BASELINE_DISCRIMINATOR",
    "MIGRATE_REGISTRATION_DISCRIMINATOR",
    "AGENT_REGISTRATION_DISCRIMINATOR",
]
