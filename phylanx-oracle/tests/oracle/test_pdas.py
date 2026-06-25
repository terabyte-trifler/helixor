"""
tests/oracle/test_pdas.py — PDA derivation must be deterministic + match Anchor seeds.
"""

from __future__ import annotations

from solders.pubkey import Pubkey

from oracle import (
    AGENT_PDA_SEED,
    ORACLE_CONFIG_PDA_SEED,
    derive_agent_registration_pda,
    derive_oracle_config_pda,
)

PROGRAM_ID = Pubkey.from_string("Hex1xor111111111111111111111111111111111111")


class TestAgentRegistrationPda:

    def test_seeds_are_b_agent_then_wallet(self):
        # Sanity: the constant matches what the Anchor program uses.
        assert AGENT_PDA_SEED == b"agent"

    def test_deterministic_for_same_inputs(self):
        agent = Pubkey.from_string("11111111111111111111111111111112")
        pda1, b1 = derive_agent_registration_pda(PROGRAM_ID, agent)
        pda2, b2 = derive_agent_registration_pda(PROGRAM_ID, agent)
        assert pda1 == pda2
        assert b1 == b2

    def test_different_agents_different_pdas(self):
        a1 = Pubkey.from_string("11111111111111111111111111111112")
        a2 = Pubkey.from_string("11111111111111111111111111111113")
        p1, _ = derive_agent_registration_pda(PROGRAM_ID, a1)
        p2, _ = derive_agent_registration_pda(PROGRAM_ID, a2)
        assert p1 != p2

    def test_different_program_ids_different_pdas(self):
        agent = Pubkey.from_string("11111111111111111111111111111112")
        other = Pubkey.from_string("11111111111111111111111111111113")
        p1, _ = derive_agent_registration_pda(PROGRAM_ID, agent)
        p2, _ = derive_agent_registration_pda(other, agent)
        assert p1 != p2


class TestOracleConfigPda:

    def test_seeds_constant(self):
        assert ORACLE_CONFIG_PDA_SEED == b"oracle_config"

    def test_singleton_pda(self):
        # Always the same — there's only one OracleConfig per program.
        p1, _ = derive_oracle_config_pda(PROGRAM_ID)
        p2, _ = derive_oracle_config_pda(PROGRAM_ID)
        assert p1 == p2
