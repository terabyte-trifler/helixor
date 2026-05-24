// =============================================================================
// programs/slash-authority/tests/slash_logic.rs
//
// Pure unit tests for the Day-20 slash-authority logic. No runtime — these
// exercise the layout constants, the OffenseTier codec, and the tiered
// slash-amount math in isolation. Full on-chain behaviour (the lamport
// debit, the append-only SlashRecord, authority gating) is exercised by
// the TypeScript integration test.
// =============================================================================

use slash_authority::state::{
    compute_slash_amount, EscrowVault, OffenseTier, SlashConfig,
    SlashDestination, SlashRecord,
};

// =============================================================================
// Layout constants
// =============================================================================

#[test]
fn escrow_vault_size_is_correct() {
    //   32 + 8 + 8 + 8 + 8 + 1 + 1 + 1 = 67  + 32 reserved = 99
    assert_eq!(EscrowVault::SIZE_WITHOUT_DISCRIMINATOR, 99);
    assert_eq!(EscrowVault::SPACE, 107); // + 8 discriminator
}

#[test]
fn slash_record_size_is_correct() {
    //   Day-20 core 140 + Day-21 lifecycle 49 + reserve 7 = 196
    assert_eq!(SlashRecord::SIZE_WITHOUT_DISCRIMINATOR, 196);
    assert_eq!(SlashRecord::SPACE, 204); // + 8 discriminator
}

#[test]
fn slash_config_size_is_correct() {
    // 8 + 32 + 32 + 32 + 1 = 105
    assert_eq!(SlashConfig::SPACE, 105);
}

#[test]
fn min_stake_is_point_zero_one_sol() {
    // 0.01 SOL = 10_000_000 lamports — the figure the MVP used, now enforced.
    assert_eq!(EscrowVault::MIN_STAKE_LAMPORTS, 10_000_000);
}

#[test]
fn seed_prefixes_are_stable() {
    assert_eq!(EscrowVault::SEED_PREFIX, b"escrow");
    assert_eq!(SlashRecord::SEED_PREFIX, b"slash");
    assert_eq!(SlashConfig::SEED, b"slash_config");
}

// =============================================================================
// OffenseTier codec
// =============================================================================

#[test]
fn offense_tier_round_trips() {
    for tier in [OffenseTier::Minor, OffenseTier::Major, OffenseTier::Compromise] {
        assert_eq!(OffenseTier::from_u8(tier.as_u8()), Some(tier));
    }
}

#[test]
fn offense_tier_codes_are_stable() {
    assert_eq!(OffenseTier::Minor.as_u8(), 0);
    assert_eq!(OffenseTier::Major.as_u8(), 1);
    assert_eq!(OffenseTier::Compromise.as_u8(), 2);
}

#[test]
fn offense_tier_rejects_invalid_code() {
    assert_eq!(OffenseTier::from_u8(3), None);
    assert_eq!(OffenseTier::from_u8(255), None);
}

// =============================================================================
// Tiering — bps, destination, terminality
// =============================================================================

#[test]
fn tier_bps_are_correct() {
    assert_eq!(OffenseTier::Minor.slash_bps(), 500);      // 5%
    assert_eq!(OffenseTier::Major.slash_bps(), 5_000);    // 50%
    assert_eq!(OffenseTier::Compromise.slash_bps(), 10_000); // 100%
}

#[test]
fn minor_and_major_go_to_treasury() {
    assert_eq!(OffenseTier::Minor.destination(), SlashDestination::Treasury);
    assert_eq!(OffenseTier::Major.destination(), SlashDestination::Treasury);
}

#[test]
fn compromise_burns() {
    assert_eq!(OffenseTier::Compromise.destination(), SlashDestination::Burn);
}

#[test]
fn only_compromise_is_terminal() {
    assert!(!OffenseTier::Minor.is_terminal());
    assert!(!OffenseTier::Major.is_terminal());
    assert!(OffenseTier::Compromise.is_terminal());
}

// =============================================================================
// compute_slash_amount — the tiered math
// =============================================================================

#[test]
fn minor_slash_takes_five_percent() {
    // 1 SOL staked, Minor → 5% = 0.05 SOL.
    assert_eq!(
        compute_slash_amount(1_000_000_000, OffenseTier::Minor),
        50_000_000,
    );
}

#[test]
fn major_slash_takes_fifty_percent() {
    assert_eq!(
        compute_slash_amount(1_000_000_000, OffenseTier::Major),
        500_000_000,
    );
}

#[test]
fn compromise_takes_the_whole_stake() {
    // Compromise must take 100% exactly — no dust left behind.
    assert_eq!(
        compute_slash_amount(1_000_000_000, OffenseTier::Compromise),
        1_000_000_000,
    );
}

#[test]
fn compromise_takes_everything_even_on_odd_amounts() {
    // An odd stake that would not divide cleanly — Compromise still takes
    // the WHOLE thing (the is_terminal guard, not the bps math).
    for stake in [1u64, 7, 999, 12_345_678, 33_333_333] {
        assert_eq!(
            compute_slash_amount(stake, OffenseTier::Compromise),
            stake,
        );
    }
}

#[test]
fn slash_never_exceeds_the_stake() {
    for stake in [0u64, 1, 100, 10_000_000, u64::MAX / 2] {
        for tier in [OffenseTier::Minor, OffenseTier::Major, OffenseTier::Compromise] {
            assert!(compute_slash_amount(stake, tier) <= stake);
        }
    }
}

#[test]
fn slash_of_zero_stake_is_zero() {
    for tier in [OffenseTier::Minor, OffenseTier::Major, OffenseTier::Compromise] {
        assert_eq!(compute_slash_amount(0, tier), 0);
    }
}

#[test]
fn large_stake_does_not_overflow() {
    // u128 intermediate — a near-u64::MAX stake must not panic.
    let big = u64::MAX / 2;
    let amount = compute_slash_amount(big, OffenseTier::Major);
    assert!(amount <= big);
    assert_eq!(amount, ((big as u128) * 5_000 / 10_000) as u64);
}
