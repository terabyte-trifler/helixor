// =============================================================================
// programs/slash-authority/src/state/slash_config.rs
//
// SlashConfig — the singleton config for the slash-authority program.
//
//     seeds = ["slash_config"]
//
// VULN-04 REMEDIATION — ROLE SEPARATION, TIMELOCK, EMERGENCY PAUSE
// ----------------------------------------------------------------
// The Day-20/21 design used a single `slash_authority` Pubkey that gated
// execute_slash, resolve_appeal AND settle_slash. That one key, if
// compromised (or held by a malicious insider), could:
//   1. execute_slash on any agent (encumber stake),
//   2. resolve_appeal(uphold=true) (override the agent's defence),
//   3. settle_slash (move stake to a treasury they also control).
//
// The fix splits the single key into three independent roles AND adds a
// post-resolution timelock + an emergency pause so a compromised single
// key cannot drain stake even if it gets one of the three roles:
//
//   slash_executor   — may call execute_slash and settle_slash.
//   appeal_resolver  — may call resolve_appeal. MUST be a different key
//                      from slash_executor. Must also differ from the
//                      executor of the specific slash being resolved
//                      (defence in depth — even within the same org an
//                      individual cannot review their own slash).
//   pause_authority  — may call pause_settlements / unpause_settlements,
//                      a kill-switch that freezes execute_slash,
//                      resolve_appeal AND settle_slash. Cannot move funds
//                      on its own.
//
// settlement_timelock_seconds is the MINIMUM delay between an appeal
// being upheld and the slash becoming settle-able. Even if both the
// executor and the resolver are compromised, the timelock buys >= 72h
// for the pause_authority (or governance) to intervene.
//
// The three roles MUST all be distinct, all non-default. Production
// deployments should map each role to a separate organisational
// signer / multisig. Phase 4 wiring of the oracle threshold authority
// must arrive before any real SOL is staked.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   admin                       32   (Pubkey — may update this config)
//   slash_executor              32   (Pubkey — execute_slash + settle_slash)
//   appeal_resolver             32   (Pubkey — resolve_appeal)
//   pause_authority             32   (Pubkey — pause/unpause)
//   treasury                    32   (Pubkey — receives non-burn slashes)
//   settlement_timelock_seconds  8   (i64    — post-uphold delay, >=72h)
//   paused                       1   (bool   — kill switch)
//   paused_at                    8   (i64    — unix seconds of pause)
//   bump                         1   (u8)
//   layout_version               1   (u8    — for future migrations)
//   _reserved                   30   (zeroed cushion)
//   TOTAL (without discriminator): 209 bytes
// =============================================================================

use anchor_lang::prelude::*;
use solana_program::pubkey;

/// The minimum settlement timelock — the shortest delay we accept between
/// an appeal being upheld and the slash becoming settle-able. 72h: long
/// enough for the pause_authority or governance to react if the executor
/// AND resolver are both compromised.
pub const MIN_SETTLEMENT_TIMELOCK_SECONDS: i64 = 72 * 3_600;

/// The current SlashConfig layout version. Bumped if the on-disk shape
/// ever changes.
pub const SLASH_CONFIG_LAYOUT_VERSION: u8 = 2;

#[account]
#[derive(Default, Debug)]
pub struct SlashConfig {
    /// Admin authority — the key that may rotate the role keys via
    /// `update_authorities`.
    pub admin:                       Pubkey,
    /// The authority permitted to execute and settle slashes. MUST differ
    /// from `appeal_resolver` and `pause_authority`.
    pub slash_executor:              Pubkey,
    /// The authority permitted to resolve appeals. MUST differ from
    /// `slash_executor` and `pause_authority`, AND from the specific
    /// slash record's executor at resolve-time.
    pub appeal_resolver:             Pubkey,
    /// The emergency-pause authority. MAY freeze execute_slash,
    /// resolve_appeal and settle_slash, but cannot move funds on its own.
    /// MUST differ from the other two role keys.
    pub pause_authority:             Pubkey,
    /// The treasury account that receives Treasury-destination slashes.
    pub treasury:                    Pubkey,
    /// Minimum delay (seconds) between an appeal being upheld and the
    /// slash becoming settle-able. Enforced at init / update to be
    /// >= MIN_SETTLEMENT_TIMELOCK_SECONDS.
    pub settlement_timelock_seconds: i64,
    /// True while slash actions are paused.
    pub paused:                      bool,
    /// Unix seconds the pause was last activated. Zero if never paused.
    pub paused_at:                   i64,
    /// Canonical PDA bump.
    pub bump:                        u8,
    /// Account-layout version.
    pub layout_version:              u8,
    /// Zero-padded reserve for future fields.
    pub _reserved:                   [u8; 30],
}

impl SlashConfig {
    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   5*32 (pubkeys) + 8 (timelock) + 1 (paused) + 8 (paused_at)
    /// + 1 (bump) + 1 (layout_version) + 30 (reserved) = 209
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 * 5 + 8 + 1 + 8 + 1 + 1 + 30;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"slash_config";

    /// The Solana incinerator address — lamports sent here are burned
    /// (economically destroyed; the address has no private key).
    /// This is the canonical, well-known incinerator pubkey.
    pub const INCINERATOR: Pubkey =
        pubkey!("1nc1nerator11111111111111111111111111111111");
}

/// Validate the three role keys are all distinct and all non-default.
/// Returns Ok(()) iff they form a valid separated-authority set.
pub fn validate_authority_separation(
    slash_executor:  &Pubkey,
    appeal_resolver: &Pubkey,
    pause_authority: &Pubkey,
) -> std::result::Result<(), AuthoritySeparationError> {
    let default = Pubkey::default();
    if slash_executor == &default
        || appeal_resolver == &default
        || pause_authority == &default
    {
        return Err(AuthoritySeparationError::DefaultPubkey);
    }
    if slash_executor == appeal_resolver
        || slash_executor == pause_authority
        || appeal_resolver == pause_authority
    {
        return Err(AuthoritySeparationError::NotDistinct);
    }
    Ok(())
}

/// Why a set of three role keys was rejected. Mapped to typed SlashError
/// codes at the instruction boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritySeparationError {
    /// At least one of the role keys is the all-zero default Pubkey.
    DefaultPubkey,
    /// Two or more of the role keys collide.
    NotDistinct,
}
