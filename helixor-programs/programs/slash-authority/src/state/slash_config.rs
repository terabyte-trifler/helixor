// =============================================================================
// programs/slash-authority/src/state/slash_config.rs
//
// SlashConfig — the singleton config for the slash-authority program.
//
//     seeds = ["slash_config"]
//
// Holds the authority permitted to execute a slash and the treasury that
// receives non-burn slashes.
//
// THE AUTHORITY MODEL — AND WHAT "MULTISIG" MEANS TODAY
// ----------------------------------------------------
// The brief says "only the oracle MULTISIG can execute a slash". The real
// 3-of-N threshold authority is Phase-4 work — the rest of the codebase
// already notes this (OracleConfig: "In Phase 4 this will be replaced by a
// 3-of-5 threshold; for now, one key").
//
// So `slash_authority` here is a SINGLE authorised key — the same shape as
// OracleConfig.oracle_node — that STANDS IN for the eventual multisig.
// Crucially the program reads the authority from this config, never a
// hard-coded key: swapping the single key for a multisig PDA in Phase 4 is
// one `update` write, no redeploy. The README is explicit that today's
// gate is a single key, not a true multisig.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   admin            32   (Pubkey — may update this config)
//   slash_authority  32   (Pubkey — may execute a slash; the "multisig" stand-in)
//   treasury         32   (Pubkey — receives non-burn slashes)
//   bump              1   (u8)
//   TOTAL (without discriminator): 97 bytes
// =============================================================================

use anchor_lang::prelude::*;

#[account]
#[derive(Default, Debug)]
pub struct SlashConfig {
    /// Admin authority — the key that may update this config (e.g. to swap
    /// `slash_authority` for the Phase-4 multisig).
    pub admin:           Pubkey,
    /// The authority permitted to execute a slash. A single key today,
    /// standing in for the eventual oracle multisig.
    pub slash_authority: Pubkey,
    /// The treasury account that receives Treasury-destination slashes.
    pub treasury:        Pubkey,
    /// Canonical PDA bump.
    pub bump:            u8,
}

impl SlashConfig {
    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 1;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"slash_config";

    /// The Solana incinerator address — lamports sent here are burned
    /// (economically destroyed; the address has no private key).
    /// This is the canonical, well-known incinerator pubkey.
    pub const INCINERATOR: Pubkey = Pubkey::new_from_array([
        0, 51, 144, 114, 141, 52, 17, 96,
        121, 189, 201, 17, 191, 255, 0, 219,
        212, 77, 46, 205, 204, 247, 156, 166,
        225, 0, 56, 225, 0, 0, 0, 0,
    ]);
}
