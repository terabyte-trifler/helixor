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
// H-04 — BOUNDED PAUSE WITH HARD CAP
// -----------------------------------
// The Day-VULN-04 pause was a boolean: a compromised `pause_authority`
// key could freeze the slash pipeline INDEFINITELY (a DoS, not a theft —
// funds are held, not stolen). H-04 caps it: `pause_handler` takes a
// `duration_seconds` argument bounded by MAX_PAUSE_SECONDS (7 days) and
// writes `paused_until = now + duration_seconds`. The "is currently
// paused" check that gates execute / resolve / settle reads BOTH
// `paused` and `paused_until` — an expired pause behaves identically
// to an unpaused config without requiring an unpause tx. A malicious
// pause_authority must re-issue the pause every 7 days, leaving an
// observable on-chain trail and time for SPOF-#2 authority rotation
// to replace the compromised key.
//
// M-08 — AUTHORITY-EPOCH SNAPSHOT TAG
// -----------------------------------
// The audit raised a forensic-accountability gap: every SlashRecord
// records the executor pubkey, but NOT the authority-set context the
// executor was acting under at the time. After SPOF-#2 rotation
// installs a new `slash_executor`, an off-chain auditor inspecting an
// old SlashRecord sees a pubkey that is no longer the live executor —
// they have to walk the AuthorityRotationEnacted event log to confirm
// the executor was authoritative at the moment they ran the slash.
// That walk is doable but brittle: if events get reorganised, indexed
// inconsistently, or simply outpaced by a sequence of rotations, the
// link between (slash_record.executor, execution moment) and "this
// key was the live executor" weakens.
//
// M-08 fixes this by introducing a `slash_config_version` — a u32
// monotonic counter that:
//   * starts at 1 at `initialize_config`,
//   * bumps strictly +1 on every `enact_authority_rotation`,
//   * is snapshotted onto every SlashRecord at `execute_slash` time,
//   * is included in the `SlashExecuted` event payload.
// The counter is small (4 bytes) — carved from the M-07 `_reserved`
// cushion (6 → 2 bytes), zero-net-growth. A forensic auditor can now
// answer "was this key authorised at the moment it slashed?" from one
// number on the SlashRecord and the live `AuthorityRotationEnacted`
// log (which carries old/new versions); no event-replay required.
//
// M-07 — ON-CHAIN TUNABLE SETTLE-SLASH TIMING
// -------------------------------------------
// The VULN-08 fix introduced two timing gates on settle_slash:
//   - a 48h execute->settle floor (defence-in-depth vs same-block griefing),
//   - a 1h post-appeal-window grace (defence vs MEV front-running of an
//     appeal landing in the deadline slot).
// Those numbers were `pub const` in `settle_slash.rs` — meaning the only
// way to tune them was a program redeploy. The audit (M-07) flagged this
// as operationally brittle: an incident that demanded (say) a longer
// floor could not be applied without a full deploy + IDL roll-out across
// every consumer.
//
// M-07 moves both numbers onto SlashConfig where the admin can tune them
// in-flight via `update_settle_timing`. To preserve byte-layout for
// pre-M-07 accounts (which have 22 zero bytes in `_reserved`) we carve
// the two new i64 fields OUT of the reserved cushion (22 → 6). Accounts
// initialised before M-07 will read both fields as `0`, which the
// `effective_*` accessors treat as "use the default" — so existing
// deployments continue to behave exactly as before until the admin
// actively calls update_settle_timing.
//
// The on-chain defaults remain 48h and 1h. The on-chain BOUNDS prevent
// an admin (or a compromised admin key) from setting nonsensical values:
//   execute_to_settle_seconds ∈ [MIN_EXECUTE_TO_SETTLE_BOUND,
//                                MAX_EXECUTE_TO_SETTLE_BOUND]  (12h..7d)
//   settle_grace_seconds      ∈ [MIN_SETTLE_GRACE_BOUND,
//                                MAX_SETTLE_GRACE_BOUND]       (5m..24h)
// These bounds are pinned in `tests/m07_on_chain_settle_timing.rs`.
//
// LAYOUT (after the 8-byte Anchor discriminator):
//   admin                          32   (Pubkey — may update this config)
//   slash_executor                 32   (Pubkey — execute_slash + settle_slash)
//   appeal_resolver                32   (Pubkey — resolve_appeal)
//   pause_authority                32   (Pubkey — pause/unpause)
//   treasury                       32   (Pubkey — receives non-burn slashes)
//   settlement_timelock_seconds     8   (i64    — post-uphold delay, >=72h)
//   paused                          1   (bool   — kill-switch flag)
//   paused_at                       8   (i64    — unix seconds of pause start)
//   paused_until                    8   (i64    — H-04: unix seconds the pause
//                                                 auto-expires; 0 if not paused)
//   bump                            1   (u8)
//   layout_version                  1   (u8    — for future migrations)
//   execute_to_settle_seconds       8   (i64    — M-07: VULN-08 floor;
//                                                 0 = use DEFAULT (48h))
//   settle_grace_seconds            8   (i64    — M-07: VULN-08 grace;
//                                                 0 = use DEFAULT (1h))
//   slash_config_version            4   (u32    — M-08: monotonic authority
//                                                 epoch; bumped on every
//                                                 enact_authority_rotation,
//                                                 snapshotted on SlashRecord)
//   _reserved                       2   (zeroed cushion — reduced by 4 to fit
//                                        slash_config_version at zero net
//                                        growth)
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
/// ever changes. v3 added H-04's `paused_until`; v4 (M-07) added
/// `execute_to_settle_seconds` + `settle_grace_seconds`; v5 (M-08) adds
/// `slash_config_version` — all reclaimed from the `_reserved` cushion,
/// net zero size growth.
pub const SLASH_CONFIG_LAYOUT_VERSION: u8 = 5;

/// M-08: the value `slash_config_version` is seeded to at
/// `initialize_config`. 1 chosen as the genesis epoch so the canonical
/// "never been initialised" zero remains a sentinel ("config has not
/// been written yet"). Every subsequent rotation increments by +1.
pub const SLASH_CONFIG_GENESIS_VERSION: u32 = 1;

/// H-04: the maximum duration a pause may persist without being
/// re-issued. 7 days — long enough for a real incident response, short
/// enough that a compromised pause_authority key must re-pause
/// repeatedly (each re-pause is observable on chain) instead of
/// freezing the program indefinitely. Bounded by SPOF-#2 rotation
/// latency: a 48h-timelock + 2-of-3 attested rotation can replace the
/// pause_authority within the cap.
pub const MAX_PAUSE_SECONDS: i64 = 7 * 24 * 3_600;

/// M-07: the BUILT-IN DEFAULTS for the two settle_slash timing gates.
/// These are also re-exported as `DEFAULT_EXECUTE_TO_SETTLE_SECONDS` /
/// `DEFAULT_SETTLE_GRACE_SECONDS` from `instructions::settle_slash` so
/// existing test sites keep importing from one canonical place. The
/// numbers match the pre-M-07 VULN-08 constants exactly — M-07 is a
/// pure mobility upgrade, not a re-tune.
pub const DEFAULT_EXECUTE_TO_SETTLE_SECONDS: i64 = 48 * 3_600;
pub const DEFAULT_SETTLE_GRACE_SECONDS:      i64 = 60 * 60;

/// M-07: hard bounds on the on-chain-tunable settle_slash floor. A floor
/// shorter than 12h would re-open the same-block griefing window that
/// VULN-08 closed; a floor longer than 7d would let a compromised admin
/// indefinitely freeze settlement of an upheld slash. The interval is
/// asymmetric: the LOWER bound is the security floor (don't go beneath
/// it), the UPPER bound is the operability ceiling (don't go above it).
pub const MIN_EXECUTE_TO_SETTLE_BOUND: i64 = 12 * 3_600;
pub const MAX_EXECUTE_TO_SETTLE_BOUND: i64 = 7 * 24 * 3_600;

/// M-07: hard bounds on the on-chain-tunable settle_slash grace period.
/// 5m is the floor — anything shorter cannot protect an appeal that
/// landed in the same slot as the deadline against an MEV bot racing
/// settlement in the next block. 24h is the ceiling — anything longer
/// is operationally indistinguishable from a permanent freeze given the
/// 48h-7d execute-to-settle floor next to it.
pub const MIN_SETTLE_GRACE_BOUND: i64 = 5 * 60;
pub const MAX_SETTLE_GRACE_BOUND: i64 = 24 * 3_600;

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
    /// True while slash actions are paused. H-04: the EFFECTIVE pause
    /// state is `paused && now < paused_until` — an expired pause behaves
    /// like an unpaused config without requiring an explicit unpause tx.
    /// Read through `is_paused_now(now)` rather than this flag directly.
    pub paused:                      bool,
    /// Unix seconds the pause was last activated. Zero if never paused.
    pub paused_at:                   i64,
    /// H-04: Unix seconds the pause auto-expires. The pause_authority sets
    /// this to `now + duration_seconds` (1..=MAX_PAUSE_SECONDS) at pause
    /// time. Zero when not paused.
    pub paused_until:                i64,
    /// Canonical PDA bump.
    pub bump:                        u8,
    /// Account-layout version.
    pub layout_version:              u8,
    /// M-07: on-chain-tunable VULN-08 floor. The minimum gap between
    /// execute_slash and settle_slash, regardless of appeal status.
    /// `0` means "use the DEFAULT" (48h) — preserves byte-layout for
    /// pre-M-07 accounts whose `_reserved` was previously zero. Read
    /// through `effective_execute_to_settle_seconds()`, not directly.
    pub execute_to_settle_seconds:   i64,
    /// M-07: on-chain-tunable VULN-08 grace period. The minimum gap
    /// between `appeal_deadline` closing and `settle_slash` becoming
    /// callable. `0` means "use the DEFAULT" (1h). Read through
    /// `effective_settle_grace_seconds()`, not directly.
    pub settle_grace_seconds:        i64,
    /// M-08: the AUTHORITY EPOCH counter. Seeded to
    /// `SLASH_CONFIG_GENESIS_VERSION` at init, incremented strictly +1
    /// on every `enact_authority_rotation`. Snapshotted onto every
    /// SlashRecord at `execute_slash` time so an off-chain auditor can
    /// answer "was this executor authoritative at the moment of the
    /// slash?" from one number rather than walking the rotation event
    /// log. The u32 ceiling is a hard error, not a wrap.
    pub slash_config_version:        u32,
    /// Zero-padded reserve for future fields. Shrunk from 6 to 2 to
    /// fit M-08's `slash_config_version` at zero net growth.
    pub _reserved:                   [u8; 2],
}

impl SlashConfig {
    /// Data size WITHOUT the 8-byte Anchor discriminator.
    ///   5*32 (pubkeys) + 8 (timelock) + 1 (paused) + 8 (paused_at)
    /// + 8 (paused_until — H-04) + 1 (bump) + 1 (layout_version)
    /// + 8 (execute_to_settle_seconds — M-07)
    /// + 8 (settle_grace_seconds — M-07)
    /// + 4 (slash_config_version — M-08)
    /// + 2 (reserved) = 209
    pub const SIZE_WITHOUT_DISCRIMINATOR: usize =
        32 * 5 + 8 + 1 + 8 + 8 + 1 + 1 + 8 + 8 + 4 + 2;

    /// Total account size INCLUDING the 8-byte Anchor discriminator.
    pub const SPACE: usize = 8 + Self::SIZE_WITHOUT_DISCRIMINATOR;

    /// The PDA seed.
    pub const SEED: &'static [u8] = b"slash_config";

    /// The Solana incinerator address — lamports sent here are burned
    /// (economically destroyed; the address has no private key).
    /// This is the canonical, well-known incinerator pubkey.
    pub const INCINERATOR: Pubkey =
        pubkey!("1nc1nerator11111111111111111111111111111111");

    /// H-04: the EFFECTIVE pause state at time `now`. A pause is in
    /// effect only when the flag is set AND the auto-expiry has not
    /// elapsed. An expired pause behaves as unpaused without requiring
    /// an explicit unpause transaction — the cap is the whole point of
    /// the H-04 mitigation.
    pub fn is_paused_now(&self, now: i64) -> bool {
        self.paused && now < self.paused_until
    }

    /// M-07: the EFFECTIVE execute->settle floor. Falls back to the
    /// `DEFAULT_EXECUTE_TO_SETTLE_SECONDS` (48h) when the on-chain
    /// field is non-positive — preserves behaviour for any account
    /// whose `_reserved` was zero before M-07 carved this field out.
    /// The on-chain bounds guarantee a freshly-set value is always
    /// positive, so the only way to reach the fallback is via a
    /// pre-M-07 account or a deliberate `0` write (which is rejected
    /// at the `update_settle_timing` boundary).
    pub fn effective_execute_to_settle_seconds(&self) -> i64 {
        if self.execute_to_settle_seconds > 0 {
            self.execute_to_settle_seconds
        } else {
            DEFAULT_EXECUTE_TO_SETTLE_SECONDS
        }
    }

    /// M-07: the EFFECTIVE post-appeal grace. See
    /// `effective_execute_to_settle_seconds` for the fallback logic.
    pub fn effective_settle_grace_seconds(&self) -> i64 {
        if self.settle_grace_seconds > 0 {
            self.settle_grace_seconds
        } else {
            DEFAULT_SETTLE_GRACE_SECONDS
        }
    }
}

/// M-07: validate a proposed (execute_to_settle, settle_grace) pair
/// against the on-chain bounds. Returns `Ok(())` iff BOTH values fall
/// within their respective `[MIN_*_BOUND, MAX_*_BOUND]` intervals.
/// Extracted so `update_settle_timing` and the unit tests share one
/// canonical validation surface.
pub fn validate_settle_timing_seconds(
    execute_to_settle_seconds: i64,
    settle_grace_seconds:      i64,
) -> std::result::Result<(), SettleTimingBoundsError> {
    if execute_to_settle_seconds < MIN_EXECUTE_TO_SETTLE_BOUND
        || execute_to_settle_seconds > MAX_EXECUTE_TO_SETTLE_BOUND
    {
        return Err(SettleTimingBoundsError::ExecuteToSettleOutOfBounds);
    }
    if settle_grace_seconds < MIN_SETTLE_GRACE_BOUND
        || settle_grace_seconds > MAX_SETTLE_GRACE_BOUND
    {
        return Err(SettleTimingBoundsError::SettleGraceOutOfBounds);
    }
    Ok(())
}

/// M-07: structured rejection reason from `validate_settle_timing_seconds`.
/// The instruction boundary maps both variants to the same
/// `SlashError::SettleTimingOutOfBounds` code — the split exists only so
/// unit tests can pin the per-field semantics independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleTimingBoundsError {
    ExecuteToSettleOutOfBounds,
    SettleGraceOutOfBounds,
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
