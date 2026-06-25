// =============================================================================
// programs/certificate-issuer/src/slot_anchor.rs
//
// AW-01-EXT — on-chain verification of a cluster-pinned Solana slot anchor
// against the `SlotHashes` sysvar.
//
// THE GAP THIS CLOSES
// -------------------
// AW-01 binds the cert's threshold signatures to a cluster-majority hash
// over the inputs the nodes scored. That defends against per-node
// poisoning. The remaining gap is COORDINATED upstream poisoning where
// every node reads from the SAME compromised path (one cloud provider, one
// Geyser fleet, one Kafka cluster) — every honest node agrees on the same
// false inputs and the cluster-majority check passes.
//
// This module closes that gap by introducing a THIRD independent source of
// truth: Solana's own SlotHashes sysvar. The cluster captures
// `(slot, block_hash)` at scoring time and submits it with the cert. The
// on-chain handler verifies the pair is present in the sysvar — Solana
// itself attesting that the slot exists and has that hash.
//
// An attacker who wants to forge the inputs now has to also forge Solana's
// own block history: i.e. compromise ≥33% of Solana's stake to fork the
// chain to a state where the slot they want to attest to has the hash they
// claim. That is far outside the threat envelope of "compromise the
// cluster's RPC fleet" — it is "break Solana".
//
// SYSVAR PARSING
// --------------
// `SlotHashes` is too large (~20 KB) to load via `anchor_lang::Sysvar`
// (which caps at 10 KB). We read the AccountInfo's raw data instead. The
// layout is documented and stable:
//
//   bytes 0..8        count (u64 LE) — number of entries
//   bytes 8..8+40*N   entries — each entry is (slot u64 LE) + (hash [u8;32])
//
// Entries are stored newest-first (largest slot at offset 8). We walk
// them and short-circuit when we find a match. Worst case we read the
// whole 512-entry window (~3.4 minutes of slots), which is cheap.
// =============================================================================

use anchor_lang::prelude::*;
use solana_program::sysvar::slot_hashes::ID as SLOT_HASHES_ID;

use crate::errors::CertificateError;

/// A zero anchor — the off-chain submitter's `MissingSlotAnchor` sentinel.
/// Refused early so a stub anchor cannot bypass the SlotHashes check.
pub const ZERO_SLOT_ANCHOR_HASH: [u8; 32] = [0u8; 32];

/// Bytes per `(slot u64, hash [u8;32])` entry in the sysvar layout.
const ENTRY_BYTES: usize = 8 + 32;

/// The 8-byte length prefix at the start of the sysvar data.
const LEN_PREFIX_BYTES: usize = 8;

/// Verify that the supplied `(slot, hash)` anchor is present in the
/// `SlotHashes` sysvar.
///
/// Returns:
///   Ok(())                              — anchor verified.
///   Err(WrongSlotHashesSysvar)           — wrong sysvar account passed in.
///   Err(MissingSlotAnchor)               — anchor is the zero sentinel.
///   Err(SlotAnchorTooOld)                — slot is older than the
///                                          ~512-slot sysvar window.
///   Err(SlotAnchorHashMismatch)          — slot present, but the
///                                          recorded hash differs from
///                                          what the cluster pinned.
///
/// PURE EXCEPT FOR THE SYSVAR READ. No allocation; one borrow of the
/// sysvar's data buffer.
pub fn verify_slot_anchor(
    slot_hashes_sysvar: &AccountInfo,
    anchor_slot:        u64,
    anchor_hash:        &[u8; 32],
) -> Result<()> {
    // 1. Sanity: the right sysvar account was passed.
    require!(
        slot_hashes_sysvar.key == &SLOT_HASHES_ID,
        CertificateError::WrongSlotHashesSysvar,
    );

    // 2. Sentinel: refuse the all-zero hash (the off-chain "missing"
    //    marker). Without this, a misconfigured submitter could pass
    //    (slot=0, hash=zeros) and only fail downstream — better to fail
    //    here with the dedicated error.
    require!(
        anchor_hash != &ZERO_SLOT_ANCHOR_HASH,
        CertificateError::MissingSlotAnchor,
    );

    // 3. Parse the sysvar. Layout: u64 LE count + count * (u64 LE slot +
    //    [u8;32] hash). Entries are sorted by slot, newest first.
    let data = slot_hashes_sysvar.try_borrow_data()?;
    require!(
        data.len() >= LEN_PREFIX_BYTES,
        CertificateError::WrongSlotHashesSysvar,
    );

    let mut count_bytes = [0u8; 8];
    count_bytes.copy_from_slice(&data[0..8]);
    let count = u64::from_le_bytes(count_bytes) as usize;

    // Bounds: every entry must fit.
    let expected_end = LEN_PREFIX_BYTES.saturating_add(
        count.saturating_mul(ENTRY_BYTES),
    );
    require!(
        data.len() >= expected_end,
        CertificateError::WrongSlotHashesSysvar,
    );

    // 4. Bound the search by the actual sysvar window. If the anchor is
    //    older than the oldest entry, we cannot verify it — that is
    //    SlotAnchorTooOld, distinct from "found but mismatched".
    let mut oldest_slot_seen: Option<u64> = None;

    for i in 0..count {
        let off = LEN_PREFIX_BYTES + i * ENTRY_BYTES;

        let mut slot_bytes = [0u8; 8];
        slot_bytes.copy_from_slice(&data[off..off + 8]);
        let entry_slot = u64::from_le_bytes(slot_bytes);

        oldest_slot_seen = Some(entry_slot); // updated each iter; last wins

        if entry_slot == anchor_slot {
            // Found the entry; check the hash.
            let entry_hash = &data[off + 8..off + ENTRY_BYTES];
            // Constant-time-ish compare: equal-length, fixed-iteration.
            // We do not have the ed25519-dalek subtle::ConstantTimeEq
            // dep here; the inputs are public anyway (block hashes), so
            // a fast eq is fine.
            if entry_hash == anchor_hash.as_ref() {
                return Ok(());
            }
            return Err(CertificateError::SlotAnchorHashMismatch.into());
        }
    }

    // 5. Not found. Decide between "too old" and "future / unknown".
    //    Both collapse to SlotAnchorTooOld for the operator-facing
    //    error — a future slot is also unverifiable, just for a
    //    different reason; either way the cluster must re-pin a fresher
    //    anchor and resubmit.
    let _ = oldest_slot_seen; // avoid unused warning when count == 0
    Err(CertificateError::SlotAnchorTooOld.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::pubkey::Pubkey;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Build an AccountInfo whose data holds a synthetic SlotHashes sysvar
    /// with `entries` packed in (newest-first).
    fn make_sysvar(entries: &[(u64, [u8; 32])]) -> (Pubkey, Vec<u8>) {
        let mut data = Vec::with_capacity(
            LEN_PREFIX_BYTES + entries.len() * ENTRY_BYTES,
        );
        data.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (slot, hash) in entries {
            data.extend_from_slice(&slot.to_le_bytes());
            data.extend_from_slice(hash);
        }
        (SLOT_HASHES_ID, data)
    }

    fn with_account_info<R>(
        key: Pubkey,
        data: &mut Vec<u8>,
        f: impl FnOnce(&AccountInfo) -> R,
    ) -> R {
        let mut lamports: u64 = 0;
        let owner = Pubkey::default();
        // solana-account-info 3.x renamed the trailing `rent_epoch` field to
        // `_unused` (ABIv2 deprecation). The exact layout still matters because
        // the runtime depends on it, but the name is now `_unused`.
        let info = AccountInfo {
            key: &key,
            is_signer: false,
            is_writable: false,
            lamports: Rc::new(RefCell::new(&mut lamports)),
            data: Rc::new(RefCell::new(data.as_mut_slice())),
            owner: &owner,
            executable: false,
            _unused: 0,
        };
        f(&info)
    }

    #[test]
    fn matching_anchor_is_accepted() {
        let hash = [7u8; 32];
        let (key, mut data) = make_sysvar(&[
            (100, [9u8; 32]),
            (99,  hash),
            (98,  [11u8; 32]),
        ]);
        with_account_info(key, &mut data, |info| {
            verify_slot_anchor(info, 99, &hash).unwrap();
        });
    }

    #[test]
    fn slot_present_but_hash_mismatched_yields_specific_error() {
        let (key, mut data) = make_sysvar(&[
            (100, [9u8; 32]),
            (99,  [1u8; 32]),
        ]);
        with_account_info(key, &mut data, |info| {
            let err = verify_slot_anchor(info, 99, &[2u8; 32]).unwrap_err();
            let code: anchor_lang::error::Error =
                CertificateError::SlotAnchorHashMismatch.into();
            assert_eq!(format!("{:?}", err), format!("{:?}", code));
        });
    }

    #[test]
    fn slot_not_in_window_yields_too_old() {
        let (key, mut data) = make_sysvar(&[
            (200, [9u8; 32]),
            (199, [10u8; 32]),
        ]);
        with_account_info(key, &mut data, |info| {
            let err = verify_slot_anchor(info, 150, &[9u8; 32]).unwrap_err();
            let code: anchor_lang::error::Error =
                CertificateError::SlotAnchorTooOld.into();
            assert_eq!(format!("{:?}", err), format!("{:?}", code));
        });
    }

    /// Extract just the error code number from a possibly-Anchor error so
    /// assertions don't drift when Anchor adds origin/source annotations to
    /// errors raised via `require!`. Returns None for non-Anchor errors.
    fn anchor_code(err: &anchor_lang::error::Error) -> Option<u32> {
        match err {
            anchor_lang::error::Error::AnchorError(boxed) => {
                Some(boxed.error_code_number)
            }
            _ => None,
        }
    }

    #[test]
    fn zero_hash_yields_missing_anchor() {
        let (key, mut data) = make_sysvar(&[(1, [0u8; 32])]);
        with_account_info(key, &mut data, |info| {
            let err = verify_slot_anchor(info, 1, &ZERO_SLOT_ANCHOR_HASH).unwrap_err();
            let expected: anchor_lang::error::Error =
                CertificateError::MissingSlotAnchor.into();
            assert_eq!(anchor_code(&err), anchor_code(&expected));
        });
    }

    #[test]
    fn wrong_sysvar_account_is_rejected() {
        let foreign = Pubkey::new_unique();
        let mut data = vec![0u8; LEN_PREFIX_BYTES];
        with_account_info(foreign, &mut data, |info| {
            let err = verify_slot_anchor(info, 1, &[1u8; 32]).unwrap_err();
            let expected: anchor_lang::error::Error =
                CertificateError::WrongSlotHashesSysvar.into();
            assert_eq!(anchor_code(&err), anchor_code(&expected));
        });
    }
}
