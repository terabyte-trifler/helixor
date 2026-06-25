// =============================================================================
// programs/health-oracle/src/slot_gate.rs
//
// M-04 — SECONDARY ORACLE-SIDE SLOT ANCHOR VERIFICATION
//
// THE GAP
// -------
// AW-01-EXT verifies the cluster-pinned `(slot, block_hash)` anchor against
// the SlotHashes sysvar on the CERTIFICATE-ISSUER side. The oracle-side
// `submit_score` forwards the anchor arguments verbatim to the CPI and does
// NOT verify them itself. If the cert-issuer's check is ever regressed —
// future refactor, alternative cert-write path, or a CPI route that bypasses
// `verify_slot_anchor` — an un-anchored or forged score would reach the
// certificate write through the oracle. The audit asked for a defence-in-
// depth secondary gate on the oracle side.
//
// THE FIX
// -------
// This module mirrors the cert-issuer's `slot_anchor::verify_slot_anchor`
// logic with PhylanxError attribution, and is called inside `submit_score`
// BEFORE the CPI. Two independent verifications of the same invariant —
// a bug or bypass in either side cannot pass an un-anchored score through
// the oracle.
//
// SYSVAR PARSING
// --------------
// `SlotHashes` is too large (~20 KB) to load via `anchor_lang::Sysvar`
// (which caps at 10 KB). We read the AccountInfo's raw data instead. The
// on-chain layout is documented and stable:
//
//   bytes 0..8        count (u64 LE) — number of entries
//   bytes 8..8+40*N   entries — each entry is (slot u64 LE) + (hash [u8;32])
//
// Entries are stored newest-first (largest slot at offset 8). We walk
// them and short-circuit when we find a match. Worst case we read the
// whole 512-entry window (~3.4 minutes of slots), which is cheap.
//
// INDEPENDENCE FROM CERT-ISSUER
// -----------------------------
// We deliberately do NOT call into `certificate_issuer::slot_anchor` even
// though it is reachable via the CPI dependency — sharing the function
// would defeat the audit's "secondary gate" intent. The clone is
// intentional. Bug fixes that affect the SlotHashes layout must be
// applied to BOTH modules.
// =============================================================================

use anchor_lang::prelude::*;
use solana_program::sysvar::slot_hashes::ID as SLOT_HASHES_ID;

use crate::errors::PhylanxError;

/// The zero-hash sentinel used by the off-chain submitter when no slot
/// anchor was available. Rejected with `MissingSlotAnchor`.
pub const ZERO_SLOT_ANCHOR_HASH: [u8; 32] = [0u8; 32];

/// Bytes per `(slot u64, hash [u8;32])` entry in the sysvar layout.
const ENTRY_BYTES: usize = 8 + 32;

/// The 8-byte length prefix at the start of the sysvar data.
const LEN_PREFIX_BYTES: usize = 8;

/// Verify that the supplied `(slot, hash)` anchor is present in the
/// `SlotHashes` sysvar. Returns:
///   Ok(())                            — anchor verified.
///   Err(WrongSlotHashesSysvar)         — wrong sysvar account passed in.
///   Err(MissingSlotAnchor)             — anchor is the zero sentinel.
///   Err(SlotAnchorTooOld)              — slot is older than the
///                                        ~512-slot sysvar window.
///   Err(SlotAnchorHashMismatch)        — slot present, but the recorded
///                                        hash differs from what the
///                                        cluster supplied.
///
/// PURE EXCEPT FOR THE SYSVAR READ. No allocation; one borrow of the
/// sysvar's data buffer.
pub fn verify_slot_anchor(
    slot_hashes_sysvar: &AccountInfo,
    anchor_slot:        u64,
    anchor_hash:        &[u8; 32],
) -> Result<()> {
    // 1. The right sysvar account was passed.
    require!(
        slot_hashes_sysvar.key == &SLOT_HASHES_ID,
        PhylanxError::WrongSlotHashesSysvar,
    );

    // 2. Refuse the all-zero sentinel before doing any layout walking.
    require!(
        anchor_hash != &ZERO_SLOT_ANCHOR_HASH,
        PhylanxError::MissingSlotAnchor,
    );

    // 3. Parse the sysvar.
    let data = slot_hashes_sysvar.try_borrow_data()?;
    require!(
        data.len() >= LEN_PREFIX_BYTES,
        PhylanxError::WrongSlotHashesSysvar,
    );

    let mut count_bytes = [0u8; 8];
    count_bytes.copy_from_slice(&data[0..8]);
    let count = u64::from_le_bytes(count_bytes) as usize;

    let expected_end = LEN_PREFIX_BYTES
        .saturating_add(count.saturating_mul(ENTRY_BYTES));
    require!(
        data.len() >= expected_end,
        PhylanxError::WrongSlotHashesSysvar,
    );

    // 4. Linear scan — entries newest-first. Short-circuit on match.
    for i in 0..count {
        let off = LEN_PREFIX_BYTES + i * ENTRY_BYTES;

        let mut slot_bytes = [0u8; 8];
        slot_bytes.copy_from_slice(&data[off..off + 8]);
        let entry_slot = u64::from_le_bytes(slot_bytes);

        if entry_slot == anchor_slot {
            let entry_hash = &data[off + 8..off + ENTRY_BYTES];
            if entry_hash == anchor_hash.as_ref() {
                return Ok(());
            }
            return Err(PhylanxError::SlotAnchorHashMismatch.into());
        }
    }

    // 5. Not found in the window — either past the SlotHashes horizon
    //    (too old) or ahead of the cluster's known tip (future / unknown).
    //    Both collapse to SlotAnchorTooOld for the operator-facing error
    //    surface; the cluster must re-pin a fresher anchor either way.
    Err(PhylanxError::SlotAnchorTooOld.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::pubkey::Pubkey;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Build a synthetic SlotHashes sysvar buffer with `entries` packed in
    /// (the caller passes them newest-first to match real layout).
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

    fn anchor_code(err: &anchor_lang::error::Error) -> Option<u32> {
        match err {
            anchor_lang::error::Error::AnchorError(boxed) => {
                Some(boxed.error_code_number)
            }
            _ => None,
        }
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
            let expected: anchor_lang::error::Error =
                PhylanxError::SlotAnchorHashMismatch.into();
            assert_eq!(anchor_code(&err), anchor_code(&expected));
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
            let expected: anchor_lang::error::Error =
                PhylanxError::SlotAnchorTooOld.into();
            assert_eq!(anchor_code(&err), anchor_code(&expected));
        });
    }

    #[test]
    fn zero_hash_yields_missing_anchor() {
        let (key, mut data) = make_sysvar(&[(1, [0u8; 32])]);
        with_account_info(key, &mut data, |info| {
            let err = verify_slot_anchor(info, 1, &ZERO_SLOT_ANCHOR_HASH).unwrap_err();
            let expected: anchor_lang::error::Error =
                PhylanxError::MissingSlotAnchor.into();
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
                PhylanxError::WrongSlotHashesSysvar.into();
            assert_eq!(anchor_code(&err), anchor_code(&expected));
        });
    }
}
