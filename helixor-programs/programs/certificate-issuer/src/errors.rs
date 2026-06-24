// =============================================================================
// programs/certificate-issuer/src/errors.rs
//
// Typed errors for the certificate-issuer program. Anchor maps these to
// numeric codes >= 6000. Every error names a specific, attributable cause.
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum CertificateError {
    // ── Authority ───────────────────────────────────────────────────────────
    #[msg("signer is not the configured certificate-issuer authority")]
    NotIssuerAuthority = 6000,

    // ── Input validation ────────────────────────────────────────────────────
    #[msg("score exceeds the maximum (1000)")]
    ScoreOutOfRange = 6010,
    #[msg("alert_tier is not a valid AlertTier code (0 GREEN, 1 YELLOW, 2 RED)")]
    InvalidAlertTier = 6011,
    #[msg("epoch is zero — epochs are 1-indexed")]
    ZeroEpoch = 6012,
    #[msg("baseline_hash is all zeros — refusing to issue against an empty baseline")]
    ZeroBaselineHash = 6013,

    // ── State preconditions ─────────────────────────────────────────────────
    #[msg("the score / alert pair is inconsistent: a RED alert needs immediate_red \
           or a low score; a GREEN alert needs a high score")]
    InconsistentScoreAlert = 6020,
    #[msg("no baseline has been recorded for this agent — record one before issuing")]
    BaselineNotRecorded = 6021,

    // ── Day 27: 3-of-5 threshold signing ────────────────────────────────────
    #[msg("issuer cluster size invalid — must be 1 (single-key) or 3..=5 (BFT)")]
    InvalidClusterSize = 6030,
    #[msg("duplicate pubkey in the issuer cluster key set")]
    DuplicateClusterKey = 6031,
    #[msg("threshold invalid — must be 1..=cluster_size and a strict majority for BFT")]
    InvalidThreshold = 6032,
    #[msg("certificate write carries fewer valid cluster signatures than the threshold")]
    InsufficientSignatures = 6033,
    #[msg("supplied instructions sysvar does not match the expected sysvar pubkey")]
    WrongInstructionsSysvar = 6034,
    #[msg("Ed25519 precompile instruction is malformed or truncated")]
    MalformedEd25519Instruction = 6035,
    #[msg("Ed25519 instruction references another instruction's data — refused")]
    CrossInstructionReference = 6036,
    #[msg("Ed25519 signed message length is not the expected 32-byte digest")]
    WrongDigestLength = 6037,

    // ── VULN-06: baseline write gating ──────────────────────────────────────
    #[msg("signer is not authorised to write this agent's baseline — must be \
           the agent itself or a cluster signing key")]
    UnauthorizedBaselineWriter = 6040,
    #[msg("baseline rotation refused — a baseline for this agent was already \
           recorded at this epoch; rotate at a later epoch")]
    BaselineRotationTooSoon = 6041,
    #[msg("baseline epoch is not strictly greater than the previously recorded \
           epoch — baseline records are appendable only and monotonic")]
    BaselineEpochNotMonotonic = 6042,

    // ── VULN-16: CPI caller allow-list ──────────────────────────────────────
    #[msg("issue_certificate was CPI-invoked by an unrecognised program — \
           only a direct top-level call or a CPI from the configured \
           health_oracle program is permitted")]
    UntrustedCpiCaller = 6050,
    #[msg("issue_certificate could not read the top-level instruction from \
           the Instructions sysvar — refusing to issue a cert without \
           caller attribution")]
    CallerIntrospectionFailed = 6051,

    // ── AW-01: input-provenance commitment ──────────────────────────────────
    #[msg("input_commitment is all zeros — the cluster must agree on the \
           input-provenance commitment before issuing a cert (AW-01); a \
           zero commitment indicates the off-chain submitter skipped the \
           per-node + cross-node input binding")]
    MissingInputCommitment = 6060,

    // ── AW-01-EXT: Solana slot-anchor verification ──────────────────────────
    #[msg("slot_anchor is all zeros — the cluster must pin a Solana slot \
           anchor (AW-01-EXT) so the cert can be verified against the \
           SlotHashes sysvar")]
    MissingSlotAnchor = 6070,
    #[msg("supplied SlotHashes sysvar does not match the expected sysvar pubkey")]
    WrongSlotHashesSysvar = 6071,
    #[msg("slot_anchor.slot is older than the SlotHashes sysvar window \
           (~512 slots / ~3.4 min) — submit the cert closer to the scoring \
           time so the anchor is still verifiable on chain")]
    SlotAnchorTooOld = 6072,
    #[msg("slot_anchor.block_hash does not match Solana's recorded hash for \
           that slot — the cluster pinned an anchor Solana does not recognise; \
           either every cluster node reads from a poisoned upstream, or the \
           submitter forged the anchor (AW-01-EXT defence-in-depth caught it)")]
    SlotAnchorHashMismatch = 6073,

    // ── AW-01-EXT.6: certificate challenge instruction ──────────────────────
    #[msg("challenge cluster not configured — issuer_config has zero attester \
           keys or zero threshold; rotate the attester cluster in before \
           filing challenges")]
    NoAttesterCluster = 6080,
    #[msg("certificate predates AW-01-EXT (layout_version < 4) and has no slot \
           anchor to challenge")]
    PreV4CertNotChallengeable = 6081,
    #[msg("a challenge has already been filed against this certificate — \
           outcome is permanent (Upheld or Rejected)")]
    ChallengeAlreadyFiled = 6082,
    #[msg("certificate is too old to challenge — challenge window is the \
           configured CHALLENGE_WINDOW_SECONDS (default 90 days) from \
           issued_at")]
    ChallengeExpired = 6083,
    #[msg("challenge carries fewer valid attester signatures than the \
           challenge_threshold")]
    InsufficientChallengeAttesters = 6084,
    #[msg("challenge invalid cluster size — must be 1..=MAX_CHALLENGE_ATTESTER_KEYS")]
    InvalidAttesterClusterSize = 6086,
    #[msg("duplicate pubkey in the challenge-attester key set")]
    DuplicateAttesterKey = 6087,
    #[msg("challenge-attester key overlaps the cert-signing cluster — the \
           attester cluster must be DISJOINT (independent re-checkers)")]
    AttesterOverlapsCluster = 6088,
    #[msg("challenge_threshold invalid — must be 1..=challenge_attester_keys.len()")]
    InvalidChallengeThreshold = 6089,

    // ── AW-03: on-chain baseline data-availability proof ────────────────────
    #[msg("baseline_commit_nonce is zero — record_baseline now requires the \
           AgentRegistration.commit_nonce that the baseline_hash was committed \
           at on health-oracle (AW-03); pass it through so the cert can locate \
           the on-chain DA account")]
    ZeroBaselineCommitNonce = 6090,
    #[msg("baseline_commit_nonce is not strictly greater than the previously \
           recorded nonce — baseline-data nonces are appendable only and \
           monotonic; a same/lower nonce would mask a stale DA account")]
    BaselineCommitNonceNotMonotonic = 6091,

    // ── AW-04: scoring-engine provenance ────────────────────────────────────
    #[msg("scoring_code_hash is all zeros — the cluster must compute the \
           canonical scoring-bundle hash before issuing a cert (AW-04); a \
           zero hash indicates the off-chain submitter skipped the scoring-\
           kernel provenance binding")]
    MissingScoringCodeHash = 6100,
    #[msg("score_components_hash is all zeros — every cert must publish a \
           paired ScoreComponentsAccount with the per-dimension breakdown \
           (AW-04); a zero hash indicates the off-chain submitter skipped \
           the score-components binding")]
    MissingScoreComponentsHash = 6101,
    #[msg("score-components payload is empty — refusing to write an empty \
           components account")]
    ScoreComponentsPayloadEmpty = 6102,
    #[msg("score-components payload exceeds MAX_SCORE_COMPONENTS_PAYLOAD_LEN — \
           the off-chain serializer drifted from the canonical form")]
    ScoreComponentsPayloadTooLarge = 6103,
    #[msg("sha256(score_components_payload) != score_components_hash — the \
           on-chain bytes and the cluster-signed hash disagree; refusing \
           to write the components account (AW-04 invariant)")]
    ScoreComponentsHashMismatch = 6104,

    // ── DBP-2: VerifiedConsumer registration / revocation ───────────────────
    #[msg("integration_hash is all zeros — refusing to mint a VerifiedConsumer \
           PDA against an empty manifest hash (DBP-2)")]
    ZeroIntegrationHash = 6110,
    #[msg("partner_wallet is the default (zero) pubkey — refusing to register a \
           VerifiedConsumer for the zero identity")]
    ZeroPartnerWallet = 6111,
    #[msg("VerifiedConsumer badge is already revoked — re-revocation is a no-op \
           and refused so the audit trail records exactly one revoke event per \
           badge")]
    BadgeAlreadyRevoked = 6112,
    #[msg("signer is not authorised to revoke this VerifiedConsumer — must be \
           either the partner_wallet (self-revoke) or the issuer_config \
           authority (admin revoke)")]
    UnauthorizedRevoke = 6113,
    #[msg("revoke_reason is not a recognised RevokeReason variant — must be \
           PartnerSelfRevoke (1), AdminBadFaith (2), or AdminTerminated (3); \
           NotRevoked (0) is invalid for a revoke call")]
    InvalidRevokeReason = 6114,
    #[msg("revoke_reason does not match the signer — partner_wallet may only \
           self-revoke with PartnerSelfRevoke (1); admin revokes may only use \
           AdminBadFaith (2) or AdminTerminated (3)")]
    RevokeReasonSignerMismatch = 6115,

    // ── M-06: cluster-key rotation with proof-of-possession ─────────────────
    #[msg("cluster rotation refused — not all new cluster keys produced a \
           valid Ed25519 signature over the canonical rotation digest \
           (M-06 proof-of-possession); each new key MUST sign in the same \
           transaction so the operator cannot install a key whose privkey \
           they do not control")]
    MissingRotationProofOfPossession = 6120,
    #[msg("cluster rotation refused — config_version would overflow u32 on \
           increment; rotate via a fresh IssuerConfig deployment instead")]
    RotationConfigVersionOverflow = 6121,
    #[msg("cluster rotation refused — the supplied new_cluster_keys is \
           IDENTICAL to the current set; a rotation MUST change at least \
           one key or threshold to be meaningful (and to consume a \
           config_version bump)")]
    RotationNoOpRejected = 6122,
    #[msg("H-2: cluster rotation refused — a Byzantine fault-tolerant cluster \
           (>= MIN_BFT_CLUSTER_KEYS) may not be rotated BELOW the BFT floor. \
           Without this, a compromised issuer authority could collapse a \
           3-of-5 quorum down to a single attacker key and forge every \
           certificate with one signature. A degenerate single-issuer cluster \
           (bootstrapped at size 1 via initialize_config) may still rotate in \
           place or PROMOTE to a BFT cluster; it just cannot be the target of \
           a downgrade once it is BFT.")]
    ClusterBftFloorViolation = 6123,

    // ── M-09: canonical PDA bind on `get_certificate` ─────────────────────────
    #[msg("get_certificate refused — the supplied certificate account is \
           not the canonical [\"cert\", agent_wallet, epoch_le] PDA for the \
           certificate-issuer program. M-09 binds the CertificateRead event \
           to the canonical address ON CHAIN so a downstream consumer that \
           trusts only the event payload can never be fooled by a same-\
           shaped event emitted from a non-canonical account.")]
    CertificatePdaMismatch = 6130,

    // ── M-12: alert-vector hash binding on issue_certificate ────────────────
    #[msg("M-12: issue_certificate refused — the alert-vector hash recomputed \
           from the WRITTEN cert account fields (score, alert_tier, flags, \
           immediate_red) does not equal the hash computed from the input \
           args before the write. The on-chain handler computes \
           sha256(score_be || alert_tier || flags_be || immediate_red_byte) \
           twice and asserts equality post-write so a future refactor that \
           field-shadow-writes the wrong cert slot can never emit a \
           CertificateIssued event whose alert_vector_hash silently \
           disagrees with the stored bytes. The off-chain consumer treats \
           this hash as the canonical tamper-detection artifact for the \
           alert vector and would have no defence against a same-block \
           write-shadow bug without this gate.")]
    InvalidAlertVectorBinding = 6131,

    // ── Day 38 / Cert v2: full diagnostic certificate ───────────────────────
    #[msg("Day 38: issue_certificate refused — failure_mode_bitmask & \
           0xFFFF_FFFF != flags as u64. The legacy v1..v8 invariant is that \
           `flags` is a u32 view onto the same failure-mode bit field as the \
           v9 u64 bitmask; a mismatch would drift the on-chain record from \
           every legacy consumer that only reads `flags`. Either the cluster's \
           per-bit u64 majority disagrees with the u32 flags it published, or \
           the off-chain submitter computed them independently — both indicate \
           a bug that must surface, not be silently accepted.")]
    LegacyFlagsBitmaskMismatch = 6140,

    // ── H-3: two-step authority transfer ────────────────────────────────────
    #[msg("H-3: propose_authority_transfer refused — the proposed new \
           authority is the all-zero default pubkey. Refusing to schedule a \
           handoff to an unspendable address, which would brick the cert \
           system's admin authority forever.")]
    ZeroPendingAuthority = 6150,
    #[msg("H-3: propose_authority_transfer refused — the proposed new \
           authority equals the CURRENT authority. A transfer must change \
           the key to be meaningful.")]
    PendingAuthorityIsCurrent = 6151,
    #[msg("H-3: authority-transfer action refused — no transfer is currently \
           pending (pending_authority is the all-zero default). Propose one \
           first.")]
    NoPendingAuthorityTransfer = 6152,
    #[msg("H-3: accept_authority_transfer refused — the signer is not the \
           pending_authority recorded by propose_authority_transfer. Only the \
           proposed successor may accept (this proves it controls the key).")]
    NotPendingAuthority = 6153,
    #[msg("H-3: accept_authority_transfer refused — the 48h transfer timelock \
           has not elapsed. The successor may accept only after \
           authority_transfer_eta, giving a monitoring operator a window to \
           cancel a malicious or mistaken proposal.")]
    AuthorityTransferTimelockNotElapsed = 6154,

    // ── H-4: on-chain certificate freshness + agent-age GREEN floor ─────────
    #[msg("H-4 / NSS-3: issue_certificate refused — a GREEN certificate may \
           not be issued for an agent younger than MIN_GREEN_AGE_SECONDS \
           (14 days) since its FIRST recorded baseline. This is the on-chain \
           backstop against the set-up-and-borrow / score-inflation class: a \
           brand-new wallet cannot present a fully-trusted GREEN certificate. \
           Issue a YELLOW (or lower) cert until the agent ages past the floor.")]
    AgentTooYoungForGreen = 6160,
    #[msg("H-4 / TA-6: get_certificate refused — the certificate is older than \
           the caller-supplied max_age_seconds. The certificate exists and is \
           the canonical PDA, but it is STALE relative to the caller's \
           freshness requirement. (Pass max_age_seconds = 0 to disable this \
           on-chain freshness gate.)")]
    CertificateStale = 6161,

    // ── H-5: cluster-key fault-domain diversity ─────────────────────────────
    #[msg("H-5: cluster config refused — cluster_key_domains length must equal \
           cluster_keys length (one fault-domain id per key).")]
    ClusterDomainsLengthMismatch = 6170,
    #[msg("H-5: cluster config refused — the cluster spans fewer DISTINCT fault \
           domains than the threshold, so no quorum could ever satisfy the \
           domain-diversity rule. Spread the keys across at least `threshold` \
           independent host/region domains.")]
    InsufficientDomainDiversity = 6171,
    #[msg("H-5: certificate write refused — the signing quorum spans fewer \
           DISTINCT fault domains than the threshold. Multiple cluster keys on \
           one host/region count ONCE, so a single compromised fault domain \
           cannot reach the threshold; the quorum must come from `threshold` \
           independent domains.")]
    InsufficientSignerDiversity = 6172,

    // ── M-2: nested-CPI hardening of the cpi-guard ──────────────────────────
    #[msg("M-2: certificate write refused — issue_certificate was reached via a \
           NESTED CPI (stack height > 2). The instructions-sysvar only exposes \
           the TOP-LEVEL instruction, which is NOT the immediate caller once \
           there is more than one CPI hop, so the caller cannot be attributed. \
           The protocol has exactly two legitimate paths — a direct top-level \
           call, or a single CPI hop from health-oracle — and fails closed on \
           anything deeper.")]
    NestedCpiCallerRejected = 6180,
}
