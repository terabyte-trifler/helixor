# Design — `challenge_certificate` (AW-01-EXT.6)

**Status:** IMPLEMENTED. Phase 4 ship-blocker, resolved.
- Handler: `programs/certificate-issuer/src/instructions/challenge_certificate.rs`
- Account: `programs/certificate-issuer/src/state/challenge_record.rs`
- Cert state byte: `HealthCertificate.challenge_state` (layout v5)
- IssuerConfig fields: `challenge_attester_keys`, `challenge_threshold`
- Errors: `NoAttesterCluster` (12080) through `InvalidChallengeThreshold` (12089)
- Events: `CertificateRepudiated`, `ChallengeRejected`

**Owner:** certificate-issuer program.
**Lineage:** AW-01 (input-provenance commitment) → AW-01-EXT (Solana slot
anchor as third source of truth) → AW-01-EXT.6 (this doc) — the
public, on-chain rebuttal path for a cert whose slot anchor cannot be
re-verified against the SlotHashes sysvar.

---

## Problem this closes

The slot anchor in a `HealthCertificate` (layout v4: `slot_anchor_slot` +
`slot_anchor_hash`) is verified ONCE, at write time, inside
`issue_certificate::handler` → `verify_slot_anchor`. After that the
SlotHashes sysvar moves on — its window is ~512 slots (~3.4 min). A
certificate written at slot N is permanently stamped with the
`(slot, block_hash)` the cluster pinned, but the on-chain verifier has
no way to re-prove that stamp later because the sysvar no longer
contains slot N.

This is fine while the cluster is honest. It is **not** fine in the
threat model AW-01-EXT exists to address: a coordinated upstream
poisoning where every cluster node was reading from compromised RPCs
and signed a cert whose `slot_anchor_hash` does not match what the
Solana ledger actually recorded for that slot. Once the sysvar window
moves on, the lie is permanent on-chain and indistinguishable from a
truthful cert.

`challenge_certificate` is the rebuttal: any third party who can
furnish a fresh proof that `(slot, block_hash)` was wrong gets to mark
the cert REPUDIATED on-chain, and the cluster takes the slash.

## Threat model

In scope:

* **Coordinated upstream poisoning.** All N cluster nodes were
  reading the same poisoned RPC fleet at scoring time. The
  signatures are real, the input-commitment commits to the cluster's
  shared view, the slot anchor matches because the poisoned RPCs
  agreed on a (fake) block hash for the slot. The challenge re-walks
  the actual Solana ledger via a fresh validator vote-account snapshot
  or BlockHeader proof and shows the recorded hash does NOT match.
* **Liveness-window adversary.** Cluster wrote a cert whose anchor
  was technically valid at the slot it was pinned to (~512-slot
  window) but the challenger can demonstrate the ledger never
  contained that block — e.g. a forked / orphaned hash that lost the
  vote race.

Out of scope (other audits cover these):

* Wrong score for an honest input — covered by the appeal flow
  (`launch/runbooks/challenge_filed.md`).
* Mis-signed cert (threshold violation) — already rejected at
  `issue_certificate` write time by `signing::verify_threshold`.

## Instruction signature

```rust
pub fn challenge_certificate(
    ctx: Context<ChallengeCertificate>,
    // The block-hash proof. Two forms — we pick one before
    // implementation. See "Proof shape" below.
    proof: BlockHashProof,
) -> Result<()>
```

Where:

```rust
pub enum BlockHashProof {
    /// Form A — naïve. The challenger posts the historical block hash
    /// from a trusted off-chain source AND a recent SlotHashes entry
    /// that chains back via parent-hash links. ~impossible on-chain.
    /// Listed for completeness, NOT recommended.
    SlotHashesChain { intermediate_entries: Vec<(u64, [u8; 32])> },

    /// Form B — recommended. Re-anchor in TODAY's SlotHashes window
    /// PLUS an off-chain attestation from M-of-N independent
    /// challenge-attesters (a separate, smaller multisig that signs
    /// historical-slot lookups). The on-chain handler verifies M
    /// Ed25519 precompile signatures over `(slot, true_block_hash)`.
    AttestedHistorical {
        true_block_hash:  [u8; 32],
        attester_count:   u8,           // M satisfied → success
    },

    /// Form C — alternative. Pin a VoteAccount that voted on the
    /// disputed slot in its `votes` ring. Cheapest on-chain proof
    /// IF we accept VoteAccount as canonical evidence (it is, for
    /// any slot still inside a recent vote-account snapshot — much
    /// wider than SlotHashes).
    VoteAccountProof { vote_account_pubkey: Pubkey },
}
```

Phase-4 implementation MUST pick Form B (AttestedHistorical). Form C
is the right long-term answer but requires a VoteAccount parser inside
the certificate-issuer, which is out of scope until Phase 5.

## Accounts

```rust
#[derive(Accounts)]
pub struct ChallengeCertificate<'info> {
    /// The cert being challenged. MUST be layout_version ≥ 4 (a v3 or
    /// older cert has no slot anchor to challenge).
    #[account(
        mut,
        seeds = [b"cert", certificate.agent_wallet.as_ref(),
                 &certificate.epoch.to_le_bytes()],
        bump,
        constraint = certificate.layout_version >= 4
            @ CertificateError::PreV4CertNotChallengeable,
        constraint = certificate.challenge_state == ChallengeState::None
            @ CertificateError::ChallengeAlreadyFiled,
    )]
    pub certificate: Account<'info, HealthCertificate>,

    /// The IssuerConfig — defines the challenge-attester cluster
    /// (separate from the cert-signing cluster, by design — see
    /// "Trust assumptions" below) and the M-of-N threshold.
    #[account(seeds = [b"issuer_config"], bump = issuer_config.bump)]
    pub issuer_config: Account<'info, IssuerConfig>,

    /// The slash-record PDA the handler initialises if the challenge
    /// succeeds. ["challenge", cert] — one per cert.
    #[account(
        init,
        payer = challenger,
        space = 8 + ChallengeRecord::SIZE,
        seeds = [b"challenge", certificate.key().as_ref()],
        bump,
    )]
    pub challenge_record: Account<'info, ChallengeRecord>,

    #[account(mut)]
    pub challenger: Signer<'info>,

    /// CHECK — Instructions sysvar, for verifying the attester
    /// signatures attached to this transaction.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}
```

New on-chain state, ~88 bytes:

```rust
#[account]
pub struct ChallengeRecord {
    pub certificate:        Pubkey,        // 32
    pub challenger:         Pubkey,        // 32
    pub filed_at:           i64,           //  8
    pub true_block_hash:    [u8; 32],      // 32  (only if attested form)
    pub state:              ChallengeState,//  1
    pub bump:               u8,            //  1
}
```

And one new field on `HealthCertificate`:

```rust
pub challenge_state: ChallengeState,    // 1 byte from _reserved
```

(`ChallengeState = None | Filed | Upheld | Rejected`.) `_reserved`
drops to 14, layout version → v5.

## Handler flow

1. **Account-level gate.** Anchor checks: cert is v4+, no existing
   challenge, challenge-record PDA derivable and uninitialised.
2. **Parse proof.** For Form B, recover M Ed25519 precompile ixs from
   the Instructions sysvar where the signed message is exactly
   `b"phylanx-aw01-ext-challenge" || cert_pubkey || true_block_hash`.
3. **Verify M-of-N over attester cluster.** Same pattern as
   `signing::verify_threshold`. Attester cluster keys come from
   `issuer_config.challenge_attester_keys` (new Vec field — adds
   `4 + 32*N` bytes to IssuerConfig). Threshold from
   `issuer_config.challenge_threshold` (1 byte).
4. **The actual check.** `cert.slot_anchor_hash != true_block_hash`.
   If they match, the challenge is FRIVOLOUS — reject with
   `ChallengeFrivolous` and burn the challenger's `lamports_at_stake`
   (TBD, ~0.1 SOL — high enough to deter spam, low enough not to
   gate honest reporting).
5. **Mark.** `certificate.challenge_state = ChallengeState::Upheld`,
   `challenge_record.state = Upheld`, write `true_block_hash` into
   the record.
6. **Emit.** `CertificateRepudiated { cert, agent, epoch, challenger,
   true_block_hash }`. Downstream consumers (the SDK's
   `verifyAgainstSolanaLedger` already returns `AnchorHashMismatch`
   for this case off-chain — the on-chain repudiation is the
   permanent, audit-grade record).

## Slashing

`challenge_certificate` does NOT itself slash the cluster keys — that
belongs to `slash_authority::record_slash` which already exists and
already handles the cluster-key path. The flow is:

```
challenge_certificate (this ix)
  → emits CertificateRepudiated
  → slash_authority::record_slash (separate ix, ~next slot)
    → marks each cluster key with one strike + lamports forfeiture
```

Keeping the two ixs separate has two benefits: (1) the challenge ix
is small and cheap so legitimate challengers don't get priced out,
(2) the slash ix already audits its own authority gating
(`slash_authority` requires a Squads multisig in production) so we
don't re-implement that gate here.

## Trust assumptions

The **challenge-attester cluster** must be:

* **Disjoint from the cert-signing cluster.** Same keys signing both
  sides defeats the whole purpose — a compromised cert-signing
  cluster could refuse to attest its own challenges. Operationally:
  ~3–5 third-party nodes (a friendly L2 team, a Solana validator, an
  exchange's ops desk, etc.) run a tiny attester process that does
  one job: given a (slot, block_hash) request, fetch the slot from
  their own RPC, sign the true (slot, true_block_hash) if asked.
* **M-of-N with M ≥ 2.** Even one independent re-checker is enough
  to catch a corrupted cert-signing cluster, but 2 prevents a single
  compromised attester from filing frivolous challenges.

The attester cluster is configured at deployment in `IssuerConfig` and
ROTATED via the same time-locked, N-of-M-attested governance pattern
already implemented in health-oracle for the cert-signing cluster
(`propose_oracle_key_rotation` / `attest_oracle_key_rotation` /
`enact_oracle_key_rotation` / `cancel_oracle_key_rotation`). The
implementation should copy that pattern verbatim, not invent a new
one.

## Replay protection

The `ChallengeRecord` PDA is `["challenge", cert]` — one per cert.
Anchor's `init` guarantees init-once, so the same cert cannot be
challenged twice. A `Rejected` challenge consumes the slot
permanently: the challenger paid rent + their stake, and the cert is
now provably honest. This is intentional — a cert that survived a
challenge attempt has a stronger on-chain provenance, not a weaker
one.

## Open questions (resolve before implementation)

1. **Stake amount.** What's the right `lamports_at_stake` for a
   frivolous challenge? Too low → spam; too high → honest reporters
   priced out. Suggested starting point: 0.1 SOL with an upgradeable
   value on `IssuerConfig`.
2. **Time bound.** Should challenges expire? Probably YES — a cert
   from 6 months ago has compounding interest implications for the
   slashing math. Suggest: 90 days from `cert.issued_at`. After that
   the cert is considered final and the only recourse is a manual
   governance instrument.
3. **Form C migration path.** When we add VoteAccount parsing in
   Phase 5, the challenge ix should accept EITHER Form B or Form C
   — Form C dominates Form B (no attester cluster required), but
   Form B remains as the backstop for slots already aged out of the
   vote-account snapshot.
4. **Interaction with `slash_authority::settle`.** A successful
   challenge raised AFTER `settle` has already credited the cluster
   needs a clawback path. Best handled by making the cluster
   `settle` window LONGER than the challenge window (i.e. 91 days
   minimum settle floor if challenge window is 90 days), not by
   inventing a clawback.

## What does NOT change

* `verify_slot_anchor` stays exactly as it is — the write-time check
  is the first line of defence; the challenge ix is the second.
* The off-chain `verifyAgainstSolanaLedger` in
  `phylanx-sdk/src/input_provenance.ts` already returns
  `AnchorHashMismatch` for the same condition; this design adds the
  on-chain analogue. Consumers who want belt-and-braces can call
  both — the SDK function detects in milliseconds, the on-chain ix
  produces the permanent record.
* The input-provenance commitment (`input_commitment`, AW-01) is
  NOT what this ix challenges. AW-01 has its own divergence
  surface (FlagBit 7) handled by the existing `input_provenance.md`
  runbook. This ix is strictly about the SLOT ANCHOR portion of
  AW-01-EXT — the third source of truth.

## Build estimate

* state + errors + events: ~1 day
* handler + signature verification (reuses `signing::*`): ~2 days
* attester-cluster rotation ixs (4 ixs, copy from health-oracle): ~2 days
* tests (Rust unit + TS integration + audit scanner pins): ~2 days
* runbook + alerting: ~1 day

Total: ~8 dev-days. Recommend scheduling for Phase 5 sprint 2 — it
is NOT a launch blocker for Phase 4 because the write-time check
already catches the unsophisticated attack; this ix is the
defence-in-depth for the sophisticated coordinated-poisoning case.
