// =============================================================================
// audit/trident/targets/certificate-issuer/fuzz_target.rs
//
// Trident fuzz harness for the certificate-issuer program.
//
// The Day-27 threshold-signature path is the prime fuzz target: the
// Ed25519 precompile-instruction parser handles ATTACKER-CONTROLLED
// 144-byte blobs from the Instructions sysvar. A single panic in parsing
// would be a critical CVE. The fuzzer generates arbitrary blob payloads,
// out-of-bounds offsets, malformed headers, oversize messages,
// duplicated signers — anything an adversary's transaction might
// contain. Zero panics is non-negotiable.
// =============================================================================

use anchor_lang::prelude::*;
use trident_client::prelude::*;
use trident_client::fuzzing::*;

use certificate_issuer::instruction as ci_ix;

#[derive(Arbitrary, Debug)]
pub struct FuzzData {
    pub instruction: FuzzInstruction,
}

#[derive(Arbitrary, Debug)]
pub enum FuzzInstruction {
    InitializeConfig(InitConfigArgs),
    RecordBaseline(RecordBaselineArgs),
    IssueCertificate(IssueCertArgs),
    GetCertificate(GetCertArgs),
}


// ── Per-ix argument shapes ───────────────────────────────────────────────────

#[derive(Arbitrary, Debug)]
pub struct InitConfigArgs {
    pub issuer_node:              Pubkey,
    pub cluster_keys:             Vec<Pubkey>,    // bounded 0..=8 by Trident; covers
                                                  // reject (2, 6+) and accept (1,3,4,5)
    pub threshold:                u8,             // u8 — covers 0, all valid, overflow
    // VULN-16: the canonical health-oracle program ID. Arbitrary Pubkey
    // (including Pubkey::default() = "CPI allow-list disabled") so the
    // fuzzer explores both enabled and disabled allow-list configurations.
    pub health_oracle_program_id: Pubkey,
}

#[derive(Arbitrary, Debug)]
pub struct RecordBaselineArgs {
    pub agent_wallet:          Pubkey,
    pub baseline_hash:         [u8; 32],
    pub baseline_algo_version: u8,
    pub baseline_block_height: u64,
}

#[derive(Arbitrary, Debug)]
pub struct IssueCertArgs {
    // The cert fields — fuzzer generates arbitrary u16/u32/bool, the
    // handler validates ranges.
    pub epoch:         u64,
    pub score:         u16,
    pub alert_tier:    u8,
    pub flags:         u32,
    pub immediate_red: bool,

    // The Ed25519 precompile ATTACK SURFACE.
    // The fuzz harness pre-builds 0..=8 precompile instructions per tx,
    // each with arbitrary 0..=300 byte data blobs and arbitrary headers.
    // The handler MUST NOT panic on any of them — only return a typed
    // CertificateError variant (MalformedEd25519Instruction,
    // CrossInstructionReference, WrongDigestLength, ...).
    pub ed25519_blobs: Vec<Vec<u8>>,
}

#[derive(Arbitrary, Debug)]
pub struct GetCertArgs {
    pub agent_wallet: Pubkey,
    pub epoch:        u64,
}


// ── Fuzz driver ──────────────────────────────────────────────────────────────

fn main() {
    fuzz_trd!(fuzz_iteration: FuzzData);
}

fn fuzz_iteration(fuzz_data: FuzzData, client: &mut impl FuzzClient) {
    let _ = match fuzz_data.instruction {
        FuzzInstruction::InitializeConfig(args) => {
            ci_ix::initialize_config(
                client, args.issuer_node, args.cluster_keys, args.threshold,
                args.health_oracle_program_id,
            )
        }
        FuzzInstruction::RecordBaseline(args) => {
            ci_ix::record_baseline(
                client, args.agent_wallet, args.baseline_hash,
                args.baseline_algo_version, args.baseline_block_height,
            )
        }
        FuzzInstruction::IssueCertificate(args) => {
            // Attach the arbitrary Ed25519 blobs to the tx as precompile
            // instructions BEFORE invoking issue_certificate, exactly as
            // a real attacker would.
            client.attach_ed25519_blobs(args.ed25519_blobs.clone());
            ci_ix::issue_certificate(
                client, args.epoch, args.score, args.alert_tier,
                args.flags, args.immediate_red,
            )
        }
        FuzzInstruction::GetCertificate(args) => {
            ci_ix::get_certificate(client, args.agent_wallet, args.epoch)
        }
    };
    // Zero panics. Any panic persists the input under audit/reports/fuzz_crashes/.
}
