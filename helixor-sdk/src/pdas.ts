// =============================================================================
// helixor-sdk/src/pdas.ts — PDA derivation.
//
// Every PDA seed in the SDK is derived HERE, in one place, so the seed
// scheme is defined exactly once and cannot drift between the SDK and the
// on-chain programs. The seeds mirror the Rust:
//
//   certificate-issuer  HealthCertificate  ["cert", agent, epoch_le_u64]
//   certificate-issuer  BaselineStats      ["baseline", agent]
//   certificate-issuer  IssuerConfig       ["issuer_config"]
//   health-oracle       EpochState         ["epoch_state"]
// =============================================================================

import { PublicKey } from "@solana/web3.js";

const enc = (s: string): Buffer => Buffer.from(s, "utf-8");

/** Encode a u64 epoch as 8 little-endian bytes — matches Rust `to_le_bytes`. */
export function epochToLeBytes(epoch: number | bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(epoch));
  return buf;
}

/** The epoch-keyed HealthCertificate PDA on the certificate-issuer program. */
export function certificatePda(
  certificateIssuer: PublicKey,
  agent: PublicKey,
  epoch: number | bigint
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("cert"), agent.toBuffer(), epochToLeBytes(epoch)],
    certificateIssuer
  )[0];
}

/** The per-agent BaselineStats PDA on the certificate-issuer program. */
export function baselineStatsPda(
  certificateIssuer: PublicKey,
  agent: PublicKey
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("baseline"), agent.toBuffer()],
    certificateIssuer
  )[0];
}

/** The IssuerConfig singleton on the certificate-issuer program. */
export function issuerConfigPda(certificateIssuer: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("issuer_config")],
    certificateIssuer
  )[0];
}

/** The EpochState singleton on the health-oracle program. */
export function epochStatePda(healthOracle: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("epoch_state")],
    healthOracle
  )[0];
}
