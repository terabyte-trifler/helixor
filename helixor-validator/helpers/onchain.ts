import fs from "node:fs";

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

import type { ValidationEnv } from "./env";

const REGISTER_AGENT_DISCRIMINATOR = Uint8Array.from([
  0x87, 0x9d, 0x42, 0xc3, 0x02, 0x71, 0xaf, 0x1e,
]);

export function loadKeypairFromFile(filePath: string): Keypair {
  const secret = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secret));
}

export function deriveAgentPdas(programId: PublicKey, agentWallet: string): {
  registrationPda: PublicKey;
  escrowVaultPda: PublicKey;
} {
  const agent = new PublicKey(agentWallet);
  const [registrationPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), agent.toBuffer()],
    programId,
  );
  const [escrowVaultPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("escrow"), agent.toBuffer()],
    programId,
  );
  return { registrationPda, escrowVaultPda };
}

export async function registerAgentOnchain(
  env: ValidationEnv,
  owner: Keypair,
  agentSigner: Keypair,
  name: string,
): Promise<{ signature: string; registrationPda: string; escrowVaultPda: string }> {
  const conn = new Connection(env.solanaRpcUrl, "confirmed");
  const agentWallet = agentSigner.publicKey.toBase58();
  const agent = new PublicKey(agentWallet);
  const { registrationPda, escrowVaultPda } = deriveAgentPdas(env.programId, agentWallet);

  const existing = await conn.getAccountInfo(registrationPda);
  if (existing) {
    return {
      signature: "ALREADY_REGISTERED",
      registrationPda: registrationPda.toBase58(),
      escrowVaultPda: escrowVaultPda.toBase58(),
    };
  }

  const nameBytes = new TextEncoder().encode(name);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(nameBytes.length, 0);
  const data = Buffer.concat([
    Buffer.from(REGISTER_AGENT_DISCRIMINATOR),
    lenBuf,
    Buffer.from(nameBytes),
  ]);

  const ix = new TransactionInstruction({
    programId: env.programId,
    keys: [
      { pubkey: owner.publicKey, isSigner: true, isWritable: true },
      { pubkey: agent, isSigner: true, isWritable: false },
      { pubkey: registrationPda, isSigner: false, isWritable: true },
      { pubkey: escrowVaultPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const latest = await conn.getLatestBlockhash("confirmed");
  const tx = new Transaction({
    feePayer: owner.publicKey,
    recentBlockhash: latest.blockhash,
  }).add(ix);

  tx.sign(owner, agentSigner);
  const signature = await conn.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });
  await conn.confirmTransaction(
    {
      signature,
      blockhash: latest.blockhash,
      lastValidBlockHeight: latest.lastValidBlockHeight,
    },
    "confirmed",
  );

  return {
    signature,
    registrationPda: registrationPda.toBase58(),
    escrowVaultPda: escrowVaultPda.toBase58(),
  };
}
