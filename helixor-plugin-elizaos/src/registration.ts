// =============================================================================
// @elizaos/plugin-helixor — on-chain registration helper.
//
// IMPORTANT: this module does NOT submit transactions. It builds an unsigned
// transaction the operator signs with their wallet (Phantom, hardware, etc).
//
// Why: registering an agent transfers 0.01 SOL escrow from the OWNER wallet.
// We never want the plugin to hold the owner's private key. The flow is:
//
//   1. Plugin builds the register_agent tx
//   2. Operator signs via their wallet
//   3. Operator submits via their RPC of choice
//   4. agent_sync (Day 4) sees the tx and registers the agent
//
// For automation environments (CI, hosted infra) operators provide a signer
// keypair separately and call submitRegistrationWithKeypair() — explicit
// opt-in.
// =============================================================================

import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  type Keypair,
} from "@solana/web3.js";

const HELIXOR_PROGRAM_ID = new PublicKey("Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P");

// Anchor instruction discriminator for "register_agent"
//   = first 8 bytes of sha256("global:register_agent")
// Hardcoded to avoid runtime hashing dependency. If the program is renamed,
// regenerate this.
const REGISTER_AGENT_DISCRIMINATOR = new Uint8Array([
  // sha256("global:register_agent")[0..8]
  0x87, 0x9d, 0x42, 0xc3, 0x02, 0x71, 0xaf, 0x1e,
]);

const MAX_NAME_BYTES = 64;

export interface RegistrationArgs {
  agentWallet: string;
  ownerWallet: string;
  name:        string;
  rpcUrl:      string;
}

export interface PreparedRegistration {
  /** Base64-encoded unsigned transaction. Operator signs + submits. */
  unsignedTxBase64: string;

  /** Helpful PDAs for the operator's UI. */
  registrationPda: string;
  escrowVaultPda:  string;

  /** Recent blockhash used (caller must submit before it expires). */
  recentBlockhash: string;
}

export class RegistrationError extends Error {
  constructor(msg: string) {
    super(`[Helixor] ${msg}`);
    this.name = "RegistrationError";
  }
}

/** Validate args. Throws on bad input. */
function validateArgs(args: RegistrationArgs): void {
  const PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

  if (!PUBKEY_RE.test(args.agentWallet)) {
    throw new RegistrationError(`Invalid agent_wallet: ${args.agentWallet}`);
  }
  if (!PUBKEY_RE.test(args.ownerWallet)) {
    throw new RegistrationError(`Invalid owner_wallet: ${args.ownerWallet}`);
  }
  if (args.agentWallet === args.ownerWallet) {
    throw new RegistrationError("agent_wallet must differ from owner_wallet");
  }

  const nameBytes = new TextEncoder().encode(args.name);
  if (nameBytes.length === 0) {
    throw new RegistrationError("name cannot be empty");
  }
  if (nameBytes.length > MAX_NAME_BYTES) {
    throw new RegistrationError(
      `name is ${nameBytes.length} bytes (max ${MAX_NAME_BYTES} bytes). UTF-8 emoji count as 4 bytes each.`,
    );
  }

  if (!/^https?:\/\//.test(args.rpcUrl)) {
    throw new RegistrationError(`rpcUrl must start with http:// or https:// (got: ${args.rpcUrl})`);
  }
}

/** Derive PDA addresses. Pure function. */
export function derivePdas(agentWallet: string): {
  registrationPda: PublicKey;
  escrowVaultPda:  PublicKey;
} {
  const agent = new PublicKey(agentWallet);
  const [registrationPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), agent.toBuffer()],
    HELIXOR_PROGRAM_ID,
  );
  const [escrowVaultPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("escrow"), agent.toBuffer()],
    HELIXOR_PROGRAM_ID,
  );
  return { registrationPda, escrowVaultPda };
}

/**
 * Build an unsigned register_agent transaction.
 *
 * The returned base64 string can be:
 *   • Decoded via Transaction.from() in a wallet adapter (Phantom etc.)
 *   • Signed by the owner's wallet
 *   • Submitted to any Solana RPC
 *
 * Plugin never holds the owner's private key with this path.
 */
export async function prepareRegistration(args: RegistrationArgs): Promise<PreparedRegistration> {
  validateArgs(args);

  const owner = new PublicKey(args.ownerWallet);
  const agent = new PublicKey(args.agentWallet);
  const { registrationPda, escrowVaultPda } = derivePdas(args.agentWallet);

  // Encode RegisterParams { name: String }
  // Layout:
  //   [0..8]   discriminator
  //   [8..12]  name length (u32, LE)  — Borsh String prefix
  //   [12..]   name bytes (UTF-8)
  const nameBytes  = new TextEncoder().encode(args.name);
  const lengthBuf  = new Uint8Array(4);
  new DataView(lengthBuf.buffer).setUint32(0, nameBytes.length, true);

  const data = new Uint8Array(8 + 4 + nameBytes.length);
  data.set(REGISTER_AGENT_DISCRIMINATOR, 0);
  data.set(lengthBuf, 8);
  data.set(nameBytes, 12);

  const ix = new TransactionInstruction({
    programId: HELIXOR_PROGRAM_ID,
    keys: [
      { pubkey: owner,            isSigner: true,  isWritable: true  },
      { pubkey: agent,            isSigner: true,  isWritable: false },
      { pubkey: registrationPda,  isSigner: false, isWritable: true  },
      { pubkey: escrowVaultPda,   isSigner: false, isWritable: true  },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });

  const conn = new Connection(args.rpcUrl, "confirmed");
  const { blockhash } = await conn.getLatestBlockhash();

  const tx = new Transaction();
  tx.recentBlockhash = blockhash;
  tx.feePayer = owner;
  tx.add(ix);

  // Serialize unsigned (skip signature verification)
  const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });

  return {
    unsignedTxBase64: Buffer.from(serialized).toString("base64"),
    registrationPda:  registrationPda.toBase58(),
    escrowVaultPda:   escrowVaultPda.toBase58(),
    recentBlockhash:  blockhash,
  };
}

/**
 * EXPLICIT opt-in: submit a registration tx using a server-side keypair.
 * Use only in trusted infra (CI, automated registration services).
 * Never call this with a key you don't fully control.
 */
export async function submitRegistrationWithKeypair(
  args:    RegistrationArgs,
  ownerKp: Keypair,
): Promise<{ signature: string; registrationPda: string }> {
  if (ownerKp.publicKey.toBase58() !== args.ownerWallet) {
    throw new RegistrationError(
      "ownerKp.publicKey does not match args.ownerWallet — refusing to sign as the wrong owner.",
    );
  }

  const prepared = await prepareRegistration(args);

  const conn = new Connection(args.rpcUrl, "confirmed");
  const tx = Transaction.from(Buffer.from(prepared.unsignedTxBase64, "base64"));
  tx.sign(ownerKp);

  const signature = await conn.sendRawTransaction(tx.serialize(), {
    skipPreflight: false, preflightCommitment: "confirmed",
  });
  await conn.confirmTransaction({
    signature,
    blockhash: prepared.recentBlockhash,
    lastValidBlockHeight: (await conn.getLatestBlockhash()).lastValidBlockHeight,
  }, "confirmed");

  return { signature, registrationPda: prepared.registrationPda };
}
