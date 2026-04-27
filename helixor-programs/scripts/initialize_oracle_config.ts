import * as anchor from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import type { HealthOracle } from "../target/types/health_oracle";

async function main() {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.HealthOracle as anchor.Program<HealthOracle>;

  const oracleKeyArg = process.argv[2];
  const adminKeyArg = process.argv[3];

  if (!oracleKeyArg || !adminKeyArg) {
    throw new Error(
      "Usage: ts-node scripts/initialize_oracle_config.ts <oracle_pubkey> <admin_pubkey>",
    );
  }

  const oracleKey = new PublicKey(oracleKeyArg);
  const adminKey = new PublicKey(adminKeyArg);

  const [oracleConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("oracle_config")],
    program.programId,
  );

  const txSig = await program.methods
    .initializeOracleConfig({
      oracleKey,
      adminKey,
    })
    .accounts({
      deployer: provider.wallet.publicKey,
      systemProgram: anchor.web3.SystemProgram.programId,
    } as any)
    .rpc();

  console.log(
    JSON.stringify(
      {
        ok: true,
        programId: program.programId.toBase58(),
        oracleConfig: oracleConfig.toBase58(),
        oracleKey: oracleKey.toBase58(),
        adminKey: adminKey.toBase58(),
        txSig,
      },
      null,
      2,
    ),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
