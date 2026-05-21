// =============================================================================
// audit/multisig/transfer_upgrade_authority.ts
//
// Transfer the BPF Upgrade Authority of each Helixor program to a Squads
// v4 3-of-5 multisig vault. This is the Day-29 hardening step that turns
// the deployer key from a single point of compromise into a 3-of-5
// threshold for any program upgrade.
//
// WHAT IT DOES (in order)
// -----------------------
//   1. Builds the SetUpgradeAuthority tx for each of the three programs,
//      naming the Squads vault PDA as the new authority.
//   2. Prints the unsigned tx bytes + base64 for offline review.
//   3. If --execute, sends each tx with the current upgrade-authority
//      keypair.
//   4. Verifies via `getAccountInfo` that the post-transfer upgrade
//      authority is the Squads vault PDA. Exits non-zero on mismatch.
//
// REQUIRES the current upgrade-authority keypair (single key today) and
// the Squads vault address. The vault is created out-of-band via the
// Squads CLI before this script runs:
//
//   squads-cli multisig create --members <5 pubkeys> --threshold 3
//
// USAGE
// -----
//   npx ts-node audit/multisig/transfer_upgrade_authority.ts \\
//     --vault       <SquadsVaultPDA> \\
//     --keypair     ~/.config/solana/deployer.json \\
//     --cluster     mainnet-beta \\
//     --execute
//
// Without --execute, the script is DRY-RUN: it builds, prints, and
// SIMULATES the txs but does not send. The audit operator reviews the
// dry-run output first.
// =============================================================================

import {
    Connection, Keypair, PublicKey, Transaction, TransactionInstruction,
    SystemProgram, sendAndConfirmTransaction,
} from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";

// ─────────────────────────────────────────────────────────────────────────────
// Program IDs — pin these to your deployed program addresses.
// ─────────────────────────────────────────────────────────────────────────────

const PROGRAMS = {
    "health-oracle":       "HzOraCLE111111111111111111111111111111111",   // PIN
    "certificate-issuer":  "CertIssuer1111111111111111111111111111111",   // PIN
    "slash-authority":     "SLasH1111111111111111111111111111111111111",  // PIN
} as const;

const BPF_UPGRADEABLE_LOADER = new PublicKey(
    "BPFLoaderUpgradeab1e11111111111111111111111",
);


// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

function parseArgs(): {
    vault: string; keypair: string; cluster: string; execute: boolean;
} {
    const argv = process.argv.slice(2);
    const get = (k: string, fallback?: string): string => {
        const i = argv.indexOf(`--${k}`);
        if (i < 0) {
            if (fallback !== undefined) return fallback;
            throw new Error(`missing --${k}`);
        }
        return argv[i + 1];
    };
    return {
        vault:   get("vault"),
        keypair: get("keypair"),
        cluster: get("cluster", "devnet"),
        execute: argv.includes("--execute"),
    };
}


// ─────────────────────────────────────────────────────────────────────────────
// Find the upgrade-data PDA for a program — that's the account whose
// upgrade_authority field we are setting.
// ─────────────────────────────────────────────────────────────────────────────

function programDataPda(programId: PublicKey): PublicKey {
    const [pda] = PublicKey.findProgramAddressSync(
        [programId.toBuffer()],
        BPF_UPGRADEABLE_LOADER,
    );
    return pda;
}


// ─────────────────────────────────────────────────────────────────────────────
// Build the SetUpgradeAuthority instruction.
//
// Instruction layout (BPF Loader Upgradeable):
//   u32 (= 4 for SetAuthority)
// Accounts:
//   [w]  ProgramData
//   [s]  current authority
//   [_]  new authority   (optional — if absent, authority is removed)
// ─────────────────────────────────────────────────────────────────────────────

function buildSetAuthorityIx(
    programData: PublicKey,
    currentAuthority: PublicKey,
    newAuthority: PublicKey,
): TransactionInstruction {
    const data = Buffer.alloc(4);
    data.writeUInt32LE(4, 0);                  // SetAuthority discriminator
    return new TransactionInstruction({
        programId: BPF_UPGRADEABLE_LOADER,
        keys: [
            { pubkey: programData,      isSigner: false, isWritable: true  },
            { pubkey: currentAuthority, isSigner: true,  isWritable: false },
            { pubkey: newAuthority,     isSigner: false, isWritable: false },
        ],
        data,
    });
}


// ─────────────────────────────────────────────────────────────────────────────
// Inspect the program-data account to confirm the upgrade authority.
//
// The BPF program-data account layout:
//   bytes 0..4   : variant (= 3 for ProgramData)
//   bytes 4..12  : slot (u64 LE)
//   byte  12     : Option<Pubkey> discriminator (1 = Some, 0 = None)
//   bytes 13..45 : Pubkey  (if Some)
// ─────────────────────────────────────────────────────────────────────────────

async function readUpgradeAuthority(
    conn: Connection, programData: PublicKey,
): Promise<PublicKey | null> {
    const info = await conn.getAccountInfo(programData);
    if (!info) throw new Error(`program-data account ${programData.toBase58()} missing`);
    const data = info.data;
    if (data.readUInt32LE(0) !== 3) {
        throw new Error("not a ProgramData account");
    }
    const has = data.readUInt8(12);
    if (has === 0) return null;
    return new PublicKey(data.slice(13, 45));
}


// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<number> {
    const args = parseArgs();
    const clusterUrl = args.cluster.includes("://")
        ? args.cluster
        : `https://api.${args.cluster}.solana.com`;
    const conn = new Connection(clusterUrl, "confirmed");

    const keypairJson = JSON.parse(fs.readFileSync(args.keypair, "utf8"));
    const authority = Keypair.fromSecretKey(Uint8Array.from(keypairJson));
    const vault = new PublicKey(args.vault);

    console.log(`Current authority:  ${authority.publicKey.toBase58()}`);
    console.log(`Squads vault (new): ${vault.toBase58()}`);
    console.log(`Cluster:            ${clusterUrl}`);
    console.log(`Mode:               ${args.execute ? "EXECUTE" : "DRY-RUN"}\n`);

    const report: Record<string, string> = {};

    for (const [name, idStr] of Object.entries(PROGRAMS)) {
        const programId = new PublicKey(idStr);
        const dataPda = programDataPda(programId);

        // Sanity: confirm current authority matches.
        const currentOnChain = await readUpgradeAuthority(conn, dataPda);
        console.log(`[${name}]`);
        console.log(`  program-data PDA: ${dataPda.toBase58()}`);
        console.log(`  current on-chain authority: ${currentOnChain?.toBase58() ?? "<none>"}`);

        if (currentOnChain === null) {
            console.log(`  ⚠️  program is already non-upgradeable — skipping`);
            report[name] = "non-upgradeable";
            continue;
        }
        if (!currentOnChain.equals(authority.publicKey)) {
            console.log(`  ❌ on-chain authority does NOT match the supplied keypair`);
            return 2;
        }

        // Build the transfer tx.
        const ix = buildSetAuthorityIx(dataPda, authority.publicKey, vault);
        const tx = new Transaction().add(ix);
        tx.feePayer = authority.publicKey;
        const { blockhash } = await conn.getLatestBlockhash();
        tx.recentBlockhash = blockhash;

        if (!args.execute) {
            // Dry-run — simulate.
            const sim = await conn.simulateTransaction(tx, [authority]);
            console.log(`  dry-run simulate logs:`);
            (sim.value.logs ?? []).forEach((l) => console.log(`    ${l}`));
            if (sim.value.err) {
                console.log(`  ❌ simulation error: ${JSON.stringify(sim.value.err)}`);
                return 2;
            }
            report[name] = "dry-run-ok";
            continue;
        }

        // Execute — send + confirm.
        const sig = await sendAndConfirmTransaction(conn, tx, [authority], {
            commitment: "finalized",
        });
        console.log(`  tx: ${sig}`);

        // Verify.
        const newAuthority = await readUpgradeAuthority(conn, dataPda);
        if (newAuthority === null || !newAuthority.equals(vault)) {
            console.log(`  ❌ post-transfer authority is ${newAuthority?.toBase58()}, expected ${vault.toBase58()}`);
            return 2;
        }
        console.log(`  ✅ authority now ${newAuthority.toBase58()}`);
        report[name] = `transferred: tx=${sig}`;
    }

    // Persist a JSON report for the audit log.
    const out = path.join(__dirname, "..", "reports", "multisig_transfer.json");
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, JSON.stringify({
        mode: args.execute ? "execute" : "dry-run",
        cluster: clusterUrl,
        vault: vault.toBase58(),
        programs: report,
    }, null, 2));
    console.log(`\nReport written to ${out}`);
    console.log(args.execute
        ? "✅ TRANSFER COMPLETE — upgrade authority is now the Squads 3-of-5 vault"
        : "ℹ️  DRY-RUN complete — re-run with --execute to apply");
    return 0;
}


main().then(process.exit).catch((e) => { console.error(e); process.exit(1); });
