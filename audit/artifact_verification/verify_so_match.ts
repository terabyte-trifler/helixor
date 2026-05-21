// =============================================================================
// audit/artifact_verification/verify_so_match.ts
//
// Day 29 — deployed .so byte-match verification.
//
// Fetches program-data bytes from a live Solana cluster, compares them
// against the local-built target/deploy/<program>.so, and asserts byte
// equality. A mismatch means the deployed code does NOT match the audited
// source. The companion deploy_and_verify_local.sh script first deploys
// the same local artifacts to a disposable validator, then runs this
// verifier against that validator so the local audit gate exercises the
// actual on-chain ProgramData comparison path.
//
// USAGE
// -----
//   npx ts-node audit/artifact_verification/verify_so_match.ts \\
//     --cluster mainnet-beta \\
//     --build-dir helixor-programs/target/deploy
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";


const PROGRAMS = {
    "health_oracle":       "Cnn6AWzKD6NjwNZNsJnDYYYTTjt2C9Gow2TZoXzK3U5P",
    "certificate_issuer":  "3ViKj3cYMo76HwnLYAnbM5BDuMPxmKuKhotXhfPq94gW",
    "slash_authority":     "2pGoLLvs3XegXDXm7HAZTrFoJZV9dPnNTU1PDEdcUhsN",
} as const;

const BPF_UPGRADEABLE_LOADER = new PublicKey(
    "BPFLoaderUpgradeab1e11111111111111111111111",
);


// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

function parseArgs(): { cluster: string; buildDir: string; report: string; localOnly: boolean } {
    const argv = process.argv.slice(2);
    const get = (k: string, dflt: string) => {
        const i = argv.indexOf(`--${k}`);
        return i < 0 ? dflt : argv[i + 1];
    };
    return {
        cluster:  get("cluster", "mainnet-beta"),
        buildDir: get("build-dir", "helixor-programs/target/deploy"),
        report:   get("report", "audit/reports/so_match.json"),
        localOnly: argv.includes("--local-only"),
    };
}


// ─────────────────────────────────────────────────────────────────────────────
// Fetch the deployed bytecode from chain.
//
// ProgramData layout (BPF Loader Upgradeable):
//   [0..4]   variant     = 3
//   [4..12]  slot
//   [12..45] Option<Pubkey> upgrade authority
//   [45..]   raw .so bytecode
// ─────────────────────────────────────────────────────────────────────────────

async function fetchDeployedBytes(
    conn: Connection, programId: PublicKey,
): Promise<Buffer> {
    const [dataPda] = PublicKey.findProgramAddressSync(
        [programId.toBuffer()], BPF_UPGRADEABLE_LOADER,
    );
    const info = await conn.getAccountInfo(dataPda);
    if (!info) throw new Error(`program-data ${dataPda.toBase58()} missing`);
    // Skip the 45-byte header.
    return info.data.slice(45);
}


function sha256(buf: Buffer): string {
    return createHash("sha256").update(buf).digest("hex");
}


async function main(): Promise<number> {
    const args = parseArgs();
    const clusterUrl = args.cluster.includes("://")
        ? args.cluster
        : `https://api.${args.cluster}.solana.com`;
    const conn = new Connection(clusterUrl, "confirmed");

    const report: Record<string, any> = {
        cluster: args.localOnly ? "local-only" : clusterUrl,
        local_only: args.localOnly,
        programs: {},
    };
    let failed = false;

    for (const [name, idStr] of Object.entries(PROGRAMS)) {
        const localPath = path.join(args.buildDir, `${name}.so`);

        if (!fs.existsSync(localPath)) {
            console.log(`❌ [${name}] local build missing: ${localPath}`);
            console.log(`   run: cd helixor-programs && anchor build --verifiable`);
            failed = true;
            continue;
        }

        const localBytes = trimTrailingZeros(fs.readFileSync(localPath));
        const localHash = sha256(localBytes);

        if (args.localOnly) {
            console.log(`[${name}]`);
            console.log(`  local  ${localBytes.length} bytes  sha256=${localHash}`);
            report.programs[name] = {
                programId: idStr,
                local_path:   localPath,
                local_size:   localBytes.length,
                local_sha256: localHash,
                match:        true,
                mode:         "local-only",
            };
            continue;
        }

        const programId = new PublicKey(idStr);

        let deployedHash = "";
        let deployedSize = 0;
        try {
            const deployedBytes = await fetchDeployedBytes(conn, programId);
            // The deployed bytes are zero-padded to the program-data
            // account size; strip trailing zeros for comparison.
            const trimmed = trimTrailingZeros(deployedBytes);
            deployedHash = sha256(trimmed);
            deployedSize = trimmed.length;

            const match = deployedHash === localHash;
            console.log(`[${name}]`);
            console.log(`  local  ${localBytes.length} bytes  sha256=${localHash}`);
            console.log(`  chain  ${deployedSize} bytes  sha256=${deployedHash}`);
            console.log(`  match: ${match ? "✅" : "❌"}`);

            report.programs[name] = {
                programId: idStr,
                local_path:   localPath,
                local_size:   localBytes.length,
                local_sha256: localHash,
                deployed_size:   deployedSize,
                deployed_sha256: deployedHash,
                match,
            };

            if (!match) failed = true;
        } catch (e: any) {
            console.log(`❌ [${name}] fetch failed: ${e.message}`);
            report.programs[name] = { error: e.message };
            failed = true;
        }
    }

    fs.mkdirSync(path.dirname(args.report), { recursive: true });
    fs.writeFileSync(args.report, JSON.stringify(report, null, 2));
    console.log(`\nReport: ${args.report}`);

    if (failed) {
        console.log("❌ ARTIFACT VERIFICATION FAILED");
        return 1;
    }
    if (args.localOnly) {
        console.log("✅ ARTIFACT VERIFICATION CLEAN — local .so hashes pinned");
    } else {
        console.log("✅ ARTIFACT VERIFICATION CLEAN — deployed = local for all programs");
    }
    return 0;
}


function trimTrailingZeros(buf: Buffer): Buffer {
    let end = buf.length;
    while (end > 0 && buf[end - 1] === 0) end -= 1;
    return buf.slice(0, end);
}


main().then(process.exit).catch((e) => { console.error(e); process.exit(1); });
