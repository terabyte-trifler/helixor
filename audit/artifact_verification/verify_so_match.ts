// =============================================================================
// audit/artifact_verification/verify_so_match.ts
//
// Day 29 — deployed .so byte-match verification.
//
// Fetches the deployed program-data bytes from the chain, compares them
// against the local-built target/deploy/<program>.so (a reproducible build
// — `anchor build --verifiable`), and asserts byte equality. A mismatch
// means the deployed code does NOT match the audited source.
//
// SHA-256 of every local .so is also pinned in audit/reports/so_hashes.json
// so a future verification can prove the verified source has not changed.
//
// USAGE
// -----
//   npx ts-node audit/artifact_verification/verify_so_match.ts \\
//     --cluster mainnet-beta \\
//     --build-dir phylanx-programs/target/deploy
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";


// Placeholder mainnet IDs — replace with the real upgrade-keypair pubkeys
// at deploy time. For non-mainnet runs (devnet, localhost, CI), supply
// `--programs-file <path.json>` with the actual deployed IDs:
//   { "health_oracle": "EKK2...", "certificate_issuer": "4bsG...", ... }
const PROGRAMS: Record<string, string> = {
    "health_oracle":       "HzOraCLE111111111111111111111111111111111",
    "certificate_issuer":  "CertIssuer1111111111111111111111111111111",
    "slash_authority":     "SLasH1111111111111111111111111111111111111",
};

const BPF_UPGRADEABLE_LOADER = new PublicKey(
    "BPFLoaderUpgradeab1e11111111111111111111111",
);


// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

function parseArgs(): {
    cluster: string; buildDir: string; report: string;
    programsFile: string | null;
} {
    const argv = process.argv.slice(2);
    const get = (k: string, dflt: string) => {
        const i = argv.indexOf(`--${k}`);
        return i < 0 ? dflt : argv[i + 1];
    };
    const programsFile = argv.indexOf("--programs-file");
    return {
        cluster:      get("cluster", "mainnet-beta"),
        buildDir:     get("build-dir", "phylanx-programs/target/deploy"),
        report:       get("report", "audit/reports/so_match.json"),
        programsFile: programsFile < 0 ? null : argv[programsFile + 1],
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
    const clusterUrl = (() => {
        if (args.cluster.includes("://")) return args.cluster;
        if (args.cluster === "localhost" || args.cluster === "localnet") {
            return "http://127.0.0.1:8899";
        }
        return `https://api.${args.cluster}.solana.com`;
    })();
    const conn = new Connection(clusterUrl, "confirmed");

    let programs: Record<string, string> = PROGRAMS;
    if (args.programsFile) {
        const raw = fs.readFileSync(args.programsFile, "utf8");
        programs = JSON.parse(raw);
    }

    const report: Record<string, any> = { cluster: clusterUrl, programs: {} };
    let failed = false;

    for (const [name, idStr] of Object.entries(programs)) {
        const programId = new PublicKey(idStr);
        const localPath = path.join(args.buildDir, `${name}.so`);

        if (!fs.existsSync(localPath)) {
            console.log(`❌ [${name}] local build missing: ${localPath}`);
            console.log(`   run: cd phylanx-programs && anchor build --verifiable`);
            failed = true;
            continue;
        }

        // Trim trailing zero padding from BOTH sides — the linker may emit
        // a few trailing zero bytes on the local .so, and the chain copy
        // is also zero-padded to max_data_size. Strip equally so the
        // comparison reflects the real bytecode.
        const localRaw = fs.readFileSync(localPath);
        const localBytes = trimTrailingZeros(localRaw);
        const localHash = sha256(localBytes);

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
            console.log(`  local  ${localBytes.length} bytes (raw ${localRaw.length})  sha256=${localHash}`);
            console.log(`  chain  ${deployedSize} bytes  sha256=${deployedHash}`);
            console.log(`  match: ${match ? "✅" : "❌"}`);

            report.programs[name] = {
                programId: idStr,
                local_path:        localPath,
                local_size:        localBytes.length,
                local_size_raw:    localRaw.length,
                local_sha256:      localHash,
                deployed_size:     deployedSize,
                deployed_sha256:   deployedHash,
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
    console.log("✅ ARTIFACT VERIFICATION CLEAN — deployed = local for all programs");
    return 0;
}


function trimTrailingZeros(buf: Buffer): Buffer {
    let end = buf.length;
    while (end > 0 && buf[end - 1] === 0) end -= 1;
    return buf.slice(0, end);
}


main().then(process.exit).catch((e) => { console.error(e); process.exit(1); });
