// =============================================================================
// launch/deploy/preflight_vault.ts — VULN-19 mitigation.
//
// Verify that the Squads multisig vault PDA the deployer is ABOUT to hand
// upgrade authority to actually exists on chain and is owned by an
// accepted program. Runs BEFORE the first `anchor deploy` so a misconfigured
// vault never opens the post-deploy / pre-transfer window.
//
// THE WINDOW THIS CLOSES
// ----------------------
// In the legacy flow:
//     1. anchor deploy            — hot key is upgrade authority
//     2. ... time passes ...      — hot key is still upgrade authority (!)
//     3. transfer_upgrade_authority.ts --execute
// Steps 2-3 are the VULN-19 window. If step 3 fails because the vault is
// wrong, the hot key keeps authority until the operator notices, and the
// "transfer immediately" rule in the launch checklist becomes "transfer
// when we figure out the right vault."
//
// This preflight runs BEFORE step 1 and refuses the whole deploy if:
//   * the vault PDA does not exist on chain
//   * the vault is owned by an unexpected program (typo, wrong cluster,
//     vault for a different multisig family)
//   * the vault account has zero data (uninitialised)
//
// USAGE
// -----
//   npx ts-node launch/deploy/preflight_vault.ts \
//       --vault          <SquadsVaultPDA> \
//       --cluster        mainnet-beta \
//       --expected-owner <ProgramId,ProgramId,...> \
//       [--out audit/reports/squads_vault_preflight.json]
//
// `--expected-owner` is a comma-separated list of accepted owner program
// IDs. The Squads v4 program ID goes here; multiple are allowed so the
// operator can support both Squads v3 and v4 deployments without code
// changes. The script does NOT hard-code Squads program IDs because the
// audited program ID at deploy time is an operator decision recorded in
// launch/RUNBOOK.md.
//
// EXIT CODES
// ----------
//   0  vault verified
//   2  preflight failed — do NOT proceed with deploy
//   1  unexpected error
// =============================================================================

import { Connection, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";


function parseArgs(): {
    vault: string;
    cluster: string;
    expectedOwners: string[];
    outPath: string;
    minDataLen: number;
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
    const ownersRaw = get("expected-owner");
    const expectedOwners = ownersRaw.split(",").map((s) => s.trim()).filter(Boolean);
    if (expectedOwners.length === 0) {
        throw new Error("--expected-owner must list at least one program id");
    }
    const minDataLenRaw = get("min-data-len", "8");
    const minDataLen = Number.parseInt(minDataLenRaw, 10);
    if (!Number.isFinite(minDataLen) || minDataLen < 0) {
        throw new Error(`--min-data-len must be a non-negative integer, got '${minDataLenRaw}'`);
    }
    return {
        vault:    get("vault"),
        cluster:  get("cluster", "devnet"),
        expectedOwners,
        outPath:  get("out", "audit/reports/squads_vault_preflight.json"),
        minDataLen,
    };
}


function clusterUrl(name: string): string {
    if (name.includes("://")) return name;
    return `https://api.${name}.solana.com`;
}


async function main(): Promise<number> {
    let args;
    try {
        args = parseArgs();
    } catch (e) {
        console.error(`preflight_vault: ${(e as Error).message}`);
        return 2;
    }
    const url  = clusterUrl(args.cluster);
    const conn = new Connection(url, "confirmed");

    let vaultPk: PublicKey;
    try {
        vaultPk = new PublicKey(args.vault);
    } catch {
        console.error(`preflight_vault: --vault ${args.vault} is not a valid pubkey`);
        return 2;
    }

    const expectedOwners: PublicKey[] = [];
    for (const o of args.expectedOwners) {
        try { expectedOwners.push(new PublicKey(o)); }
        catch { console.error(`preflight_vault: --expected-owner ${o} is not a valid pubkey`); return 2; }
    }

    console.log(`preflight_vault: cluster=${url}`);
    console.log(`preflight_vault: vault=${vaultPk.toBase58()}`);
    console.log(
        `preflight_vault: accepted owners=${expectedOwners.map((p) => p.toBase58()).join(", ")}`,
    );

    const info = await conn.getAccountInfo(vaultPk, "confirmed");
    if (info === null) {
        console.error(
            `preflight_vault: ❌ vault ${vaultPk.toBase58()} does NOT exist on ${url}. ` +
            `The deploy will be REFUSED. Create the Squads multisig first ` +
            `(see launch/RUNBOOK.md §"Squads vault provisioning").`,
        );
        return 2;
    }

    const ownerOk = expectedOwners.some((p) => p.equals(info.owner));
    if (!ownerOk) {
        console.error(
            `preflight_vault: ❌ vault ${vaultPk.toBase58()} is owned by ` +
            `${info.owner.toBase58()}, not in the accepted set ` +
            `[${expectedOwners.map((p) => p.toBase58()).join(", ")}]. ` +
            `This usually means a typo in --vault, the wrong cluster, or ` +
            `a vault from a different multisig program.`,
        );
        return 2;
    }

    if (info.data.length < args.minDataLen) {
        console.error(
            `preflight_vault: ❌ vault ${vaultPk.toBase58()} has only ` +
            `${info.data.length} bytes of data; expected at least ${args.minDataLen}. ` +
            `The account exists but looks uninitialised.`,
        );
        return 2;
    }

    console.log(`preflight_vault: ✅ vault exists, owner ${info.owner.toBase58()}, ${info.data.length} bytes`);

    const record = {
        verified_at: new Date().toISOString(),
        cluster:     url,
        vault:       vaultPk.toBase58(),
        owner:       info.owner.toBase58(),
        data_length: info.data.length,
        lamports:    info.lamports,
        accepted_owners: expectedOwners.map((p) => p.toBase58()),
    };
    fs.mkdirSync(path.dirname(args.outPath), { recursive: true });
    fs.writeFileSync(args.outPath, JSON.stringify(record, null, 2));
    console.log(`preflight_vault: report written to ${args.outPath}`);
    return 0;
}


main().then((code) => process.exit(code)).catch((e) => {
    console.error(`preflight_vault: unexpected error: ${e}`);
    process.exit(1);
});
