// =============================================================================
// launch/deploy/initialize_configs.ts
//
// Day 30 — initialize the three Phylanx on-chain config PDAs after deploy.
//
// Idempotent: skips a config that already exists.
//
// Configs initialized:
//   * health-oracle:       OracleConfig (oracle_keys, min_confidence)
//   * certificate-issuer:  IssuerConfig (issuer_node, cluster_keys, threshold)
//   * slash-authority:     SlashConfig  (initial admin, default thresholds)
// =============================================================================

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import * as fs from "fs";

const enc = anchor.utils.bytes.utf8.encode;
const { BN } = anchor;


function args(): {
    cluster: string; admin: string; oracleKeys: string; threshold: number;
    slashExecutor: string; appealResolver: string; pauseAuthority: string;
    treasury: string; settlementTimelockSeconds: number;
} {
    const a = process.argv.slice(2);
    const get = (k: string, dflt?: string): string => {
        const i = a.indexOf(`--${k}`);
        if (i < 0) {
            if (dflt !== undefined) return dflt;
            throw new Error(`missing --${k}`);
        }
        return a[i + 1];
    };
    return {
        cluster:    get("cluster"),
        admin:      get("admin"),
        oracleKeys: get("oracle-keys"),
        threshold:  parseInt(get("threshold", "3")),
        // VULN-04: slash-authority requires three distinct role keys, a
        // treasury, and a settlement timelock >= 72h. No defaults — these
        // MUST be supplied so that production never silently reuses one
        // key for all three roles.
        slashExecutor:             get("slash-executor"),
        appealResolver:            get("appeal-resolver"),
        pauseAuthority:            get("pause-authority"),
        treasury:                  get("treasury"),
        settlementTimelockSeconds: parseInt(get("settlement-timelock-seconds",
                                                String(72 * 3_600))),
    };
}


function clusterUrl(name: string): string {
    return name === "localnet" ? "http://localhost:8899"
         : name === "mainnet-beta" ? "https://api.mainnet-beta.solana.com"
         : `https://api.${name}.solana.com`;
}


async function main(): Promise<number> {
    const a = args();
    const url = clusterUrl(a.cluster);
    const conn = new anchor.web3.Connection(url, "confirmed");

    const adminKp = Keypair.fromSecretKey(Uint8Array.from(
        JSON.parse(fs.readFileSync(a.admin, "utf8")),
    ));
    const oracleKeysJson = JSON.parse(fs.readFileSync(a.oracleKeys, "utf8"));
    const oracleKeys = (oracleKeysJson as string[]).map((s) => new PublicKey(s));

    if (oracleKeys.length !== 5) {
        console.error(`❌ expected 5 oracle keys, got ${oracleKeys.length}`);
        return 2;
    }

    const wallet = new anchor.Wallet(adminKp);
    const provider = new anchor.AnchorProvider(conn, wallet, {
        commitment: "confirmed",
    });
    anchor.setProvider(provider);

    const manifest = JSON.parse(
        fs.readFileSync("launch/deploy/manifest.json", "utf8"),
    );
    const programs = manifest[a.cluster];
    if (!programs) {
        console.error(`❌ no deploy manifest for cluster ${a.cluster}`);
        return 2;
    }

    console.log(`Cluster:       ${url}`);
    console.log(`Admin:         ${adminKp.publicKey.toBase58()}`);
    console.log(`Oracle keys:   ${oracleKeys.length}`);
    console.log(`Threshold:     ${a.threshold} of ${oracleKeys.length}`);
    console.log();

    // ── 1. health-oracle: OracleConfig ──────────────────────────────────────
    await initOracleConfig(provider, programs, adminKp, oracleKeys);

    // ── 2. certificate-issuer: IssuerConfig ─────────────────────────────────
    // VULN-16: pin the canonical health-oracle program ID into IssuerConfig.
    // `issue_certificate`'s cpi_guard then refuses any CPI from a program
    // other than this one (and direct top-level calls remain accepted).
    const healthOracleProgramId = new PublicKey(programs["health-oracle"].program_id);
    await initIssuerConfig(
        provider, programs, adminKp, oracleKeys, a.threshold,
        healthOracleProgramId,
    );

    // ── 3. slash-authority: SlashConfig ─────────────────────────────────────
    // VULN-04: admin pays rent and becomes the update authority. The
    // executor/resolver/pauser keys MUST be distinct from each other and
    // from the default Pubkey. The settlement timelock MUST be >= 72h —
    // the on-chain program will reject anything shorter.
    await initSlashConfig(
        provider, programs, adminKp,
        new PublicKey(a.slashExecutor),
        new PublicKey(a.appealResolver),
        new PublicKey(a.pauseAuthority),
        new PublicKey(a.treasury),
        a.settlementTimelockSeconds,
    );

    console.log();
    console.log("✅ ALL CONFIGS INITIALIZED");
    return 0;
}


async function initOracleConfig(
    provider: anchor.AnchorProvider,
    programs: Record<string, any>,
    admin: Keypair,
    oracleKeys: PublicKey[],
): Promise<void> {
    const idl = require("../../phylanx-programs/target/idl/health_oracle.json");
    const programId = new PublicKey(programs["health-oracle"].program_id);
    idl.address = programId.toBase58();
    const program = new Program(idl, provider);

    const [pda] = PublicKey.findProgramAddressSync(
        [enc("oracle_config")], programId,
    );
    if (await provider.connection.getAccountInfo(pda)) {
        console.log("⊘  health-oracle.OracleConfig already exists, skipping");
        return;
    }

    const sig = await program.methods
        .initializeOracleConfig(oracleKeys, 700)        // min_confidence = 700
        .accounts({
            oracleConfig:  pda,
            admin:         admin.publicKey,
            systemProgram: SystemProgram.programId,
        })
        .rpc();
    console.log(`✅ health-oracle.OracleConfig init  tx=${sig}`);
}


async function initIssuerConfig(
    provider:               anchor.AnchorProvider,
    programs:               Record<string, any>,
    admin:                  Keypair,
    clusterKeys:            PublicKey[],
    threshold:              number,
    // VULN-16: the canonical health-oracle program ID. The cpi_guard in
    // issue_certificate uses this as the sole accepted CPI caller; any
    // other program that tries to CPI in is rejected with UntrustedCpiCaller.
    healthOracleProgramId:  PublicKey,
): Promise<void> {
    const idl = require("../../phylanx-programs/target/idl/certificate_issuer.json");
    const programId = new PublicKey(programs["certificate-issuer"].program_id);
    idl.address = programId.toBase58();
    const program = new Program(idl, provider);

    const [pda] = PublicKey.findProgramAddressSync(
        [enc("issuer_config")], programId,
    );
    if (await provider.connection.getAccountInfo(pda)) {
        console.log("⊘  certificate-issuer.IssuerConfig already exists, skipping");
        return;
    }

    const sig = await program.methods
        .initializeConfig(
            admin.publicKey,                            // issuer_node (rent payer)
            clusterKeys,
            threshold,
            healthOracleProgramId,                      // VULN-16 CPI allow-list
            [],                                         // AW-01-EXT.6: challenge attesters disabled on localnet
            0,
        )
        .accounts({
            issuerConfig:  pda,
            admin:         admin.publicKey,
            systemProgram: SystemProgram.programId,
        })
        .rpc();
    console.log(`✅ certificate-issuer.IssuerConfig init  tx=${sig}  ` +
                `(cpi-allow-list = health-oracle ${healthOracleProgramId.toBase58()})`);
}


async function initSlashConfig(
    provider:                  anchor.AnchorProvider,
    programs:                  Record<string, any>,
    admin:                     Keypair,
    slashExecutor:             PublicKey,
    appealResolver:            PublicKey,
    pauseAuthority:            PublicKey,
    treasury:                  PublicKey,
    settlementTimelockSeconds: number,
): Promise<void> {
    const idl = require("../../phylanx-programs/target/idl/slash_authority.json");
    const programId = new PublicKey(programs["slash-authority"].program_id);
    idl.address = programId.toBase58();
    const program = new Program(idl, provider);

    const [pda] = PublicKey.findProgramAddressSync(
        [enc("slash_config")], programId,
    );
    if (await provider.connection.getAccountInfo(pda)) {
        console.log("⊘  slash-authority.SlashConfig already exists, skipping");
        return;
    }

    const sig = await program.methods
        .initializeConfig(
            slashExecutor,
            appealResolver,
            pauseAuthority,
            treasury,
            new BN(settlementTimelockSeconds),
        )
        .accounts({
            slashConfig:   pda,
            admin:         admin.publicKey,
            systemProgram: SystemProgram.programId,
        })
        .rpc();
    console.log(
        `✅ slash-authority.SlashConfig init  tx=${sig} ` +
        `executor=${slashExecutor.toBase58()} ` +
        `resolver=${appealResolver.toBase58()} ` +
        `pauser=${pauseAuthority.toBase58()} ` +
        `timelock=${settlementTimelockSeconds}s`,
    );
}


main().then(process.exit).catch((e) => { console.error(e); process.exit(1); });
