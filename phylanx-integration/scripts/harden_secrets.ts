#!/usr/bin/env tsx
// =============================================================================
// scripts/harden_secrets.ts — verify operational secret hygiene.
//
// Checks:
//   - no API keys / private keys committed to the repo
//   - oracle keypair path is loaded from env, not hardcoded
//   - .env files exist only as .env.example
//   - DATABASE_URL is not a literal in any source file
// =============================================================================

import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

interface Hit {
  file: string;
  line: number;
  pattern: string;
  excerpt: string;
}

const ROOT_CANDIDATES = [
  "phylanx-programs",
  "phylanx-oracle",
  "phylanx-sdk",
  "phylanx-plugin-elizaos",
  "phylanx-e2e",
  "phylanx-integration",
];

const SCAN_EXTENSIONS = /\.(rs|ts|tsx|js|json|py|toml|yml|yaml|sh|md)$/;

const SKIP_DIRS = ["node_modules", "target", ".venv", "dist", "coverage", ".git"];
const CWD = process.cwd();
const REPO_ROOT =
  path.basename(CWD) === "phylanx-integration"
    ? path.resolve(CWD, "..")
    : CWD;
const exec = promisify(execFile);

const SUSPICIOUS_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  // Solana private key (88-char base58 starting with a digit, often)
  { name: "solana_secret_key_array",   regex: /\[(?:\s*\d+,\s*){63}\s*\d+\s*\]/ },
  // Helius/RPC API key (helius keys are UUIDs)
  { name: "uuid_api_key",              regex: /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/i },
  // Database URLs with embedded credentials (excluding test defaults)
  { name: "db_url_with_password",      regex: /postgresql:\/\/(?!phylanx:phylanx@)[^:]+:[^@]+@[^/]+/ },
  // Anthropic / OpenAI / Helius bearer-like prefixes
  { name: "openai_key",                regex: /sk-[A-Za-z0-9]{32,}/ },
  { name: "anthropic_key",             regex: /sk-ant-[A-Za-z0-9-]{32,}/ },
  // Telegram bot token
  { name: "telegram_bot_token",        regex: /\b\d{8,12}:[A-Za-z0-9_-]{30,}\b/ },
  // Phylanx operator key prefix (we issue these, never commit them)
  { name: "phylanx_operator_key",      regex: /\bhxop_[A-Za-z0-9_-]{16,}\b/ },
];


async function findFiles(root: string): Promise<string[]> {
  const tracked = await gitTrackedFiles();
  const rootAbs = path.resolve(REPO_ROOT, root);
  return tracked.filter((file) => {
    if (!file.startsWith(rootAbs + path.sep) && file !== rootAbs) return false;
    if (!SCAN_EXTENSIONS.test(file)) return false;
    return !SKIP_DIRS.some((dir) => file.split(path.sep).includes(dir));
  });
}

async function scan(root: string): Promise<Hit[]> {
  const hits: Hit[] = [];
  const files = await findFiles(root);
  for (const f of files) {
    let content: string;
    try { content = await fs.readFile(f, "utf-8"); }
    catch { continue; }

    // Skip .env.example explicitly — it's expected to have placeholders
    if (path.basename(f) === ".env.example") continue;
    // Skip test fixtures with known synthetic data
    if (f.includes("/tests/") && /placeholder|example|fake|test/i.test(content.slice(0, 200))) continue;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      // Skip comment lines clearly marking examples
      if (/example|placeholder|fixme/i.test(line)) continue;
      if (path.extname(f) === ".md" && /`hxop_[A-Za-z0-9_-]+`/.test(line)) continue;
      for (const p of SUSPICIOUS_PATTERNS) {
        if (
          p.name === "db_url_with_password" &&
          /postgresql:\/\/user:pw@host:port\/db/.test(line)
        ) {
          continue;
        }
        if (p.regex.test(line)) {
          hits.push({
            file: f, line: i + 1, pattern: p.name,
            excerpt: line.trim().slice(0, 120),
          });
        }
      }
    }
  }
  return hits;
}


// =============================================================================
// Verification: oracle keypair loaded via env path, not hardcoded
// =============================================================================

async function checkOracleKeypairLoad(): Promise<{ ok: boolean; detail: string }> {
  const oracleDir = path.resolve(REPO_ROOT, "phylanx-oracle/oracle");
  try {
    const oracleFiles = (await gitTrackedFiles()).filter((file) =>
      file.startsWith(oracleDir + path.sep) &&
      /\.(py|ts|rs)$/.test(file) &&
      !file.split(path.sep).includes("tests")
    );

    const inlineKeypairFiles: string[] = [];
    let envBackedLoaderFound = false;

    for (const file of oracleFiles) {
      const content = await fs.readFile(file, "utf-8");
      if (/Keypair\.from_bytes\s*\(\s*\[/.test(content)) {
        inlineKeypairFiles.push(file);
      }
      if (/ORACLE_KEYPAIR_PATH|oracle_keypair_path/.test(content)) {
        envBackedLoaderFound = true;
      }
    }

    if (inlineKeypairFiles.length > 0) {
      return {
        ok: false,
        detail: `oracle source contains hardcoded keypair literal(s):\n  ${inlineKeypairFiles.join("\n  ")}`,
      };
    }
    if (!envBackedLoaderFound) {
      return {
        ok: false,
        detail: "oracle source doesn't reference ORACLE_KEYPAIR_PATH / oracle_keypair_path",
      };
    }
    return { ok: true, detail: "oracle source loads authority keypair from configured env path" };
  } catch (e: any) {
    return { ok: false, detail: `couldn't audit oracle keypair loading: ${e.message}` };
  }
}


// =============================================================================
// Verification: no committed .env files
// =============================================================================

async function checkNoCommittedEnvFiles(): Promise<{ ok: boolean; detail: string }> {
  const tracked = await gitTrackedFiles();
  const offenders = tracked.filter((file) => {
    const base = path.basename(file);
    return base === ".env" || (base.startsWith(".env.") && base !== ".env.example");
  });
  if (offenders.length > 0) {
    return {
      ok: false,
      detail: `committed env file(s):\n  ${offenders.join("\n  ")}`,
    };
  }
  return { ok: true, detail: "no .env files committed (only .env.example)" };
}

async function gitTrackedFiles(): Promise<string[]> {
  const { stdout } = await exec("git", ["-C", REPO_ROOT, "ls-files", "-z"], {
    maxBuffer: 8 * 1024 * 1024,
  });
  return stdout
    .split("\0")
    .filter(Boolean)
    .map((rel) => path.join(REPO_ROOT, rel));
}


// =============================================================================
// Runner
// =============================================================================

async function main() {
  console.log("");
  console.log("╔════════════════════════════════════════════════════════════╗");
  console.log("║  Phylanx — Day 13 Secret Hygiene                          ║");
  console.log("╚════════════════════════════════════════════════════════════╝");
  console.log("");

  let failed = 0;

  // Scan all repos
  process.stdout.write("  • scanning for committed secrets ... ");
  const allHits: Hit[] = [];
  for (const root of ROOT_CANDIDATES) {
    try { allHits.push(...await scan(root)); }
    catch { /* repo may not exist locally */ }
  }
  if (allHits.length === 0) {
    console.log("\x1b[32m✓\x1b[0m  no suspicious tokens detected");
  } else {
    console.log(`\x1b[31m✗\x1b[0m  ${allHits.length} potential leak(s)`);
    for (const h of allHits.slice(0, 20)) {
      console.log(`      ${h.file}:${h.line}  [${h.pattern}]`);
      console.log(`        ${h.excerpt}`);
    }
    failed++;
  }

  // Oracle keypair handling
  process.stdout.write("  • oracle keypair loading      ... ");
  const oracleCheck = await checkOracleKeypairLoad();
  if (oracleCheck.ok) {
    console.log(`\x1b[32m✓\x1b[0m  ${oracleCheck.detail}`);
  } else {
    console.log(`\x1b[31m✗\x1b[0m  ${oracleCheck.detail}`);
    failed++;
  }

  // No .env files
  process.stdout.write("  • no committed .env files     ... ");
  const envCheck = await checkNoCommittedEnvFiles();
  if (envCheck.ok) {
    console.log(`\x1b[32m✓\x1b[0m  ${envCheck.detail}`);
  } else {
    console.log(`\x1b[31m✗\x1b[0m`);
    console.log(`      ${envCheck.detail}`);
    failed++;
  }

  console.log("");
  if (failed > 0) {
    console.log(`\x1b[31m✗ ${failed} check(s) failed\x1b[0m`);
    process.exit(1);
  }
  console.log(`\x1b[32m✓ secret hygiene OK\x1b[0m`);
}

main().catch((err) => { console.error(err); process.exit(1); });
