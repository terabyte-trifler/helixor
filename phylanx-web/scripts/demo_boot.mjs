#!/usr/bin/env node
// =============================================================================
// scripts/demo_boot.mjs — Day-42 one-command YC demo boot.
//
// What it does
// ------------
//   1. Builds the web in mock mode (NEXT_PUBLIC_API_URL='') so every page
//      renders from the deterministic in-memory mock — no Postgres, no
//      validator, no Python services required.
//   2. Starts `next start` on the configured port (default 3042) in the
//      background.
//   3. Waits for the server to answer on /.
//   4. Curls each demo page and asserts the Day-41 content strings are
//      present in the HTML. Any missing string = the demo is broken.
//   5. Prints a clickable URL list for the demo operator.
//
// Why one script instead of `npm run build && npm start`
// -------------------------------------------------------
// The web bakes env vars at BUILD time, not start time. A leftover dev
// build with `NEXT_PUBLIC_API_URL=http://localhost:8001` baked in will
// silently hit a non-existent API and 404 every demo wallet. This script
// is the safe path: always rebuild in mock mode, always health-check
// before declaring the demo ready.
//
// Run: `npm run demo` from phylanx-web/.
// =============================================================================

import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

const PORT = Number(process.env.PORT ?? 3042);
const HOST = process.env.HOST ?? "127.0.0.1";
const BASE = `http://${HOST}:${PORT}`;

const LOG_DIR  = join(ROOT, ".demo");
const LOG_FILE = join(LOG_DIR, "next-start.log");
const PID_FILE = join(LOG_DIR, "next-start.pid");

mkdirSync(LOG_DIR, { recursive: true });

// ─────────────────────────────────────────────────────────────────────────────
// Featured demo wallets — kept in lock-step with lib/mock.ts FEATURED_AGENTS.
// If those wallets change in mock.ts, change them here too — the smoke
// check below verifies the page actually renders the wallet header.
// ─────────────────────────────────────────────────────────────────────────────

const DEMO_PAGES = [
  {
    path:    "/",
    name:    "Landing",
    requireStrings: ["Phylanx", "Paste a Solana wallet to score it"],
  },
  {
    path:    "/transparency",
    name:    "Transparency",
    requireStrings: [
      "Every flag",
      "Live strike counter",
      "Label-level disagreement",
    ],
  },
  {
    path:    "/agent/Hxr1Demo01StableTrader1111111111111111111111",
    name:    "Stable arb bot",
    requireStrings: ["941", "GREEN"],
  },
  {
    path:    "/agent/Hxr2Demo02RecoveringYieldAgent11111111111111",
    name:    "Recovering (with remediation history)",
    requireStrings: ["712", "Remediation history", "RUN_FRESH_BASELINE"],
  },
  {
    path:    "/agent/Hxr3Demo03DriftingMarketMaker111111111111111",
    name:    "Drift (with COUNTERPARTY_CONCENTRATION)",
    requireStrings: ["583", "COUNTERPARTY_CONCENTRATION"],
  },
  {
    path:    "/agent/Hxr4Demo04FlaggedExfilAgent1111111111111111x",
    name:    "Compromised (TOOL_LOOP + RAPID_DRAIN)",
    requireStrings: ["184", "TOOL_LOOP", "RAPID_DRAIN", "threshold-attested"],
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Tiny pretty-printer.
// ─────────────────────────────────────────────────────────────────────────────

const COLOR = process.stdout.isTTY ? {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
  green:  "\x1b[32m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  cyan:   "\x1b[36m",
} : { reset: "", bold: "", dim: "", green: "", red: "", yellow: "", cyan: "" };

function step(msg) {
  console.log(`${COLOR.cyan}▸${COLOR.reset} ${msg}`);
}
function ok(msg)   { console.log(`  ${COLOR.green}✓${COLOR.reset} ${msg}`); }
function fail(msg) { console.log(`  ${COLOR.red}✗${COLOR.reset} ${msg}`); }
function dim(msg)  { console.log(`  ${COLOR.dim}${msg}${COLOR.reset}`); }

// ─────────────────────────────────────────────────────────────────────────────
// Helpers — run a command, sleep, wait for a port.
// ─────────────────────────────────────────────────────────────────────────────

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd: ROOT,
      stdio: opts.inherit ? "inherit" : ["ignore", "pipe", "pipe"],
      env: { ...process.env, ...(opts.env ?? {}) },
    });
    let stdout = "";
    let stderr = "";
    if (!opts.inherit) {
      child.stdout?.on("data", (d) => { stdout += d.toString(); });
      child.stderr?.on("data", (d) => { stderr += d.toString(); });
    }
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${cmd} exited ${code}\n${stderr}`));
    });
  });
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForServer(maxMs = 30_000) {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(BASE + "/", { method: "GET" });
      if (res.ok || res.status === 404) return true;
    } catch {
      // not yet
    }
    await sleep(500);
  }
  return false;
}

async function checkPage(page) {
  const url = BASE + page.path;
  try {
    const res = await fetch(url, { method: "GET" });
    if (!res.ok) {
      fail(`${page.name} (HTTP ${res.status})`);
      return false;
    }
    const html = await res.text();
    const missing = page.requireStrings.filter((s) => !html.includes(s));
    if (missing.length === 0) {
      ok(`${page.name}  ${COLOR.dim}${url}${COLOR.reset}`);
      return true;
    }
    fail(`${page.name} — missing ${missing.map((s) => `"${s}"`).join(", ")}`);
    dim(url);
    return false;
  } catch (err) {
    fail(`${page.name} — fetch failed: ${err.message}`);
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main.
// ─────────────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`${COLOR.bold}Phylanx demo boot${COLOR.reset}  →  ${BASE}\n`);

  // ── 1. Build in mock mode. ───────────────────────────────────────────────
  step("Building (mock mode)");
  await run("npx", ["next", "build"], {
    env: { NEXT_PUBLIC_API_URL: "", NEXT_PUBLIC_NETWORK: "demo" },
  });
  ok("build clean");

  // ── 2. Start the server in the background. ───────────────────────────────
  step(`Starting next start on port ${PORT}`);
  const child = spawn(
    "npx",
    ["next", "start", "--port", String(PORT), "--hostname", HOST],
    {
      cwd: ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
      env: { ...process.env, NEXT_PUBLIC_API_URL: "", NEXT_PUBLIC_NETWORK: "demo" },
    },
  );
  child.unref();
  writeFileSync(PID_FILE, String(child.pid));
  const logStream = await import("node:fs").then((fs) =>
    fs.createWriteStream(LOG_FILE, { flags: "w" }),
  );
  child.stdout?.pipe(logStream);
  child.stderr?.pipe(logStream);
  dim(`pid=${child.pid}  log=${LOG_FILE}`);

  // ── 3. Wait for it. ──────────────────────────────────────────────────────
  step("Waiting for server");
  const up = await waitForServer();
  if (!up) {
    fail(`server did not answer on ${BASE} within 30s`);
    fail(`check ${LOG_FILE} for next-start output`);
    process.exit(2);
  }
  ok("server is up");

  // ── 4. Smoke each demo page. ─────────────────────────────────────────────
  step("Smoke-checking demo pages");
  let okCount = 0;
  for (const page of DEMO_PAGES) {
    if (await checkPage(page)) okCount += 1;
  }

  console.log();
  if (okCount === DEMO_PAGES.length) {
    console.log(
      `${COLOR.green}${COLOR.bold}Demo ready${COLOR.reset}  ` +
      `(${okCount}/${DEMO_PAGES.length} pages pass).`,
    );
    console.log();
    console.log("  Featured surfaces:");
    for (const page of DEMO_PAGES) {
      console.log(`    ${COLOR.cyan}${BASE}${page.path}${COLOR.reset}`);
    }
    console.log();
    console.log(`  Server runs in the background. Stop with:`);
    console.log(`    ${COLOR.dim}kill $(cat ${PID_FILE})${COLOR.reset}`);
    console.log();
    process.exit(0);
  } else {
    fail(`only ${okCount}/${DEMO_PAGES.length} demo pages rendered correctly.`);
    fail("the demo is not ready — investigate before showing it.");
    process.exit(3);
  }
}

main().catch((err) => {
  console.error(`${COLOR.red}boot failed:${COLOR.reset}`, err);
  process.exit(1);
});
