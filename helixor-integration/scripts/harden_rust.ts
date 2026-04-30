#!/usr/bin/env tsx
// =============================================================================
// scripts/harden_rust.ts — programmatic Rust hardening for helixor-programs.
//
// Replaces the spec's bash one-liners with structured checks.
// Each check exits with non-zero if it fails; collects failures + reports.
// =============================================================================

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";

const exec = promisify(execFile);

interface Check {
  name:        string;
  description: string;
  run:         () => Promise<CheckResult>;
}

interface CheckResult {
  ok:       boolean;
  detail:   string;
  warnings?: string[];
}


// =============================================================================
// Where the helixor-programs repo lives
// =============================================================================

const PROGRAMS_DIR = process.env.HELIXOR_PROGRAMS_DIR ?? "../helixor-programs";

async function ensurePrograms() {
  try {
    const stat = await fs.stat(PROGRAMS_DIR);
    if (!stat.isDirectory()) throw new Error("not a directory");
  } catch {
    throw new Error(
      `helixor-programs not found at ${PROGRAMS_DIR}. ` +
      `Set HELIXOR_PROGRAMS_DIR or run from a sibling repo.`,
    );
  }
}


// =============================================================================
// Checks
// =============================================================================

const checks: Check[] = [

  // ── cargo audit — CVE scanner ─────────────────────────────────────────────
  {
    name: "cargo_audit",
    description: "No CVEs in the dependency tree (cargo-audit).",
    run: async () => {
      try {
        await exec("cargo", ["audit", "--quiet"], { cwd: PROGRAMS_DIR });
        return { ok: true, detail: "no vulnerabilities found" };
      } catch (err: any) {
        return {
          ok: false,
          detail: `cargo audit reported issues:\n${err.stdout ?? err.stderr ?? err}`.slice(0, 1000),
        };
      }
    },
  },

  // ── cargo clippy — static analysis ────────────────────────────────────────
  {
    name: "cargo_clippy",
    description: "Zero clippy warnings (-D warnings).",
    run: async () => {
      try {
        await exec(
          "cargo",
          ["clippy", "--all-targets", "--all-features", "--quiet", "--", "-D", "warnings"],
          {
            cwd: PROGRAMS_DIR,
            maxBuffer: 8 * 1024 * 1024,
            env: { ...process.env, RUSTFLAGS: `${process.env.RUSTFLAGS ?? ""} -Aunexpected_cfgs`.trim() },
          },
        );
        return { ok: true, detail: "no clippy warnings" };
      } catch (err: any) {
        return {
          ok: false,
          detail: `clippy failed:\n${(err.stdout ?? "") + (err.stderr ?? "")}`.slice(0, 2000),
        };
      }
    },
  },

  // ── overflow-checks must be enabled ──────────────────────────────────────
  {
    name: "overflow_checks_enabled",
    description: "overflow-checks=true in Cargo.toml release profile.",
    run: async () => {
      const cargo = await fs.readFile(path.join(PROGRAMS_DIR, "Cargo.toml"), "utf-8");
      // Look for [profile.release] section with overflow-checks = true
      const releaseSection = cargo.match(/\[profile\.release\][\s\S]*?(?=\n\[|$)/);
      if (!releaseSection) {
        return { ok: false, detail: "no [profile.release] section in Cargo.toml" };
      }
      if (!/overflow-checks\s*=\s*true/.test(releaseSection[0])) {
        return {
          ok: false,
          detail: "overflow-checks not set to true in [profile.release]",
        };
      }
      return { ok: true, detail: "[profile.release].overflow-checks = true" };
    },
  },

  // ── No unguarded unwrap() in non-test code ───────────────────────────────
  {
    name: "no_naked_unwrap_in_program_code",
    description: "No `.unwrap()` calls in src/ (tests + scripts allowed).",
    run: async () => {
      const programsSrc = path.join(PROGRAMS_DIR, "programs");
      const offenders = await scanFiles(
        programsSrc,
        /\.rs$/,
        (line, path) => {
          // Allow in tests + comments
          if (line.includes("//")) {
            const beforeComment = line.split("//")[0]!;
            if (!/\.unwrap\s*\(\s*\)/.test(beforeComment)) return null;
          }
          if (path.includes("/tests/") || path.endsWith("_test.rs") || path.endsWith("/test.rs")) return null;
          if (/\.unwrap\s*\(\s*\)/.test(line)) return line.trim();
          return null;
        },
      );
      if (offenders.length === 0) {
        return { ok: true, detail: "no naked unwraps in production paths" };
      }
      return {
        ok: false,
        detail: `${offenders.length} naked unwrap(s) found:\n` +
                offenders.slice(0, 20).map(o => `  ${o}`).join("\n"),
      };
    },
  },

  // ── No expect() with bypassable strings ──────────────────────────────────
  {
    name: "no_expect_in_program_code",
    description: "No `.expect(\"...\")` in src/ (use ? or proper errors).",
    run: async () => {
      const programsSrc = path.join(PROGRAMS_DIR, "programs");
      const offenders = await scanFiles(
        programsSrc,
        /\.rs$/,
        (line, path) => {
          if (path.includes("/tests/") || path.endsWith("_test.rs")) return null;
          if (/\.expect\s*\(\s*"/.test(line)) return line.trim();
          return null;
        },
      );
      if (offenders.length === 0) return { ok: true, detail: "no .expect() in production paths" };
      return {
        ok: false,
        detail: `${offenders.length} .expect() call(s):\n` +
                offenders.slice(0, 20).map(o => `  ${o}`).join("\n"),
      };
    },
  },

  // ── PDA bumps must be persisted (not re-derived) ─────────────────────────
  {
    name: "pda_bumps_canonical",
    description: "PDA accounts store their bump in state (avoid drift).",
    run: async () => {
      const programsSrc = path.join(PROGRAMS_DIR, "programs");
      const stateFiles = await findFiles(programsSrc, /state\.rs$/);

      // Look for `bump` field on each PDA-backed account struct.
      const missing: string[] = [];
      for (const file of stateFiles) {
        const content = await fs.readFile(file, "utf-8");
        // Find each struct with #[account] decoration; check for `bump:` field
        const structs = content.match(/#\[account[^\]]*\]\s*pub struct (\w+)\s*\{([\s\S]*?)\n\}/g) ?? [];
        for (const s of structs) {
          const nameMatch = s.match(/pub struct (\w+)/);
          const name = nameMatch?.[1] ?? "(unknown)";
          if (!/\bbump\s*:/.test(s)) {
            // OracleConfig is the one allowed exception (singleton, no PDA bump needed)
            if (name === "OracleConfig") continue;
            missing.push(`${path.basename(file)}::${name}`);
          }
        }
      }
      if (missing.length === 0) {
        return { ok: true, detail: "all PDA-backed accounts persist their bump" };
      }
      return {
        ok: false,
        detail: `missing bump field on:\n  ${missing.join("\n  ")}`,
      };
    },
  },

  // ── No hardcoded keypairs ────────────────────────────────────────────────
  {
    name: "no_hardcoded_keypairs",
    description: "No 64-byte literals in src/ (potential keypair leakage).",
    run: async () => {
      const offenders = await scanFiles(
        PROGRAMS_DIR,
        /\.(rs|ts|js|json)$/,
        (line, p) => {
          if (p.includes("/node_modules/") || p.includes("/target/")) return null;
          // 64-byte arrays look like `[N, N, N, ...]` with 64 numbers
          // We approximate: lines with 30+ comma-separated numbers
          if (line.includes("[") && line.includes("]")) {
            const numbers = line.match(/\b\d{1,3}\s*,/g) ?? [];
            if (numbers.length >= 30) return p + ": " + line.trim().slice(0, 80);
          }
          return null;
        },
      );
      if (offenders.length === 0) return { ok: true, detail: "no large numeric literals in src" };
      return {
        ok: true,  // warning only — could be legitimate
        detail: `[warning] ${offenders.length} large numeric literal(s) — review for leaked keys:\n` +
                offenders.slice(0, 10).map(o => `  ${o}`).join("\n"),
        warnings: offenders.slice(0, 10),
      };
    },
  },

  // ── update_score signer constraint ───────────────────────────────────────
  {
    name: "update_score_authority_constraint",
    description: "update_score has explicit oracle authority constraint.",
    run: async () => {
      const handlersDir = path.join(PROGRAMS_DIR, "programs/health-oracle/src/instructions");
      const updateScoreFile = path.join(handlersDir, "update_score.rs");
      try {
        const content = await fs.readFile(updateScoreFile, "utf-8");
        // Look for a constraint = ... oracle_node check
        const hasOracleCheck =
          /constraint\s*=\s*.*oracle_node/.test(content) ||
          /oracle_node\.key\(\)\s*==\s*signer/i.test(content) ||
          /address\s*=\s*oracle_config\.oracle_node/.test(content) ||
          /require_keys_eq!\s*\(\s*ctx\.accounts\.oracle\.key\(\)\s*,\s*cfg\.oracle_key/i.test(content);
        if (!hasOracleCheck) {
          return {
            ok: false,
            detail: "update_score.rs does not appear to enforce oracle authority constraint",
          };
        }
        return { ok: true, detail: "oracle authority constraint present" };
      } catch (e: any) {
        return { ok: false, detail: `couldn't read update_score.rs: ${e.message}` };
      }
    },
  },

];


// =============================================================================
// File scanner
// =============================================================================

async function findFiles(root: string, pattern: RegExp): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string) {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); }
    catch { return; }
    for (const e of entries) {
      if (e.name.startsWith(".") || e.name === "node_modules" || e.name === "target") continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) await walk(p);
      else if (pattern.test(e.name)) out.push(p);
    }
  }
  await walk(root);
  return out;
}

async function scanFiles(
  root: string, pattern: RegExp,
  predicate: (line: string, filePath: string) => string | null,
): Promise<string[]> {
  const files = await findFiles(root, pattern);
  const out: string[] = [];
  for (const f of files) {
    const content = await fs.readFile(f, "utf-8");
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const flagged = predicate(lines[i]!, f);
      if (flagged) out.push(`${path.relative(root, f)}:${i+1}: ${flagged}`);
    }
  }
  return out;
}


// =============================================================================
// Runner
// =============================================================================

async function main() {
  await ensurePrograms();

  console.log("");
  console.log("╔════════════════════════════════════════════════════════════╗");
  console.log("║  Helixor — Day 13 Rust Hardening                          ║");
  console.log(`║  Target: ${PROGRAMS_DIR.padEnd(48)}║`);
  console.log("╚════════════════════════════════════════════════════════════╝");
  console.log("");

  let failed  = 0;
  let warnings = 0;
  for (const c of checks) {
    process.stdout.write(`  • ${c.name.padEnd(36)} ... `);
    let result: CheckResult;
    try { result = await c.run(); }
    catch (err: any) {
      result = { ok: false, detail: `check threw: ${err.message ?? err}` };
    }
    if (result.ok && (result.warnings?.length ?? 0) === 0) {
      console.log(`\x1b[32m✓\x1b[0m  ${result.detail.split("\n")[0]}`);
    } else if (result.ok) {
      console.log(`\x1b[33m⚠\x1b[0m  ${result.detail.split("\n")[0]}`);
      warnings++;
    } else {
      console.log(`\x1b[31m✗\x1b[0m`);
      console.log(`      ${c.description}`);
      console.log(result.detail.split("\n").map(l => "      " + l).join("\n"));
      failed++;
    }
  }

  console.log("");
  if (failed > 0) {
    console.log(`\x1b[31m✗ ${failed} check(s) failed.\x1b[0m`);
    if (warnings > 0) console.log(`  ${warnings} warning(s).`);
    process.exit(1);
  }
  if (warnings > 0) {
    console.log(`\x1b[33m! all checks passed (${warnings} warning(s) — review above)\x1b[0m`);
    process.exit(0);
  }
  console.log(`\x1b[32m✓ all hardening checks passed\x1b[0m`);
}

main().catch((err) => { console.error(err); process.exit(1); });
