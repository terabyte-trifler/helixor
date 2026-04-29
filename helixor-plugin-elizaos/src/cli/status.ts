#!/usr/bin/env node
// =============================================================================
// CLI: npx @elizaos/plugin-helixor status
//
// Confirms the operator's plugin installation by hitting /telemetry/whoami
// with their API key. Displays:
//   - Operator account info (organization, tier, contact)
//   - All agents this operator has integrated
//   - 24h block + allow counts
//   - Whether plugin_initialized has been received in last 7 days
//
// This is the answer to Day 12's "operator confirms in chat that the plugin
// works." They run the command, copy the output, paste into Discord.
// =============================================================================

import { PLUGIN_VERSION } from "../version";


interface IntegrationSummary {
  operator_id:     number;
  organization:    string | null;
  contact_email:   string | null;
  discord_handle:  string | null;
  tier:            string;
  integrations:    Array<{
    agent_wallet:    string;
    character_name:  string | null;
    plugin_version:  string | null;
    first_seen_at:   string;
    last_seen_at:    string;
    blocks_count:    number;
    allows_count:    number;
  }>;
  plugin_initialized_count: number;
  blocks_24h:      number;
  allows_24h:      number;
}


const GREEN  = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED    = "\x1b[31m";
const DIM    = "\x1b[2m";
const BOLD   = "\x1b[1m";
const NC     = "\x1b[0m";


async function main(): Promise<number> {
  const apiUrl = process.env.HELIXOR_API_URL ?? "https://api.helixor.xyz";
  const apiKey = process.env.HELIXOR_API_KEY;

  if (!apiKey) {
    console.error(`${RED}error:${NC} HELIXOR_API_KEY is not set in environment.`);
    console.error(`Set it in your .env, then re-run.`);
    return 2;
  }

  console.log("");
  console.log(`${BOLD}Helixor plugin status${NC}  ${DIM}(v${PLUGIN_VERSION}, ${apiUrl})${NC}`);
  console.log("");

  let response: Response;
  try {
    response = await fetch(`${apiUrl.replace(/\/+$/, "")}/telemetry/whoami`, {
      method: "GET",
      headers: { "Authorization": `Bearer ${apiKey}` },
    });
  } catch (err: any) {
    console.error(`${RED}✗${NC} could not reach ${apiUrl}: ${err?.message ?? err}`);
    return 1;
  }

  if (response.status === 401) {
    console.error(`${RED}✗${NC} API key not recognized.`);
    console.error(`  Reach out to the Helixor team if you think this is wrong.`);
    return 1;
  }
  if (!response.ok) {
    console.error(`${RED}✗${NC} server returned ${response.status}: ${await response.text()}`);
    return 1;
  }

  const data = (await response.json()) as IntegrationSummary;

  // ── Operator panel ───────────────────────────────────────────────────────
  console.log(`  ${BOLD}operator${NC}      ${data.organization ?? "(unnamed)"}`);
  console.log(`  ${BOLD}operator_id${NC}   ${data.operator_id}`);
  console.log(`  ${BOLD}tier${NC}          ${tierBadge(data.tier)}`);
  if (data.contact_email)  console.log(`  ${DIM}email${NC}         ${data.contact_email}`);
  if (data.discord_handle) console.log(`  ${DIM}discord${NC}       ${data.discord_handle}`);

  console.log("");
  console.log(`  ${BOLD}24h activity${NC}    ${data.allows_24h} allowed   ${data.blocks_24h} blocked`);
  console.log(`  ${BOLD}initialized${NC}     ${data.plugin_initialized_count} times in last 7 days`);

  // ── Integrations ─────────────────────────────────────────────────────────
  console.log("");
  console.log(`  ${BOLD}── integrations ──${NC}`);
  if (data.integrations.length === 0) {
    console.log(`    ${YELLOW}!${NC} no agents seen yet. Start your elizaOS agent and re-run.`);
  } else {
    for (const i of data.integrations) {
      const agent = i.agent_wallet.slice(0, 12) + "...";
      const last  = formatRelativeTime(new Date(i.last_seen_at));
      console.log(`    ${GREEN}●${NC} ${(i.character_name ?? "(unnamed)").padEnd(28)} ${agent} ` +
                  `${DIM}plugin v${i.plugin_version}, last seen ${last}${NC}`);
      console.log(`      ${DIM}allows=${i.allows_count}  blocks=${i.blocks_count}${NC}`);
    }
  }

  // ── Healthcheck ──────────────────────────────────────────────────────────
  console.log("");
  if (data.plugin_initialized_count > 0 && data.integrations.length > 0) {
    console.log(`  ${GREEN}✓ Helixor plugin is installed + reporting telemetry${NC}`);
    console.log("");
    console.log(`  ${DIM}Paste this confirmation into your Discord/Telegram:${NC}`);
    console.log("");
    console.log(`     "Helixor plugin v${PLUGIN_VERSION} is running for ${data.organization ?? "us"}.`);
    console.log(`      ${data.integrations.length} agent(s) integrated, ${data.allows_24h} actions allowed`);
    console.log(`      and ${data.blocks_24h} blocked in the last 24 hours."`);
    console.log("");
    return 0;
  }

  console.log(`  ${YELLOW}!${NC} no plugin_initialized telemetry yet. Check:`);
  console.log(`    1. HELIXOR_API_KEY is set in your agent's .env`);
  console.log(`    2. Agent has been started at least once`);
  console.log(`    3. ${apiUrl}/telemetry/beacon is reachable from your agent`);
  return 1;
}


function tierBadge(tier: string): string {
  if (tier === "team")    return `${GREEN}team${NC}`;
  if (tier === "partner") return `${GREEN}partner${NC}`;
  return `${DIM}free${NC}`;
}


function formatRelativeTime(date: Date): string {
  const ageMs = Date.now() - date.getTime();
  const min = Math.floor(ageMs / 60_000);
  if (min < 1)        return "just now";
  if (min < 60)       return `${min}min ago`;
  const h = Math.floor(min / 60);
  if (h < 48)         return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}


main().then((code) => process.exit(code))
      .catch((err) => { console.error(err); process.exit(2); });
