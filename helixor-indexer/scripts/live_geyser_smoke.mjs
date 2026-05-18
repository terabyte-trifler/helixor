#!/usr/bin/env node
/**
 * Live Yellowstone/LaserStream smoke test.
 *
 * This verifies the real provider edge: endpoint -> auth -> gRPC subscribe ->
 * first streamed update. It intentionally does not write to TimescaleDB; the
 * Python Day-16 tests already verify the stream -> filter -> decode -> write
 * pipeline. This script proves the external socket and credentials.
 *
 * Required:
 *   HELIUS_GEYSER_TOKEN or HELIUS_API_KEY
 *
 * Optional:
 *   HELIUS_GEYSER_ENDPOINT  default: Helius LaserStream devnet endpoint
 *   TARGET_ACCOUNT          default: Helixor devnet test agent
 *   MODE                    slots | transactions
 *   TIMEOUT_MS              default: 20000
 */

import Client, { CommitmentLevel } from "@triton-one/yellowstone-grpc";

const endpoint =
  process.env.HELIUS_GEYSER_ENDPOINT ||
  "https://laserstream-devnet-ewr.helius-rpc.com";
const token = process.env.HELIUS_GEYSER_TOKEN || process.env.HELIUS_API_KEY;
const target =
  process.env.TARGET_ACCOUNT ||
  "8kJ2gRXQkKKBc1KZLEMseBExM42KnpGsTmYfZ7Tyf5gL";
const timeoutMs = Number(process.env.TIMEOUT_MS || 20_000);
const mode = process.env.MODE || "slots";

if (!token) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        reason: "missing_geyser_token",
        message: "Set HELIUS_GEYSER_TOKEN or HELIUS_API_KEY.",
      },
      null,
      2,
    ),
  );
  process.exit(2);
}

function requestForMode() {
  if (mode === "transactions") {
    return {
      accounts: {},
      accountsDataSlice: [],
      transactions: {
        helixorAgent: {
          vote: false,
          failed: false,
          signature: undefined,
          accountInclude: [target],
          accountExclude: [],
          accountRequired: [],
        },
      },
      transactionsStatus: {},
      slots: {},
      blocks: {},
      blocksMeta: {},
      entry: {},
      commitment: CommitmentLevel.CONFIRMED,
    };
  }

  return {
    accounts: {},
    accountsDataSlice: [],
    transactions: {},
    transactionsStatus: {},
    slots: { helixorSlots: { filterByCommitment: true } },
    blocks: {},
    blocksMeta: {},
    entry: {},
    commitment: CommitmentLevel.CONFIRMED,
  };
}

function publicError(err) {
  return {
    message: err?.message || String(err),
    code: err?.code,
    details: err?.details,
    cause: err?.cause?.message || err?.cause?.details,
  };
}

const client = new Client(endpoint, token, {
  "grpc.max_receive_message_length": 64 * 1024 * 1024,
});

let stream;
let settled = false;

function finish(code, payload) {
  if (settled) return;
  settled = true;
  try {
    stream?.end();
  } catch {}
  try {
    client.close();
  } catch {}
  console.log(JSON.stringify(payload, null, 2));
  process.exit(code);
}

try {
  await client.connect();
  stream = await client.subscribe();
} catch (err) {
  finish(1, {
    ok: false,
    reason: "connect_or_subscribe_failed",
    endpoint,
    mode,
    target,
    error: publicError(err),
  });
}

const timer = setTimeout(() => {
  finish(2, {
    ok: false,
    reason: "timeout_waiting_for_update",
    endpoint,
    mode,
    target,
    timeoutMs,
  });
}, timeoutMs);

stream.on("data", (data) => {
  clearTimeout(timer);
  const kind = data.slot
    ? "slot"
    : data.transaction
      ? "transaction"
      : data.pong
        ? "pong"
        : Object.keys(data).find((key) => data[key]);
  finish(0, {
    ok: true,
    endpoint,
    mode,
    target,
    kind,
    slot: data.slot?.slot ?? data.transaction?.slot ?? null,
    hasTransaction: Boolean(data.transaction),
    receivedAt: new Date().toISOString(),
  });
});

stream.on("error", (err) => {
  clearTimeout(timer);
  finish(1, {
    ok: false,
    reason: "stream_error",
    endpoint,
    mode,
    target,
    error: publicError(err),
  });
});

stream.on("end", () => {
  clearTimeout(timer);
  finish(1, {
    ok: false,
    reason: "stream_ended",
    endpoint,
    mode,
    target,
  });
});

await new Promise((resolve, reject) => {
  stream.write(requestForMode(), (err) => (err ? reject(err) : resolve()));
});
