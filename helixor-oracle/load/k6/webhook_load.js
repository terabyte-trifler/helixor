import http from "k6/http";
import { sleep } from "k6";
import { checkHttp, csvEnv, optionalEnv, pick, requiredEnv, uniqueId } from "./common.js";

const WEBHOOK_BASE_URL = optionalEnv("WEBHOOK_BASE_URL", "http://127.0.0.1:8000");
const WEBHOOK_AUTH_TOKEN = requiredEnv("HELIUS_WEBHOOK_AUTH_TOKEN");
const WEBHOOK_AGENT_WALLETS = csvEnv(
  "WEBHOOK_AGENT_WALLETS",
  "AGENT11111111111111111111111111111111111111",
);
const WEBHOOK_BATCH_SIZE = Number(optionalEnv("WEBHOOK_BATCH_SIZE", "10"));

export const options = {
  scenarios: {
    webhook_ingestion: {
      executor: "constant-arrival-rate",
      exec: "webhookBatch",
      rate: Number(optionalEnv("WEBHOOK_RPS", "5")),
      timeUnit: "1s",
      duration: optionalEnv("DURATION", "2m"),
      preAllocatedVUs: Number(optionalEnv("WEBHOOK_VUS", "10")),
      maxVUs: Number(optionalEnv("WEBHOOK_MAX_VUS", "100")),
    },
  },
  thresholds: {
    http_req_failed: [`rate<${optionalEnv("MAX_FAILURE_RATE", "0.01")}`],
    "http_req_duration{endpoint:webhook}": [
      `p(95)<${optionalEnv("WEBHOOK_P95_MS", "500")}`,
      `p(99)<${optionalEnv("WEBHOOK_P99_MS", "1000")}`,
    ],
  },
};

function heliusTx(agentWallet, index) {
  const signature = uniqueId(`k6sig${index}`).replace(/[^a-zA-Z0-9]/g, "").slice(0, 88);
  return {
    signature,
    slot: 265000000 + index,
    timestamp: Math.floor(Date.now() / 1000),
    type: "TRANSFER",
    feePayer: agentWallet,
    fee: 5000,
    instructions: [{ programId: "11111111111111111111111111111111" }],
    accountData: [{ account: agentWallet, nativeBalanceChange: -5000 }],
  };
}

export function webhookBatch() {
  const payload = [];
  for (let i = 0; i < WEBHOOK_BATCH_SIZE; i += 1) {
    payload.push(heliusTx(pick(WEBHOOK_AGENT_WALLETS), i));
  }

  const res = http.post(`${WEBHOOK_BASE_URL}/webhook`, JSON.stringify(payload), {
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "helixor-k6-webhook-load-test/1.0",
      Authorization: WEBHOOK_AUTH_TOKEN,
    },
    tags: { endpoint: "webhook" },
  });

  checkHttp(res, "/webhook", 200);
  sleep(0.05);
}
