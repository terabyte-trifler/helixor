import http from "k6/http";
import { sleep } from "k6";
import {
  checkHttp,
  csvEnv,
  headers,
  optionalEnv,
  pick,
  uniqueId,
} from "./common.js";

const API_BASE_URL = optionalEnv("API_BASE_URL", "http://127.0.0.1:8001");
const SCORE_WALLETS = csvEnv(
  "SCORE_WALLETS",
  "AGENT11111111111111111111111111111111111111",
);
const SCORE_EXPECTED_STATUS = Number(optionalEnv("SCORE_EXPECTED_STATUS", "200"));
const AGENTS_LIMIT = Number(optionalEnv("AGENTS_LIMIT", "50"));

export const options = {
  scenarios: {
    score_reads: {
      executor: "constant-arrival-rate",
      exec: "scoreRead",
      rate: Number(optionalEnv("SCORE_RPS", "20")),
      timeUnit: "1s",
      duration: optionalEnv("DURATION", "2m"),
      preAllocatedVUs: Number(optionalEnv("SCORE_VUS", "20")),
      maxVUs: Number(optionalEnv("SCORE_MAX_VUS", "100")),
    },
    agents_listing: {
      executor: "constant-arrival-rate",
      exec: "agentsList",
      rate: Number(optionalEnv("AGENTS_RPS", "5")),
      timeUnit: "1s",
      duration: optionalEnv("DURATION", "2m"),
      preAllocatedVUs: Number(optionalEnv("AGENTS_VUS", "5")),
      maxVUs: Number(optionalEnv("AGENTS_MAX_VUS", "25")),
    },
    telemetry_beacons: {
      executor: "constant-arrival-rate",
      exec: "telemetryBeacon",
      rate: Number(optionalEnv("TELEMETRY_RPS", "10")),
      timeUnit: "1s",
      duration: optionalEnv("DURATION", "2m"),
      preAllocatedVUs: Number(optionalEnv("TELEMETRY_VUS", "10")),
      maxVUs: Number(optionalEnv("TELEMETRY_MAX_VUS", "50")),
    },
  },
  thresholds: {
    http_req_failed: [`rate<${optionalEnv("MAX_FAILURE_RATE", "0.01")}`],
    "http_req_duration{endpoint:score}": [
      `p(95)<${optionalEnv("SCORE_P95_MS", "250")}`,
      `p(99)<${optionalEnv("SCORE_P99_MS", "500")}`,
    ],
    "http_req_duration{endpoint:agents}": [
      `p(95)<${optionalEnv("AGENTS_P95_MS", "400")}`,
    ],
    "http_req_duration{endpoint:telemetry}": [
      `p(95)<${optionalEnv("TELEMETRY_P95_MS", "500")}`,
    ],
  },
};

export function scoreRead() {
  const wallet = pick(SCORE_WALLETS);
  const res = http.get(`${API_BASE_URL}/score/${wallet}`, {
    headers: headers(),
    tags: { endpoint: "score" },
  });
  checkHttp(res, "/score", SCORE_EXPECTED_STATUS);
  sleep(0.05);
}

export function agentsList() {
  const res = http.get(`${API_BASE_URL}/agents?limit=${AGENTS_LIMIT}&offset=0`, {
    headers: headers(),
    tags: { endpoint: "agents" },
  });
  checkHttp(res, "/agents", 200);
  sleep(0.05);
}

export function telemetryBeacon() {
  const wallet = pick(SCORE_WALLETS);
  const payload = {
    event_type: "agent_score_fetched",
    plugin_version: optionalEnv("PLUGIN_VERSION", "k6"),
    elizaos_version: "load-test",
    node_version: "k6",
    agent_wallet: wallet,
    character_name: "k6-load-agent",
    score: 750,
    alert_level: "GREEN",
    action_name: "load_test",
    extra: { source: "k6" },
    beacon_id: uniqueId("beacon"),
  };

  const res = http.post(`${API_BASE_URL}/telemetry/beacon`, JSON.stringify(payload), {
    headers: headers(),
    tags: { endpoint: "telemetry" },
  });
  checkHttp(res, "/telemetry/beacon", 202);
  sleep(0.05);
}
