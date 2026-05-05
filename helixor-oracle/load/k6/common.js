import { check, fail } from "k6";

export function requiredEnv(name) {
  const value = __ENV[name];
  if (!value) {
    fail(`Missing required env var: ${name}`);
  }
  return value;
}

export function optionalEnv(name, fallback) {
  return __ENV[name] || fallback;
}

export function csvEnv(name, fallback) {
  return optionalEnv(name, fallback)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function pick(items) {
  return items[Math.floor(Math.random() * items.length)];
}

export function headers(extra = {}) {
  const base = {
    "Content-Type": "application/json",
    "User-Agent": "helixor-k6-load-test/1.0",
  };
  const apiKey = __ENV.HELIXOR_API_KEY;
  if (apiKey) {
    base.Authorization = `Bearer ${apiKey}`;
  }
  return { ...base, ...extra };
}

export function checkHttp(res, name, expectedStatuses) {
  const allowed = Array.isArray(expectedStatuses)
    ? expectedStatuses
    : [expectedStatuses];
  return check(res, {
    [`${name}: status ${allowed.join(" or ")}`]: (r) => allowed.includes(r.status),
    [`${name}: no 5xx`]: (r) => r.status < 500,
  });
}

export function uniqueId(prefix) {
  return `${prefix}-${__VU}-${__ITER}-${Date.now()}-${Math.random()
    .toString(16)
    .slice(2)}`;
}
