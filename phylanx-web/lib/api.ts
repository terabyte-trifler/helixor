/**
 * lib/api.ts — Phylanx read-API client with mock fallback.
 *
 * Behavior:
 *   - If NEXT_PUBLIC_API_URL is set, fetch from it.
 *   - If unset, return deterministic mock data shaped exactly like the
 *     real API's schemas.py — so the UI is demoable today.
 *
 * The mock layer is intentionally HONEST: the landing page renders a
 * banner ("demo data — devnet not yet connected") when isMock() is true.
 * No silent lying about whether the data is real.
 *
 * Why a single fetch wrapper and not a swr/tanstack-query dependency:
 * the YC demo doesn't need optimistic updates or background refetch; a
 * single fetch with `cache: "no-store"` (so the live demo always reflects
 * the cluster) is enough. Less surface area, less bundle.
 */

import type {
  ByzantineRecentResponse,
  ChallengesResponse,
  ClusterHealthResponse,
  DiagnosisResponse,
  HealthResponse,
  HistoryResponse,
  LabelDeviationEvent,
  StrikeSummaryResponse,
  VersionResponse,
} from "@/types/api";
import { mockApi } from "./mock";

const API_URL =
  typeof process !== "undefined"
    ? process.env.NEXT_PUBLIC_API_URL
    : undefined;
const API_KEY =
  typeof process !== "undefined"
    ? process.env.PHYLANX_API_KEY ?? process.env.NEXT_PUBLIC_PHYLANX_API_KEY
    : undefined;

export function isMock(): boolean {
  return !API_URL;
}

export function networkLabel(): string {
  return process.env.NEXT_PUBLIC_NETWORK ?? "devnet";
}

class ApiNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApiNotFoundError";
  }
}

async function fetchJson<T>(path: string): Promise<T> {
  if (!API_URL) {
    throw new Error("NEXT_PUBLIC_API_URL not set — use mock path");
  }
  const url = `${API_URL.replace(/\/$/, "")}${path}`;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(url, {
    headers,
    cache: "no-store",
    next: { revalidate: 0 },
  });
  if (res.status === 404) {
    throw new ApiNotFoundError(`404 ${path}`);
  }
  if (!res.ok) {
    throw new Error(`API ${res.status} ${path}`);
  }
  return res.json() as Promise<T>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public client surface
// ─────────────────────────────────────────────────────────────────────────────

export async function getAgentHealth(
  wallet: string,
): Promise<HealthResponse | null> {
  if (isMock()) return mockApi.getAgentHealth(wallet);
  try {
    return await fetchJson<HealthResponse>(
      `/agents/${encodeURIComponent(wallet)}/health`,
    );
  } catch (e) {
    if (e instanceof ApiNotFoundError) return null;
    throw e;
  }
}

export async function getAgentHistory(
  wallet: string,
  limit = 30,
): Promise<HistoryResponse> {
  if (isMock()) return mockApi.getAgentHistory(wallet, limit);
  return fetchJson<HistoryResponse>(
    `/agents/${encodeURIComponent(wallet)}/history?limit=${limit}`,
  );
}

export async function getClusterHealth(): Promise<ClusterHealthResponse> {
  if (isMock()) return mockApi.getClusterHealth();
  return fetchJson<ClusterHealthResponse>("/health/cluster?limit=20");
}

export async function getByzantineRecent(): Promise<ByzantineRecentResponse> {
  if (isMock()) return mockApi.getByzantineRecent();
  return fetchJson<ByzantineRecentResponse>("/byzantine/recent");
}

export async function getStrikeSummary(): Promise<StrikeSummaryResponse> {
  if (isMock()) return mockApi.getStrikeSummary();
  return fetchJson<StrikeSummaryResponse>("/byzantine/strikes");
}

export async function getChallenges(
  node: string,
): Promise<ChallengesResponse> {
  if (isMock()) return mockApi.getChallenges(node);
  return fetchJson<ChallengesResponse>(
    `/challenges?node=${encodeURIComponent(node)}`,
  );
}

export async function getVersion(): Promise<VersionResponse> {
  if (isMock()) return mockApi.getVersion();
  return fetchJson<VersionResponse>("/version");
}

// Day-41: label-level deviation events for the transparency page. The
// real API endpoint hasn't shipped yet — when it does, swap the mock
// branch for an `await fetchJson<...>("/byzantine/label-deviations")`.
export async function getLabelDeviations(): Promise<LabelDeviationEvent[]> {
  if (isMock()) return mockApi.getLabelDeviations();
  try {
    return await fetchJson<LabelDeviationEvent[]>("/byzantine/label-deviations");
  } catch {
    return [];
  }
}

export async function getAgentDiagnosis(
  wallet: string,
): Promise<DiagnosisResponse | null> {
  if (isMock()) return mockApi.getAgentDiagnosis(wallet);
  try {
    return await fetchJson<DiagnosisResponse>(
      `/agents/${encodeURIComponent(wallet)}/diagnosis`,
    );
  } catch (e) {
    if (e instanceof ApiNotFoundError) return null;
    throw e;
  }
}
