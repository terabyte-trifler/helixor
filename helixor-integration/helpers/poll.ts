// =============================================================================
// helpers/poll.ts — pollUntil with structured timeouts.
// =============================================================================

export interface PollOptions<T> {
  label:       string;
  timeoutMs?:  number;
  intervalMs?: number;
  check:       () => Promise<T | null | undefined>;
  describe?:   (last: T | null | undefined) => string;
}

export class PollTimeoutError extends Error {
  constructor(label: string, elapsedMs: number, description: string) {
    super(`[poll] ${label} did not complete within ${elapsedMs}ms. Last: ${description}`);
    this.name = "PollTimeoutError";
  }
}

export async function pollUntil<T>(opts: PollOptions<T>): Promise<T> {
  const timeout  = opts.timeoutMs  ?? 60_000;
  const interval = opts.intervalMs ?? 2_000;
  const started  = Date.now();
  let last: T | null | undefined = undefined;

  while (Date.now() - started < timeout) {
    try {
      last = await opts.check();
      if (last !== null && last !== undefined) {
        return last;
      }
    } catch (err) {
      last = err as any;
    }
    await sleep(interval);
  }

  const description = opts.describe ? opts.describe(last) : String(last ?? "nothing");
  throw new PollTimeoutError(opts.label, Date.now() - started, description);
}

export function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}
