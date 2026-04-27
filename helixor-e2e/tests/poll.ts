// =============================================================================
// tests/poll.ts — pollUntil + waitFor helpers for time-based assertions.
//
// Each step gets a name + timeout + interval. On failure, throws a clear
// message including how long was waited and the last value seen.
// =============================================================================

export interface PollOptions<T> {
  /** Human-readable label for the step. Used in failure messages. */
  label: string;

  /** Hard deadline. Default 60 000 ms. */
  timeoutMs?: number;

  /** How often to re-check. Default 2 000 ms. */
  intervalMs?: number;

  /** Predicate. Returns the value to return on success, or null/undefined to keep waiting. */
  check: () => Promise<T | null | undefined>;

  /** Optional: format the last seen value for the failure message. */
  describe?: (last: T | null | undefined) => string;
}

export class PollTimeoutError extends Error {
  constructor(
    public readonly label:    string,
    public readonly elapsedMs: number,
    public readonly lastValue: unknown,
    description:               string,
  ) {
    super(
      `[poll] ${label} did not complete within ${elapsedMs}ms. ` +
      `Last seen: ${description}`,
    );
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
        const elapsed = Date.now() - started;
        // eslint-disable-next-line no-console
        console.log(`  ✓ ${opts.label} (${elapsed}ms)`);
        return last;
      }
    } catch (err) {
      last = err as any;
    }
    await sleep(interval);
  }

  const description = opts.describe ? opts.describe(last) : String(last ?? "nothing");
  throw new PollTimeoutError(opts.label, Date.now() - started, last, description);
}

export function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}
