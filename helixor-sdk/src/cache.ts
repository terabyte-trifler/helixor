// =============================================================================
// Client-side TTL cache.
//
// When a DeFi transaction calls getScore() multiple times for the same agent
// in one transaction, we serve from cache instead of hitting the network.
// =============================================================================

interface Entry<T> {
  value:     T;
  expiresAt: number;
}

export class ClientCache<T> {
  private store = new Map<string, Entry<T>>();
  private readonly ttlMs: number;

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
  }

  get(key: string): T | null {
    if (this.ttlMs <= 0) return null;
    const e = this.store.get(key);
    if (!e) return null;
    if (e.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return e.value;
  }

  set(key: string, value: T): void {
    if (this.ttlMs <= 0) return;
    this.store.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  invalidate(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  get size(): number {
    return this.store.size;
  }
}
