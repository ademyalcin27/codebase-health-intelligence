/**
 * LRU-style cache with a max entry limit and TTL.
 * Evicts the oldest entry when capacity is exceeded.
 */
export class BoundedCache<V> {
  private readonly store = new Map<string, { value: V; fetchedAt: number }>();

  constructor(
    private readonly maxSize: number,
    private readonly ttlMs: number
  ) {}

  get(key: string): V | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() - entry.fetchedAt > this.ttlMs) {
      this.store.delete(key);
      return undefined;
    }
    // Refresh insertion order (LRU)
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }

  set(key: string, value: V): void {
    if (this.store.has(key)) this.store.delete(key);
    if (this.store.size >= this.maxSize) {
      // Evict oldest
      const firstKey = this.store.keys().next().value;
      if (firstKey !== undefined) this.store.delete(firstKey);
    }
    this.store.set(key, { value, fetchedAt: Date.now() });
  }

  get size(): number {
    return this.store.size;
  }
}
