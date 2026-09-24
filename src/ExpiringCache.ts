import type { Cache } from "./Cache.js"

export interface ExpiringCacheEntry<T> {
    value: T
    expiresAt: number
}

/** Absolute write-time TTL, preserved across reloads. Reads do not extend it. */
export class ExpiringCache<T> implements Cache<T> {
    constructor(private readonly cache: Cache<ExpiringCacheEntry<T>>, private readonly maxAgeMs: number) {
        if (!Number.isFinite(maxAgeMs) || maxAgeMs <= 0) throw new TypeError("Cache maxAgeMs must be positive and finite")
    }

    async get(key: string): Promise<T | undefined> {
        const entry = await this.cache.get(key)
        // Do not delete after a read: another tab may have just replaced the entry.
        return entry !== undefined && entry.expiresAt > Date.now() ? entry.value : undefined
    }

    async set(key: string, value: T): Promise<void> {
        await this.cache.set(key, {value, expiresAt: Date.now() + this.maxAgeMs})
    }

    async delete(key: string): Promise<void> {
        await this.cache.delete(key)
    }

    async clear(): Promise<void> {
        await this.cache.clear()
    }
}
