import type { SessionCache } from "./SessionCache.js"

/** Keeps sessions for the lifetime of the provider. */
export class MemorySessionCache<T> implements SessionCache<T> {
    readonly #entries = new Map<string, T>()

    async get(key: string): Promise<T | undefined> {
        return this.#entries.get(key)
    }

    async set(key: string, value: T): Promise<void> {
        this.#entries.set(key, value)
    }

    async delete(key: string): Promise<void> {
        this.#entries.delete(key)
    }
}
