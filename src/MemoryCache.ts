import type { Cache } from "./Cache.js"

/** Per-instance storage. Values retain their identity and are not serialized. */
export class MemoryCache<T> implements Cache<T> {
    readonly #values = new Map<string, T>()

    async get(key: string): Promise<T | undefined> {
        return this.#values.get(key)
    }

    async set(key: string, value: T): Promise<void> {
        this.#values.set(key, value)
    }

    async delete(key: string): Promise<void> {
        this.#values.delete(key)
    }

    async clear(): Promise<void> {
        this.#values.clear()
    }
}
