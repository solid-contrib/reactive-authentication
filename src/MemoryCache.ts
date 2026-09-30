import type { Cache } from "./Cache.js"

export class MemoryCache<T extends NonNullable<unknown>> implements Cache<T> {
    readonly #values = new Map<string, T>

    async getItem(key: string): Promise<T | null> {
        return this.#values.get(key) ?? null
    }

    async setItem(key: string, value: T): Promise<void> {
        this.#values.set(key, value)
    }

    async removeItem(key: string): Promise<void> {
        this.#values.delete(key)
    }
}
