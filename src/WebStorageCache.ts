import type { Cache } from "./Cache.js"

/** Explicit encoding/validation for string-only storage; never use for CryptoKeys. */
export interface CacheCodec<T> {
    encode(value: T): string
    decode(value: string): T
}

/**
 * An opt-in adapter for localStorage or sessionStorage and non-secret values.
 * Storage/security/quota and decoding errors reject; clear affects only this namespace.
 */
export class WebStorageCache<T> implements Cache<T> {
    readonly #prefix: string

    constructor(private readonly storage: Storage, namespace: string, private readonly codec: CacheCodec<T>) {
        if (namespace.length === 0) throw new TypeError("A cache namespace is required")
        this.#prefix = `reactive-authentication:${JSON.stringify(namespace)}:`
    }

    async get(key: string): Promise<T | undefined> {
        const value = this.storage.getItem(this.#prefix + key)
        return value === null ? undefined : this.codec.decode(value)
    }

    async set(key: string, value: T): Promise<void> {
        this.storage.setItem(this.#prefix + key, this.codec.encode(value))
    }

    async delete(key: string): Promise<void> {
        this.storage.removeItem(this.#prefix + key)
    }

    async clear(): Promise<void> {
        const keys: string[] = []
        for (let i = 0; i < this.storage.length; i++) {
            const key = this.storage.key(i)
            if (key?.startsWith(this.#prefix)) keys.push(key)
        }
        for (const key of keys) this.storage.removeItem(key)
    }
}
