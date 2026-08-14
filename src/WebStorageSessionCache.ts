import type { SessionCache } from "./SessionCache.js"

const defaultPrefix = "reactive-authentication:"

/**
 * Persists sessions as JSON in web storage: `localStorage` to survive a browser restart, or `sessionStorage` to last only as long as the tab.
 *
 * @remarks Suitable for sessions that are entirely JSON, such as a bare refresh token. A DPoP session is not, because {@link JSON.stringify} discards a {@link CryptoKey} without complaining; {@link set} throws rather than store one, and {@link IndexedDbSessionCache} handles that case.
 *
 * @remarks Anything kept here is readable by any script running on the origin, so store the least that will do.
 */
export class WebStorageSessionCache<T> implements SessionCache<T> {
    readonly #storage: Storage
    readonly #prefix: string

    /**
     * @param storage - Which store to use, normally `localStorage` or `sessionStorage`.
     * @param prefix - Namespace for the keys, to keep them apart from the rest of the origin's data.
     */
    constructor(storage: Storage, prefix: string = defaultPrefix) {
        this.#storage = storage
        this.#prefix = prefix
    }

    async get(key: string): Promise<T | undefined> {
        const stored = this.#storage.getItem(this.#prefix + key)
        if (stored === null) {
            return undefined
        }

        try {
            return JSON.parse(stored) as T
        } catch {
            // Left by an older version, or by something else on the origin.
            await this.delete(key)

            return undefined
        }
    }

    async set(key: string, value: T): Promise<void> {
        this.#storage.setItem(this.#prefix + key, JSON.stringify(value, rejectCryptoKey))
    }

    async delete(key: string): Promise<void> {
        this.#storage.removeItem(this.#prefix + key)
    }
}

function rejectCryptoKey(_: string, value: unknown): unknown {
    if (typeof CryptoKey !== "undefined" && value instanceof CryptoKey) {
        throw new TypeError("A CryptoKey cannot be stored in web storage, because JSON.stringify would silently discard it. Use IndexedDbSessionCache instead.")
    }

    return value
}
