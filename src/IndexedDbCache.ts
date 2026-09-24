import type { Cache } from "./Cache.js"

/**
 * Structured-clone storage, including non-extractable CryptoKeys. Use a unique,
 * versioned namespace per component, application, client configuration and account.
 * Importing this module does not access browser globals. No silent memory fallback.
 */
export class IndexedDbCache<T> implements Cache<T> {
    readonly #name: string

    constructor(namespace: string, private readonly factory: IDBFactory = globalThis.indexedDB) {
        if (namespace.length === 0) throw new TypeError("A cache namespace is required")
        this.#name = `reactive-authentication:${namespace}`
    }

    async get(key: string): Promise<T | undefined> {
        return this.run("readonly", store => store.get(key))
    }

    async set(key: string, value: T): Promise<void> {
        await this.run("readwrite", store => store.put(value, key))
    }

    async delete(key: string): Promise<void> {
        await this.run("readwrite", store => store.delete(key))
    }

    async clear(): Promise<void> {
        await this.run("readwrite", store => store.clear())
    }

    private async open(): Promise<IDBDatabase> {
        if (this.factory === undefined) throw new Error("IndexedDB is unavailable")
        return new Promise((resolve, reject) => {
            const request = this.factory.open(this.#name, 1)
            let blocked = false
            request.onupgradeneeded = () => request.result.createObjectStore("entries")
            request.onerror = () => reject(request.error)
            request.onblocked = () => {
                blocked = true
                reject(new Error("Opening the cache database was blocked"))
            }
            request.onsuccess = () => {
                if (blocked) {
                    request.result.close()
                } else {
                    request.result.onversionchange = () => request.result.close()
                    resolve(request.result)
                }
            }
        })
    }

    private async run<R>(mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<R>): Promise<R> {
        const database = await this.open()
        try {
            return await new Promise<R>((resolve, reject) => {
                const transaction = database.transaction("entries", mode)
                // Request success alone does not guarantee the write was committed.
                transaction.onabort = () => reject(transaction.error ?? new Error("Cache transaction aborted"))
                let request: IDBRequest<R>
                try {
                    request = operation(transaction.objectStore("entries"))
                } catch (error) {
                    transaction.abort()
                    reject(error)
                    return
                }
                transaction.oncomplete = () => resolve(request.result)
            })
        } finally {
            database.close()
        }
    }
}
