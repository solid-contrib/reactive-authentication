import type { SessionCache } from "./SessionCache.js"

const defaultDatabaseName = "reactive-authentication"
const storeName = "sessions"

/**
 * Persists sessions in IndexedDB, so they survive a reload or a browser restart.
 *
 * @remarks Preferred for DPoP. IndexedDB stores by structured clone, which keeps a non extractable {@link CryptoKey} intact, so the key outlives the page while remaining unreadable by script on the origin. {@link WebStorageSessionCache} cannot hold one at all.
 */
export class IndexedDbSessionCache<T> implements SessionCache<T> {
    readonly #databaseName: string
    #database?: Promise<IDBDatabase>

    constructor(databaseName: string = defaultDatabaseName) {
        this.#databaseName = databaseName
    }

    async get(key: string): Promise<T | undefined> {
        return this.#run("readonly", store => store.get(key))
    }

    async set(key: string, value: T): Promise<void> {
        await this.#run("readwrite", store => store.put(value, key))
    }

    async delete(key: string): Promise<void> {
        await this.#run("readwrite", store => store.delete(key))
    }

    async #run<R>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest<R>): Promise<R> {
        const database = await this.#open()

        return settled(work(database.transaction(storeName, mode).objectStore(storeName)))
    }

    #open(): Promise<IDBDatabase> {
        if (this.#database === undefined) {
            const request = indexedDB.open(this.#databaseName)
            request.onupgradeneeded = () => request.result.createObjectStore(storeName)

            this.#database = settled(request)
        }

        return this.#database
    }
}

function settled<R>(request: IDBRequest<R>): Promise<R> {
    const {promise, resolve, reject} = Promise.withResolvers<R>()

    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)

    return promise
}
