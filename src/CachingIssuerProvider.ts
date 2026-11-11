import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import { IssuerProvider } from "./IssuerProvider.js"
import type { CacheKeyProvider } from "./CacheKeyProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache: Cache<URL> = new MemoryCache // TODO: Take cache from caller
    readonly #original: IssuerProvider
    readonly #cacheKeyProvider: CacheKeyProvider

    constructor(original: IssuerProvider, cacheKeyProvider: CacheKeyProvider) {
        this.#original = original
        this.#cacheKeyProvider = cacheKeyProvider
    }

    async getIssuer(request: Request): Promise<URL> {
        const key = await this.#cacheKeyProvider.getKey(request)
        return await navigator.locks.request(`CachingIssuerProvider.getIssuer[${key}]`, async () => {
            const cached = await this.#cache.getItem(key)
            if (cached !== null) {
                return cached
            }

            const fresh = await this.#original.getIssuer(request)
            await this.#cache.setItem(key, fresh)
            return fresh
        })
    }
}
