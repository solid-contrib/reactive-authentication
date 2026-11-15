import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import { IssuerProvider } from "./IssuerProvider.js"
import type { CacheKeyProvider } from "./CacheKeyProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache: Cache<URL>
    readonly #original: IssuerProvider
    readonly #cacheKeyProvider: CacheKeyProvider

    /**
     * @param original The provider whose results are cached.
     * @param cacheKeyProvider Turns a request into the key its issuer is cached under.
     * @param cache Where results are kept. Defaults to a new {@link MemoryCache} owned by this instance.
     */
    constructor(original: IssuerProvider, cacheKeyProvider: CacheKeyProvider, cache: Cache<URL> = new MemoryCache) {
        this.#original = original
        this.#cacheKeyProvider = cacheKeyProvider
        this.#cache = cache
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
