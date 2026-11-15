import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import { IssuerProvider } from "./IssuerProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache: Cache<URL>
    readonly #original: IssuerProvider

    /**
     * @param original The provider whose results are cached.
     * @param cache Where results are kept. Defaults to a new {@link MemoryCache} owned by this instance.
     */
    constructor(original: IssuerProvider, cache: Cache<URL> = new MemoryCache) {
        this.#original = original
        this.#cache = cache
    }

    async getIssuer(request: Request): Promise<URL> {
        const cached = await this.#cache.getItem(request.url)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getIssuer(request)
        await this.#cache.setItem(request.url, fresh)
        return fresh
    }
}
