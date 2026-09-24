import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import { IssuerProvider } from "./IssuerProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache: Cache<string>
    readonly #original: IssuerProvider

    constructor(original: IssuerProvider, cache: Cache<string> = new MemoryCache()) {
        this.#cache = cache
        this.#original = original
    }

    async getIssuer(request: Request): Promise<URL> {
        const cached = await this.#cache.get(request.url)
        if (cached !== undefined) {
            return new URL(cached)
        }

        const fresh = await this.#original.getIssuer(request)
        await this.#cache.set(request.url, fresh.href)
        return fresh
    }
}
