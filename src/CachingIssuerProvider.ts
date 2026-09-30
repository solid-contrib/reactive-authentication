import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import { IssuerProvider } from "./IssuerProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache: Cache<URL> = new MemoryCache // TODO: Take cache from caller
    readonly #original: IssuerProvider

    constructor(original: IssuerProvider) {
        this.#original = original
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
