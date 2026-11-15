import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #cache: Cache<oauth.AuthorizationServer>
    readonly #original: AuthorizationServerProvider

    /**
     * @param original The provider whose results are cached.
     * @param cache Where results are kept. Defaults to a new {@link MemoryCache} owned by this instance.
     */
    constructor(original: AuthorizationServerProvider, cache: Cache<oauth.AuthorizationServer> = new MemoryCache) {
        this.#original = original
        this.#cache = cache
    }

    async getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        const cached = await this.#cache.getItem(request.url)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getAuthorizationServer(request)
        await this.#cache.setItem(request.url, fresh)
        return fresh
    }
}
