import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #cache: Cache<oauth.AuthorizationServer>
    readonly #original: AuthorizationServerProvider

    constructor(original: AuthorizationServerProvider, cache: Cache<oauth.AuthorizationServer> = new MemoryCache()) {
        this.#cache = cache
        this.#original = original
    }

    async getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        const cached = await this.#cache.get(request.url)
        if (cached !== undefined) {
            return cached
        }

        const fresh = await this.#original.getAuthorizationServer(request)
        await this.#cache.set(request.url, fresh)
        return fresh
    }
}
