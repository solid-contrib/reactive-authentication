import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import type * as oauth from "oauth4webapi"
import type { CacheKeyProvider } from "./CacheKeyProvider.js"

export class CachingAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #cache: Cache<oauth.AuthorizationServer> = new MemoryCache // TODO: Take cache from caller
    readonly #original: AuthorizationServerProvider
    readonly #cacheKeyProvider: CacheKeyProvider

    constructor(original: AuthorizationServerProvider, cacheKeyProvider: CacheKeyProvider) {
        this.#original = original
        this.#cacheKeyProvider = cacheKeyProvider
    }

    async getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        const key = await this.#cacheKeyProvider.getKey(request)
        const cached = await this.#cache.getItem(key)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getAuthorizationServer(request)
        await this.#cache.setItem(key, fresh)
        return fresh
    }
}
