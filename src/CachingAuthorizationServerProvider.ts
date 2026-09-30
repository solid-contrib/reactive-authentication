import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #cache: Cache<oauth.AuthorizationServer> = new MemoryCache // TODO: Take cache from caller
    readonly #original: AuthorizationServerProvider

    constructor(original: AuthorizationServerProvider) {
        this.#original = original
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
