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

    async getAuthorizationServer(issuer: URL, signal: AbortSignal): Promise<oauth.AuthorizationServer> {
        const key = issuer.href
        const cached = await this.#cache.getItem(key)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getAuthorizationServer(issuer, signal)
        await this.#cache.setItem(key, fresh)
        return fresh
    }
}
