import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { ClientProvider } from "./ClientProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingClientProvider implements ClientProvider {
    readonly #cache: Cache<oauth.Client>
    readonly #original: ClientProvider

    constructor(original: ClientProvider, cache: Cache<oauth.Client> = new MemoryCache()) {
        this.#cache = cache
        this.#original = original
    }

    async getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
        const cached = await this.#cache.get(as.issuer)
        if (cached !== undefined) {
            return cached
        }

        const fresh = await this.#original.getClient(as, redirectUri, signal)
        await this.#cache.set(as.issuer, fresh)
        return fresh
    }
}
