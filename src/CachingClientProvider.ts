import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { ClientProvider } from "./ClientProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingClientProvider implements ClientProvider {
    readonly #cache: Cache<oauth.Client>
    readonly #original: ClientProvider

    /**
     * @param original The provider whose results are cached.
     * @param cache Where results are kept. Defaults to a new {@link MemoryCache} owned by this instance.
     */
    constructor(original: ClientProvider, cache: Cache<oauth.Client> = new MemoryCache) {
        this.#original = original
        this.#cache = cache
    }

    async getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
        const cached = await this.#cache.getItem(as.issuer)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getClient(as, redirectUri, signal)
        await this.#cache.setItem(as.issuer, fresh)
        return fresh
    }
}
