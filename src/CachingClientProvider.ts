import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { ClientProvider } from "./ClientProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingClientProvider implements ClientProvider {
    readonly #cache: Cache<oauth.Client> = new MemoryCache // TODO: Take cache from caller
    readonly #original: ClientProvider

    constructor(original: ClientProvider) {
        this.#original = original
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
