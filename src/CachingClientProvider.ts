import type { ClientProvider } from "./ClientProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingClientProvider implements ClientProvider {
    readonly #cache = new Map<string, oauth.Client> // TODO: Take cache from caller
    readonly #original: ClientProvider

    constructor(original: ClientProvider) {
        this.#original = original
    }

    async getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
        const cached = this.#cache.get(as.issuer)
        if (cached !== undefined) {
            return cached
        }

        const fresh = await this.#original.getClient(as, redirectUri, signal)
        this.#cache.set(as.issuer, fresh)
        return fresh
    }
}
