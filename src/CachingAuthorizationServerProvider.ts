import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #cache = new Map<string, oauth.AuthorizationServer> // TODO: Take cache from caller
    readonly #original: AuthorizationServerProvider

    constructor(original: AuthorizationServerProvider) {
        this.#original = original
    }

    async getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        const cached = this.#cache.get(request.url)
        if (cached !== undefined) {
            return cached
        }

        const fresh = await this.#original.getAuthorizationServer(request)
        this.#cache.set(request.url, fresh)
        return fresh
    }
}
