import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import type * as oauth from "oauth4webapi"

export class CachingAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #cache = new Map<string, Promise<oauth.AuthorizationServer>> // TODO: Take cache from caller
    readonly #original: AuthorizationServerProvider

    constructor(original: AuthorizationServerProvider) {
        this.#original = original
    }

    getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        return this.#cache.getOrInsertComputed(request.url, _ => this.#original.getAuthorizationServer(request))
    }
}
