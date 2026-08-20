import { ClientProvider } from "./ClientProvider.js"
import * as oauth from "oauth4webapi"

export class CachingClientProvider implements ClientProvider {
    readonly #cache = new Map<string, Promise<oauth.Client>> // TODO: Take cache from caller
    readonly #original: ClientProvider

    constructor(original: ClientProvider) {
        this.#original = original
    }

    async getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
        return this.#cache.getOrInsertComputed(as.issuer, _ => this.#original.getClient(as, redirectUri, signal))
    }
}
