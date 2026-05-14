import type { TokenProvider } from "./TokenProvider.js"

export class ReactiveAuthenticationClient {
    readonly #fetch: typeof globalThis.fetch
    readonly #providers: Iterable<TokenProvider>

    constructor(fetch: typeof globalThis.fetch, providers: Iterable<TokenProvider>) {
        this.#fetch = fetch
        this.#providers = providers
    }

    async fetch(request: Request): Promise<Response> {
        const response = await this.#fetch.call(undefined, request.clone())
        if (response.status !== 401) {
            return response
        }

        const provider = await this.#findProvider(request)
        if (provider === undefined) {
            return response
        }

        const upgraded = await provider.upgrade(request)
        return this.#fetch.call(undefined, upgraded)
    }

    async #findProvider(request: Request): Promise<TokenProvider | undefined> {
        for (const provider of this.#providers) {
            if (await provider.matches(request)) {
                return provider
            }
        }

        return undefined
    }
}
