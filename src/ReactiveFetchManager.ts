import type { TokenProvider } from "./TokenProvider.js"

export class ReactiveFetchManager extends EventTarget {
    readonly #globalFetch: typeof globalThis.fetch
    readonly #providers: Iterable<TokenProvider>

    constructor(providers: Iterable<TokenProvider>) {
        super()

        this.#providers = providers

        this.#globalFetch = globalThis.fetch
        globalThis.fetch = this.#fetch.bind(this)
    }

    async #fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const request = new Request(input, init)
        const response = await this.#globalFetch.call(undefined, request.clone())
        if (response.status !== 401) {
            return response
        }

        const provider = await this.#findProvider(request)
        if (provider === undefined) {
            return response
        }

        const upgraded = await provider.upgrade(request)
        return this.#globalFetch.call(undefined, upgraded)
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
