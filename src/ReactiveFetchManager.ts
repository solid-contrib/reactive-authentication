import type { TokenProvider } from "./TokenProvider.js"

export class ReactiveFetchManager extends EventTarget {
    readonly #globalFetch: typeof globalThis.fetch
    readonly #providers: Iterable<TokenProvider>

    constructor(providers: Iterable<TokenProvider>) {
        super()

        this.#providers = providers

        this.#globalFetch = globalThis.fetch
    }

    registerGlobally() {
        globalThis.fetch = this.fetch
    }

    get fetch(): typeof globalThis.fetch {
        return this.#fetch.bind(this)
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

        const upgraded = await provider.upgrade(request.clone())
        const upgradedResponse = await this.#globalFetch.call(undefined, upgraded)
        if (upgradedResponse.status !== 401 || provider.invalidate === undefined) {
            return upgradedResponse
        }

        // The credentials we attached were rejected. Mark them stale and retry
        // once with renewed ones; if those are rejected too, give up and let the
        // caller see the 401 (bounded — never a loop). Cancel the discarded
        // response's body so the connection can be reused (undici keep-alive).
        await upgradedResponse.body?.cancel().catch(() => undefined)
        await provider.invalidate(upgraded)
        return this.#globalFetch.call(undefined, await provider.upgrade(request))
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
