import type { WWWAuthenticateChallenge } from "oauth4webapi"
import type { TokenProvider } from "./TokenProvider.js"
import { parseChallenges } from "./parseChallenges.js"

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

        const provider = await this.#findProvider(request, parseChallenges(response.headers.get("WWW-Authenticate")))
        if (provider === undefined) {
            return response
        }

        const upgraded = await provider.upgrade(request)
        return this.#fetch.call(undefined, upgraded)
    }

    async #findProvider(request: Request, challenges: readonly WWWAuthenticateChallenge[]): Promise<TokenProvider | undefined> {
        for (const provider of this.#providers) {
            if (await provider.matches(request, challenges)) {
                return provider
            }
        }

        return undefined
    }
}
