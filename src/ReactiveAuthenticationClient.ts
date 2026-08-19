import type { TokenProvider } from "./TokenProvider.js"
import { CredentialBoundary, type OriginMatcher, originOf } from "./CredentialBoundary.js"

/** Options for {@link ReactiveAuthenticationClient}. */
export interface ReactiveAuthenticationClientOptions {
    /**
     * The origins the client may attach the user's credentials to when retrying a
     * request rejected with `401` — see {@link CredentialBoundary}. Strongly
     * recommended: set this to your pod/storage origins. When omitted, every
     * `401` is upgraded regardless of origin (the previous behaviour) and a
     * one-time warning is logged.
     */
    allowedOrigins?: CredentialBoundary | Iterable<OriginMatcher>
}

export class ReactiveAuthenticationClient {
    readonly #fetch: typeof globalThis.fetch
    readonly #providers: Iterable<TokenProvider>
    readonly #boundary: CredentialBoundary | undefined
    #warnedNoBoundary = false

    constructor(
        fetch: typeof globalThis.fetch,
        providers: Iterable<TokenProvider>,
        options: ReactiveAuthenticationClientOptions = {},
    ) {
        this.#fetch = fetch
        this.#providers = providers
        this.#boundary = toBoundary(options.allowedOrigins)
    }

    async fetch(request: Request): Promise<Response> {
        const response = await this.#fetch.call(undefined, request.clone())
        if (response.status !== 401) {
            return response
        }

        // Credential boundary: an out-of-boundary 401 is returned untouched, so
        // the user's credentials are never attached to a retry against an origin
        // the consumer has not trusted (see CredentialBoundary).
        if (!this.#withinBoundary(request.url)) {
            return response
        }

        const provider = await this.#findProvider(request)
        if (provider === undefined) {
            return response
        }

        const upgraded = await provider.upgrade(request)
        return this.#fetch.call(undefined, upgraded)
    }

    #withinBoundary(url: string): boolean {
        if (this.#boundary === undefined) {
            if (!this.#warnedNoBoundary) {
                this.#warnedNoBoundary = true
                console.warn(
                    "ReactiveAuthenticationClient: no `allowedOrigins` credential boundary is set, so every 401 response — including from third-party origins — triggers a credentialed retry. Pass `allowedOrigins` (your pod/storage origins) to prevent leaking the user's credentials.",
                )
            }
            return true
        }

        const origin = originOf(url)
        return origin !== undefined && this.#boundary.allows(origin)
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

function toBoundary(input: ReactiveAuthenticationClientOptions["allowedOrigins"]): CredentialBoundary | undefined {
    if (input === undefined) {
        return undefined
    }

    return input instanceof CredentialBoundary ? input : new CredentialBoundary(input)
}
