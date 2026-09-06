import type { TokenProvider } from "./TokenProvider.js"
import { CredentialBoundary, type OriginMatcher, originOf } from "./CredentialBoundary.js"

/** Options for {@link ReactiveFetchManager}. */
export interface ReactiveFetchManagerOptions {
    /**
     * The origins the reactive layer may attach the user's credentials to when
     * retrying a request rejected with `401` — see {@link CredentialBoundary}.
     *
     * Strongly recommended: set this to your pod/storage origins so that a `401`
     * from a third-party origin cannot harvest the user's credentials. Pass a
     * {@link CredentialBoundary} instance (which you can later
     * {@link CredentialBoundary.add | widen}) or any iterable of
     * {@link OriginMatcher}s (origins / predicates).
     *
     * When omitted, every `401` is upgraded regardless of origin (the previous
     * behaviour) and a one-time warning is logged.
     */
    allowedOrigins?: CredentialBoundary | Iterable<OriginMatcher>
}

export class ReactiveFetchManager extends EventTarget {
    readonly #globalFetch: typeof globalThis.fetch
    readonly #providers: Iterable<TokenProvider>
    readonly #boundary: CredentialBoundary | undefined
    #warnedNoBoundary = false

    constructor(providers: Iterable<TokenProvider>, options: ReactiveFetchManagerOptions = {}) {
        super()

        this.#providers = providers

        this.#globalFetch = globalThis.fetch

        this.#boundary = toBoundary(options.allowedOrigins)
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

        // Credential boundary: never attach the user's credentials to a retry
        // against an origin the consumer has not trusted. An out-of-boundary
        // `401` is returned untouched — no provider is consulted, no upgrade runs.
        if (!this.#withinBoundary(request.url)) {
            return response
        }

        const provider = await this.#findProvider(request)
        if (provider === undefined) {
            return response
        }

        const upgraded = await provider.upgrade(request)
        return this.#globalFetch.call(undefined, upgraded)
    }

    #withinBoundary(url: string): boolean {
        if (this.#boundary === undefined) {
            if (!this.#warnedNoBoundary) {
                this.#warnedNoBoundary = true
                console.warn(
                    "ReactiveFetchManager: no `allowedOrigins` credential boundary is set, so every 401 response — including from third-party origins — triggers a credentialed retry. Pass `allowedOrigins` (your pod/storage origins) to prevent leaking the user's credentials.",
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

function toBoundary(input: ReactiveFetchManagerOptions["allowedOrigins"]): CredentialBoundary | undefined {
    if (input === undefined) {
        return undefined
    }

    return input instanceof CredentialBoundary ? input : new CredentialBoundary(input)
}
