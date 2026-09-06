/**
 * A value that names one or more trusted origins: an origin string or `URL`
 * (reduced to its {@link https://developer.mozilla.org/en-US/docs/Web/API/URL/origin origin}),
 * or a predicate that receives a request's origin and returns whether it is trusted.
 */
export type OriginMatcher = string | URL | ((origin: string) => boolean)

/**
 * The set of origins to which the reactive layer may attach the user's
 * credentials when retrying a request that was rejected with `401`.
 *
 * @remarks
 * Why this exists — a credential-leak boundary.
 *
 * {@link ReactiveFetchManager.registerGlobally} replaces `globalThis.fetch`, so
 * *every* fetch the page makes flows through the reactive layer — including
 * requests to third-party origins the app never meant to authenticate to (a CDN,
 * an image host, an analytics beacon, a URL embedded in fetched data). Without a
 * boundary, *any* of those origins can answer `401` to trigger a
 * {@link TokenProvider.upgrade} and receive a retry carrying the user's Solid
 * credentials — the `Authorization` access token (and a DPoP proof) minted for
 * that origin's URL. That hands the user's identity/credential to an origin they
 * never chose to trust.
 *
 * A `CredentialBoundary` is the allow-list of origins the consumer *does* trust
 * with credentials — typically their pod/storage origins (and the issuer). A
 * `401` from an out-of-boundary origin is passed through untouched: no upgrade,
 * no credential attachment.
 *
 * The boundary can be {@link add | widened} in place after construction (for
 * example when a session legitimately gains access to a further storage origin),
 * without disrupting any established session — the reactive layer holds no
 * per-origin state to re-grant.
 *
 * @example
 * ```ts
 * const boundary = new CredentialBoundary(["https://alice.pod.example"])
 * new ReactiveFetchManager([provider], {allowedOrigins: boundary}).registerGlobally()
 * // later, having discovered another storage the user can reach:
 * boundary.add("https://shared.pod.example")
 * ```
 */
export class CredentialBoundary {
    readonly #origins = new Set<string>()
    readonly #predicates: Array<(origin: string) => boolean> = []

    /**
     * @param matchers - Origins (or origin predicates) to trust with credentials.
     */
    constructor(matchers: Iterable<OriginMatcher> = []) {
        this.add(...matchers)
    }

    /**
     * Widens the boundary to trust further origins, in place. Safe to call on a
     * live boundary while requests are in flight; it never narrows the boundary.
     *
     * @returns This boundary, for chaining.
     */
    add(...matchers: OriginMatcher[]): this {
        for (const matcher of matchers) {
            if (typeof matcher === "function") {
                this.#predicates.push(matcher)
                continue
            }

            const origin = originOf(matcher)
            if (origin !== undefined) {
                this.#origins.add(origin)
            }
        }

        return this
    }

    /**
     * Whether `origin` is trusted with credentials. `origin` is expected to be a
     * canonical origin string (as produced by {@link originOf}); a value that is
     * not exactly a trusted origin and matches no predicate is not trusted.
     */
    allows(origin: string): boolean {
        return this.#origins.has(origin) || this.#predicates.some(predicate => predicate(origin))
    }
}

/**
 * Reduces a URL(-ish) value to its canonical
 * {@link https://developer.mozilla.org/en-US/docs/Web/API/URL/origin origin}
 * (scheme + host + port), or `undefined` when it is not a valid absolute URL.
 *
 * @remarks
 * Comparing canonical origins — rather than raw URL prefixes — is what makes the
 * boundary robust: `https://pod.example` and `https://pod.example:443/anything`
 * share one origin, while `https://pod.example.attacker.test` does not, so a
 * look-alike host cannot slip past a substring check.
 */
export function originOf(url: string | URL): string | undefined {
    try {
        return new URL(url).origin
    } catch {
        return undefined
    }
}
