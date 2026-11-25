import * as oauth from "oauth4webapi"
import * as DPoP from "dpop"
import type {AuthorizationServerProvider} from "./AuthorizationServerProvider.js"
import type {Cache} from "./Cache.js"
import {withDPoPNonceRetry} from "./dpopNonce.js"
import {MemoryCache} from "./MemoryCache.js"
import {ReactiveAuthenticationError} from "./ReactiveAuthenticationError.js"
import {selectDPoPSigningAlgorithm} from "./selectDPoPSigningAlgorithm.js"
import type {SubjectToken, SubjectTokenProvider} from "./SubjectTokenProvider.js"
import type {TokenExchangeTargetProvider} from "./TokenExchangeTargetProvider.js"
import type {TokenProvider} from "./TokenProvider.js"

const tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

const headroom = 30_000

// oauth4webapi requires a client, but the request must not identify one, so this placeholder is never sent. The no-op client authentication adds nothing to the request.
const anonymousClient: oauth.Client = {client_id: "unused"}
const noClientAuthentication: oauth.ClientAuth = () => {}

/**
 * What {@link TokenExchangeTokenProvider} caches for each authorization server and resource: the access token, its type, when it expires and, for a DPoP-bound token, its DPoP key pair.
 */
export type TokenExchangeCacheEntry = {
    accessToken: string,
    tokenType: string,
    expiresAt: number,
    dpopKey?: CryptoKeyPair,
}

/**
 * Changes the DPoP handle of a token exchange request, for an authorization server that wants more than {@link https://www.rfc-editor.org/rfc/rfc9449.html#section-5 RFC 9449 § 5} in the proof of a token request.
 */
export type TokenExchangeDPoPAdapter = (handle: oauth.DPoPHandle, subjectToken: SubjectToken) => oauth.DPoPHandle

/**
 * Obtains an access token for a resource by exchanging a subject token, as defined in {@link https://www.rfc-editor.org/rfc/rfc8693 RFC 8693}, and presents it as the authorization server says: as a `DPoP` token ({@link https://www.rfc-editor.org/rfc/rfc9449.html RFC 9449}) or as a `Bearer` token ({@link https://www.rfc-editor.org/rfc/rfc6750#section-2.1 RFC 6750 § 2.1}).
 *
 * The authorization server and the resource come from the {@link TokenExchangeTargetProvider}. The token request is a token exchange request as defined in {@link https://www.rfc-editor.org/rfc/rfc8693#section-2.1 RFC 8693 § 2.1}, with the `grant_type`, `resource`, `subject_token` and `subject_token_type` parameters. It has no `client_id` and no client authentication: the subject token identifies the client and the user.
 *
 * Access tokens are cached for each authorization server and resource until they expire. A response without `expires_in` counts as expired at once. A token exchange has no refresh token, so an expired access token is replaced with a new token exchange. If the authorization server rejects a token exchange with `invalid_grant` or `invalid_token`, for example because the subject token expired, the {@link SubjectTokenProvider} discards the subject token and the exchange runs once more with a new one.
 *
 * The token request carries a DPoP proof ({@link https://www.rfc-editor.org/rfc/rfc9449.html#section-5 RFC 9449 § 5}) signed with the key that the subject token is bound to, if it is bound. Otherwise it carries a proof with a new key when the authorization server advertises `dpop_signing_alg_values_supported`, and is a plain request when it does not. If the authorization server demands a nonce, the request runs once more with it ({@link https://www.rfc-editor.org/rfc/rfc9449.html#section-8 RFC 9449 § 8}). The `token_type` of the response, in any case, decides how the access token is presented. `DPoP` sends `Authorization: DPoP` and a new proof for each request, bound to the access token ({@link https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1 RFC 9449 § 7.1}). `Bearer` sends `Authorization: Bearer`, also when the request had a DPoP proof. Any other type is an error (`oauth.UnsupportedOperationError`).
 *
 * A persistent cache must hold non-extractable `CryptoKeyPair`s, so use structured storage such as IndexedDB, never `localStorage` or `sessionStorage`.
 *
 * @see {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authorization-token-exchange LWS10-OAUTH Token Exchange}, which uses this exchange.
 * @see {@link https://solidproject.org/TR/oidc#dpop-validation Solid-OIDC § 9.3 DPoP Validation}, which requires a DPoP proof when a DPoP-bound ID token is exchanged.
 */
export class TokenExchangeTokenProvider implements TokenProvider {
    readonly #targetProvider: TokenExchangeTargetProvider
    readonly #subjectTokenProvider: SubjectTokenProvider
    readonly #asProvider: AuthorizationServerProvider
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined
    readonly #cache: Cache<TokenExchangeCacheEntry>
    readonly #dpopAdapter: TokenExchangeDPoPAdapter

    /**
     * @param targetProvider Finds the authorization server and the resource of a request, and tells which responses it can handle.
     * @param subjectTokenProvider Provides the subject token to exchange.
     * @param asProvider Finds the metadata of the authorization server, which has the token endpoint.
     * @param options HTTP options for requests to the authorization server, for example to allow plain HTTP (see `allowInsecureRequests`).
     * @param cache Where access tokens are kept, keyed by authorization server and resource. Defaults to a new {@link MemoryCache} owned by this instance. Never share one cache between clients or users: an entry is a usable credential, so a shared cache lets one client act as another.
     * @param dpopAdapter Changes the DPoP handle of the token request. Defaults to no change.
     */
    constructor(targetProvider: TokenExchangeTargetProvider, subjectTokenProvider: SubjectTokenProvider, asProvider: AuthorizationServerProvider, options?: oauth.HttpRequestOptions<string, any>, cache: Cache<TokenExchangeCacheEntry> = new MemoryCache, dpopAdapter: TokenExchangeDPoPAdapter = handle => handle) {
        this.#targetProvider = targetProvider
        this.#subjectTokenProvider = subjectTokenProvider
        this.#asProvider = asProvider
        this.#options = options
        this.#cache = cache
        this.#dpopAdapter = dpopAdapter
    }

    async matches(request: Request, response: Response): Promise<boolean> {
        return await this.#targetProvider.matches(request, response)
    }

    async upgrade(request: Request, response: Response): Promise<Request> {
        const {issuer, resource} = await this.#targetProvider.getTarget(request, response, request.signal)
        const key = `${issuer} ${resource}`

        // One queue per authorization server and resource, so that concurrent requests share one token exchange.
        const {accessToken, tokenType, dpopKey} = await navigator.locks.request(`TokenExchangeTokenProvider.upgrade[${key}]`, async _ =>
            await this.#getCachedEntry(key, issuer, resource, request))

        const headers = new Headers(request.headers)
        if (tokenType.toLowerCase() === "dpop" && dpopKey !== undefined) {
            headers.set("DPoP", await DPoP.generateProof(dpopKey, request.url, request.method, undefined, accessToken))
            headers.set("Authorization", ["DPoP", accessToken].join(" "))
        } else {
            headers.set("Authorization", ["Bearer", accessToken].join(" "))
        }

        return new Request(request, {headers})
    }

    async #getCachedEntry(key: string, issuer: string, resource: string, request: Request): Promise<TokenExchangeCacheEntry> {
        const cached = await this.#cache.getItem(key)
        if (cached !== null && Date.now() <= cached.expiresAt - headroom) {
            return cached
        }

        const fresh = await this.#exchange(issuer, resource, request)
        await this.#cache.setItem(key, fresh)

        return fresh
    }

    async #exchange(issuer: string, resource: string, request: Request): Promise<TokenExchangeCacheEntry> {
        const signal = request.signal
        const authorizationServer = await this.#asProvider.getAuthorizationServer(new URL(issuer), signal)

        const subjectToken = await this.#subjectTokenProvider.getSubjectToken(request, signal)
        try {
            return await this.#sendExchange(authorizationServer, resource, subjectToken, signal)
        } catch (e) {
            if (!isRejectedSubjectToken(e)) {
                throw e
            }

            await this.#subjectTokenProvider.invalidate(request, subjectToken)

            const retrySubjectToken = await this.#subjectTokenProvider.getSubjectToken(request, signal)
            return await this.#sendExchange(authorizationServer, resource, retrySubjectToken, signal)
        }
    }

    async #sendExchange(authorizationServer: oauth.AuthorizationServer, resource: string, subjectToken: SubjectToken, signal: AbortSignal): Promise<TokenExchangeCacheEntry> {
        // No key when the authorization server does not advertise DPoP, so that DPoP is not offered to one that cannot handle it.
        const dpopKey = subjectToken.dpopKey ?? (authorizationServer.dpop_signing_alg_values_supported === undefined
            ? undefined
            : await oauth.generateKeyPair(selectDPoPSigningAlgorithm(authorizationServer), {extractable: false}))
        const dpop = dpopKey && this.#dpopAdapter(oauth.DPoP(anonymousClient, dpopKey), subjectToken)

        const result = await withDPoPNonceRetry(async () => {
            const response = await oauth.genericTokenEndpointRequest(authorizationServer, anonymousClient, noClientAuthentication, tokenExchangeGrantType, {
                resource,
                subject_token: subjectToken.token,
                subject_token_type: subjectToken.type,
            }, {...this.#options, signal, ...(dpop && {DPoP: dpop})})

            return await oauth.processGenericTokenEndpointResponse(authorizationServer, anonymousClient, response)
        })

        // oauth4webapi lower-cases token_type and rejects every value except dpop and bearer.
        const entry: TokenExchangeCacheEntry = {
            accessToken: result.access_token,
            tokenType: result.token_type,
            // Without expires_in the token counts as expired at once, so the next request exchanges again.
            expiresAt: Date.now() + (result.expires_in ?? 0) * 1_000,
        }

        if (result.token_type === "dpop") {
            if (dpopKey === undefined) {
                throw new ReactiveAuthenticationError(`The authorization server ${authorizationServer.issuer} issued a DPoP access token for a request without DPoP`)
            }

            entry.dpopKey = dpopKey
        }

        return entry
    }
}

// An authorization server may answer an invalid subject token with a 400 error body (RFC 6749 § 5.2) or with a 401 and an invalid_token challenge (RFC 6750 § 3.1). oauth4webapi throws the second kind as WWWAuthenticateChallengeError.
function isRejectedSubjectToken(e: unknown): boolean {
    if (e instanceof oauth.ResponseBodyError) {
        return e.error === "invalid_grant" || e.error === "invalid_token"
    }

    return e instanceof oauth.WWWAuthenticateChallengeError
        && e.cause.some(challenge => challenge.parameters.error === "invalid_token")
}
