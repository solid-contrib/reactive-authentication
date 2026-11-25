import * as oauth from "oauth4webapi"
import { parseChallenges } from "./parseChallenges.js"
import * as DPoP from "dpop"
import type { CodeProvider } from "./CodeProvider.js"
import type { TokenProvider } from "./TokenProvider.js"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import { ClientProvider } from "./ClientProvider.js"
import { refreshGrant, runAuthorizationCodeGrant } from "./authorizationCodeGrant.js"
import { selectDPoPSigningAlgorithm } from "./selectDPoPSigningAlgorithm.js"
import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import type { IssuerProvider } from "./IssuerProvider.js"

/**
 * What {@link DPoPTokenProvider} caches for each key: the token response, its DPoP key pair, and the client and
 * authorization server they were obtained from.
 */
export type DPoPTokenCacheEntry = {
    created: number,
    tokenResult: oauth.TokenEndpointResponse,
    dpopKey: CryptoKeyPair,
    client: oauth.Client,
    authorizationServer: oauth.AuthorizationServer,
}

export class DPoPTokenProvider implements TokenProvider {
    readonly #codeProvider: CodeProvider
    readonly #callbackUri: string

    // Keyed by issuer. This assumes Solid-OIDC access tokens (aud "solid"), which are valid at any resource server that trusts the issuer.
    // TODO: Request-specific access tokens (e.g. UMA RPTs, audience-restricted tokens per RFC 8707) require further work: they must not be shared across resources by issuer.
    readonly #cache: Cache<DPoPTokenCacheEntry>
    readonly #asProvider: AuthorizationServerProvider
    readonly #clientProvider: ClientProvider
    readonly #issuerProvider: IssuerProvider
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined

    /**
     * @param options HTTP options for requests to the authorization server, for example to allow plain HTTP (see `allowInsecureRequests`).
     * @param cache Where tokens, refresh tokens and DPoP key pairs are kept, keyed by issuer. Defaults to a new
     * {@link MemoryCache} owned by this instance. Never share one cache between clients or users: an entry is a usable
     * credential, so a shared cache lets one client act as another. A persistent cache must hold non-extractable
     * `CryptoKeyPair`s, so use structured storage such as IndexedDB, never `localStorage` or `sessionStorage`.
     */
    constructor(callbackUri: string, codeProvider: CodeProvider, issuerProvider: IssuerProvider, asProvider: AuthorizationServerProvider, clientProvider: ClientProvider, options?: oauth.HttpRequestOptions<string, any>, cache: Cache<DPoPTokenCacheEntry> = new MemoryCache) {
        this.#codeProvider = codeProvider
        this.#callbackUri = callbackUri
        this.#asProvider = asProvider
        this.#clientProvider = clientProvider
        this.#issuerProvider = issuerProvider
        this.#options = options
        this.#cache = cache
    }

    async matches(_: Request, response: Response): Promise<boolean> {
        // Servers (CSS, NSS) advertise only Bearer but accept DPoP-bound tokens, which RFC 9449 §7.1 permits
        return parseChallenges(response.headers.get("WWW-Authenticate")).some(({scheme}) => scheme === "dpop" || scheme === "bearer")
    }

    async upgrade(request: Request): Promise<Request> {
        // Form a queue per issuer to never reuse refresh tokens.
        // The token obtained here is reused for every request with the same issuer (see #cache).
        const issuer = await this.#issuerProvider.getIssuer(request)
        const lockName = `DPoPTokenProvider.upgrade[${issuer.href}]`
        const {dpopKey, tokenResult: {access_token}} = await navigator.locks.request(lockName, async _ =>
            await this.getCachedToken(request, issuer))

        const headers = new Headers(request.headers)

        headers.set("DPoP", await DPoP.generateProof(dpopKey, request.url, request.method, undefined, access_token))
        headers.set("Authorization", ["DPoP", access_token].join(" "))

        return new Request(request, {headers})
    }

    private async getCachedToken(request: Request, issuer: URL): Promise<DPoPTokenCacheEntry> {
        const cached = await this.#cache.getItem(issuer.href)

        // TODO: Support actively refreshing the token
        if (cached !== null) {
            if (!isExpired(cached)) {
                return cached
            }

            const refreshed = await this.refreshToken(cached, issuer)
            if (refreshed !== undefined) {
                await this.#cache.setItem(issuer.href, refreshed)
                return refreshed
            }
        }

        const fresh = await this.obtainToken(request, issuer)
        await this.#cache.setItem(issuer.href, fresh)

        return fresh
    }

    private async obtainToken(request: Request, issuer: URL): Promise<DPoPTokenCacheEntry> {
        const authorizationServer = await this.#asProvider.getAuthorizationServer(issuer, request.signal)

        const clientRegistration = await this.#clientProvider.getClient(authorizationServer, this.#callbackUri, request.signal)

        const dpopKey = await oauth.generateKeyPair(selectDPoPSigningAlgorithm(authorizationServer), {extractable: false})
        const dpop = oauth.DPoP({}, dpopKey)

        const tokenResult = await runAuthorizationCodeGrant({
            authorizationServer,
            client: clientRegistration,
            callbackUri: this.#callbackUri,
            codeProvider: this.#codeProvider,
            dpop,
            scopes: ["openid", "webid"],
            options: this.#options,
            signal: request.signal,
        })

        return {created: Date.now(), tokenResult, dpopKey, client: clientRegistration, authorizationServer}
    }

    private async refreshToken(cached: DPoPTokenCacheEntry, issuer: URL): Promise<DPoPTokenCacheEntry | undefined> {
        if (cached.tokenResult.refresh_token === undefined) {
            return undefined
        }

        const dpop = oauth.DPoP({}, cached.dpopKey)

        let tokenResult: oauth.TokenEndpointResponse
        try {
            tokenResult = await refreshGrant({
                authorizationServer: cached.authorizationServer,
                client: cached.client,
                refreshToken: cached.tokenResult.refresh_token,
                dpop,
                options: this.#options,
            })
        } catch (e) {
            await this.#cache.removeItem(issuer.href)

            if (e instanceof oauth.ResponseBodyError && e.error === "invalid_grant") {
                console.debug("Access token could not be refreshed")

                return undefined
            }

            throw e
        }

        // Reuse cached refreshed token if it wasn't rotated (token result didn't have one)
        if (tokenResult.refresh_token === undefined) {
            // Leave rest of token result intact
            tokenResult = {...tokenResult, refresh_token: cached.tokenResult.refresh_token}
        }

        return {created: Date.now(), tokenResult, dpopKey: cached.dpopKey, client: cached.client, authorizationServer: cached.authorizationServer}
    }
}

function isExpired(tokenData: DPoPTokenCacheEntry) {
    // TODO: Add some headroom (expire a bit before limit)
    // TODO: What to do when `expires_in` is Missing? (optional in https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2)
    return Date.now() - tokenData.created > tokenData.tokenResult.expires_in! * 1_000;
}
