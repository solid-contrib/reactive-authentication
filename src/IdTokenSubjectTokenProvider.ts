import * as oauth from "oauth4webapi"
import type {AuthorizationServerProvider} from "./AuthorizationServerProvider.js"
import type {Cache} from "./Cache.js"
import type {ClientProvider} from "./ClientProvider.js"
import type {CodeProvider} from "./CodeProvider.js"
import type {IssuerProvider} from "./IssuerProvider.js"
import {MemoryCache} from "./MemoryCache.js"
import {ReactiveAuthenticationError} from "./ReactiveAuthenticationError.js"
import {refreshGrant, runAuthorizationCodeGrant} from "./authorizationCodeGrant.js"
import {selectDPoPSigningAlgorithm} from "./selectDPoPSigningAlgorithm.js"
import type {SubjectToken, SubjectTokenProvider} from "./SubjectTokenProvider.js"

/**
 * The token type URI of an ID token, as defined in {@link https://www.rfc-editor.org/rfc/rfc8693#section-3 RFC 8693 § 3 Token Type Identifiers}.
 *
 * @see {@link https://www.w3.org/TR/lws10-authn-openid/#x6-token-type-identifier LWS10-AUTHN-OPENID § 6 Token Type Identifier}, which uses it for the LWS OpenID Connect authentication suite.
 */
export const idTokenType = "urn:ietf:params:oauth:token-type:id_token"

/**
 * What {@link IdTokenSubjectTokenProvider} caches for each OpenID Provider: the ID token and when it expires, the refresh token, the DPoP key pair that the OpenID Provider bound them to, and the client and authorization server they were obtained from.
 */
export type IdTokenSubjectTokenCacheEntry = {
    idToken: string,
    expiresAt: number,
    refreshToken?: string,
    dpopKey?: CryptoKeyPair,
    client: oauth.Client,
    authorizationServer: oauth.AuthorizationServer,
}

const headroom = 30_000

/**
 * Provides an ID token as the subject token of a token exchange ({@link https://www.rfc-editor.org/rfc/rfc8693#section-2.1 RFC 8693 § 2.1}). The ID token is defined in {@link https://openid.net/specs/openid-connect-core-1_0.html#IDToken OpenID Connect Core 1.0 § 2 ID Token}. The `sub` claim is the subject, `iss` the issuer and `azp` the client.
 *
 * The ID token is obtained with an authorization code grant that first runs without user interaction, so it is silent while the session at the OpenID Provider lives. It is cached for each OpenID Provider until its `exp` claim, then renewed with a refresh token when the OpenID Provider issues a new ID token for it, and with a new authorization code grant otherwise.
 *
 * Tokens are requested with DPoP ({@link https://www.rfc-editor.org/rfc/rfc9449.html RFC 9449}) when the OpenID Provider advertises `dpop_signing_alg_values_supported`. The key pair is kept for the refresh.
 *
 * The cache is separate from the one of {@link DPoPTokenProvider}, because an entry holds an ID token and not an access token.
 *
 * @see {@link https://www.w3.org/TR/lws10-authn-openid/#x4-authentication-credential-serialization LWS10-AUTHN-OPENID § 4 Authentication Credential Serialization}, which uses the ID token as the LWS authentication credential.
 */
export class IdTokenSubjectTokenProvider implements SubjectTokenProvider {
    readonly #callbackUri: string
    readonly #codeProvider: CodeProvider
    readonly #issuerProvider: IssuerProvider
    readonly #asProvider: AuthorizationServerProvider
    readonly #clientProvider: ClientProvider
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined
    readonly #cache: Cache<IdTokenSubjectTokenCacheEntry>

    /**
     * @param issuerProvider Resolves the OpenID Provider for a request.
     * @param options HTTP options for requests to the authorization server, for example to allow plain HTTP (see `allowInsecureRequests`).
     * @param cache Where ID tokens, refresh tokens and DPoP key pairs are kept, keyed by issuer. Defaults to a new {@link MemoryCache} owned by this instance. Never share one cache between clients or users: an entry is a usable credential, so a shared cache lets one client act as another. A persistent cache must hold non-extractable `CryptoKeyPair`s, so use structured storage such as IndexedDB, never `localStorage` or `sessionStorage`.
     */
    constructor(callbackUri: string, codeProvider: CodeProvider, issuerProvider: IssuerProvider, asProvider: AuthorizationServerProvider, clientProvider: ClientProvider, options?: oauth.HttpRequestOptions<string, any>, cache: Cache<IdTokenSubjectTokenCacheEntry> = new MemoryCache) {
        this.#callbackUri = callbackUri
        this.#codeProvider = codeProvider
        this.#issuerProvider = issuerProvider
        this.#asProvider = asProvider
        this.#clientProvider = clientProvider
        this.#options = options
        this.#cache = cache
    }

    async getSubjectToken(request: Request, signal: AbortSignal): Promise<SubjectToken> {
        const issuer = await this.#issuerProvider.getIssuer(request)

        // One queue per issuer, so that a refresh token is never used twice.
        const {idToken} = await navigator.locks.request(lockName(issuer), async _ =>
            await this.getCachedEntry(issuer, signal))

        return {token: idToken, type: idTokenType}
    }

    async invalidate(request: Request, subjectToken: SubjectToken): Promise<void> {
        const issuer = await this.#issuerProvider.getIssuer(request)

        await navigator.locks.request(lockName(issuer), async _ => {
            const cached = await this.#cache.getItem(issuer.href)

            // A concurrent caller may already have replaced the rejected subject token.
            if (cached?.idToken === subjectToken.token) {
                await this.#cache.removeItem(issuer.href)
            }
        })
    }

    private async getCachedEntry(issuer: URL, signal: AbortSignal): Promise<IdTokenSubjectTokenCacheEntry> {
        const cached = await this.#cache.getItem(issuer.href)

        if (cached !== null) {
            if (!isExpired(cached)) {
                return cached
            }

            const refreshed = await this.refresh(cached, issuer, signal)
            if (refreshed !== undefined) {
                await this.#cache.setItem(issuer.href, refreshed)
                return refreshed
            }
        }

        const fresh = await this.obtain(issuer, signal)
        await this.#cache.setItem(issuer.href, fresh)

        return fresh
    }

    private async obtain(issuer: URL, signal: AbortSignal): Promise<IdTokenSubjectTokenCacheEntry> {
        const authorizationServer = await this.#asProvider.getAuthorizationServer(issuer, signal)
        const client = await this.#clientProvider.getClient(authorizationServer, this.#callbackUri, signal)

        // No key when the OpenID Provider does not advertise DPoP, so that DPoP is not offered to one that cannot handle it.
        const dpopKey = authorizationServer.dpop_signing_alg_values_supported === undefined
            ? undefined
            : await oauth.generateKeyPair(selectDPoPSigningAlgorithm(authorizationServer), {extractable: false})

        const tokenResult = await runAuthorizationCodeGrant({
            authorizationServer,
            client,
            callbackUri: this.#callbackUri,
            codeProvider: this.#codeProvider,
            ...(dpopKey && {dpop: oauth.DPoP({}, dpopKey)}),
            scopes: ["openid", "webid"],
            options: this.#options,
            signal,
        })

        const entry = toEntry(tokenResult, authorizationServer, client, dpopKey, undefined)
        if (entry === undefined) {
            throw new ReactiveAuthenticationError(`The authorization server ${authorizationServer.issuer} did not return an ID token.`)
        }

        return entry
    }

    private async refresh(cached: IdTokenSubjectTokenCacheEntry, issuer: URL, signal: AbortSignal): Promise<IdTokenSubjectTokenCacheEntry | undefined> {
        if (cached.refreshToken === undefined) {
            return undefined
        }

        let tokenResult: oauth.TokenEndpointResponse
        try {
            tokenResult = await refreshGrant({
                authorizationServer: cached.authorizationServer,
                client: cached.client,
                refreshToken: cached.refreshToken,
                ...(cached.dpopKey && {dpop: oauth.DPoP({}, cached.dpopKey)}),
                options: {...this.#options, signal},
            })
        } catch (e) {
            await this.#cache.removeItem(issuer.href)

            if (e instanceof oauth.ResponseBodyError && e.error === "invalid_grant") {
                console.debug("ID token could not be refreshed")

                return undefined
            }

            throw e
        }

        // A refresh response is not required to contain an ID token. Without one, the caller runs the grant again.
        return toEntry(tokenResult, cached.authorizationServer, cached.client, cached.dpopKey, cached.refreshToken)
    }
}

function lockName(issuer: URL) {
    return `IdTokenSubjectTokenProvider.getSubjectToken[${issuer.href}]`
}

function toEntry(tokenResult: oauth.TokenEndpointResponse, authorizationServer: oauth.AuthorizationServer, client: oauth.Client, dpopKey: CryptoKeyPair | undefined, previousRefreshToken: string | undefined): IdTokenSubjectTokenCacheEntry | undefined {
    const claims = oauth.getValidatedIdTokenClaims(tokenResult)
    if (claims === undefined) {
        return undefined
    }

    const entry: IdTokenSubjectTokenCacheEntry = {
        idToken: tokenResult.id_token!,
        expiresAt: claims.exp * 1_000,
        client,
        authorizationServer,
    }

    // Reuse the refresh token if it was not rotated.
    const refreshToken = tokenResult.refresh_token ?? previousRefreshToken
    if (refreshToken !== undefined) {
        entry.refreshToken = refreshToken
    }
    if (dpopKey !== undefined) {
        entry.dpopKey = dpopKey
    }

    return entry
}

function isExpired(entry: IdTokenSubjectTokenCacheEntry) {
    return Date.now() > entry.expiresAt - headroom
}
